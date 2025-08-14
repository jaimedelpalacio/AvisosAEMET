// Microservicio cacheador AEMET – Avisos CAP por zona (España) con PERSISTENCIA EN DISCO
// --------------------------------------------------------------------------------------
// Novedades:
//  - Guarda la última caché válida en disco (/tmp/aemet_cache.json) tras cada /refresh correcto.
//  - Al arrancar, intenta cargar esa caché desde disco y la usa de inmediato.
//  - Si AEMET falla al inicio, /avisos seguirá devolviendo los últimos datos válidos persistidos.
//  - /health expone last_success_at; /stats muestra métricas; /avisos sirve por zona.
//
// Endpoints:
//  - GET /avisos?zona=NNNNNN
//  - GET /refresh
//  - GET /health
//  - GET /stats
//
// Variables de entorno (Render):
//  - AEMET_API_KEY   (obligatoria)
//  - AEMET_AREAS     (CSV: "61,62,63,64,78,65,66,67,68,69,77,70,71,72,79,73,74,75,76")
//  - PORT            (opcional: 3000)
//  - CACHE_PATH      (opcional: ruta del fichero de caché; por defecto /tmp/aemet_cache.json)
//
// Nota: el refresco periódico lo hace tu Cron Job llamando a /refresh.
// --------------------------------------------------------------------------------------

import express from 'express';
import { fetch } from 'undici';
import * as zlib from 'zlib';
import tar from 'tar-stream';
import crypto from 'crypto';
import { XMLParser } from 'fast-xml-parser';
import { promises as fs } from 'fs';
import path from 'path';

const app = express();
const PORT = process.env.PORT || 3000;
const UA = 'MT-Neo-AEMET-Cache/1.1';
const API_KEY = (process.env.AEMET_API_KEY || '').trim();

// Áreas (2 dígitos) a recorrer en /refresh
const AREAS = (process.env.AEMET_AREAS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// Archivo de persistencia
const CACHE_PATH = process.env.CACHE_PATH || '/tmp/aemet_cache.json';

// ------------------ Estado de caché --------------------------
let cache = {
  version: '1.1',
  generatedAt: null, // ISO del último refresco exitoso
  areas: [],
  files: [],
  alerts: [],
  byZona: new Map()
};
let lastGoodCache = null; // copia de la última caché válida

// ------------------ Utilidades de persistencia ----------------

/**
 * Serializa la caché a disco en JSON (sin Map).
 * Guardamos los campos suficientes para reconstruir índices al cargar.
 */
async function saveCacheToDisk(c) {
  try {
    const serializable = {
      version: c.version,
      generatedAt: c.generatedAt,
      areas: c.areas,
      files: c.files,
      alerts: c.alerts
    };
    await fs.mkdir(path.dirname(CACHE_PATH), { recursive: true });
    await fs.writeFile(CACHE_PATH, JSON.stringify(serializable), 'utf8');
    // eslint-disable-next-line no-console
    console.log(`[CACHE] Guardada en ${CACHE_PATH} (${c.alerts.length} alertas, zonas indexadas: ${c.byZona.size})`);
  } catch (e) {
    console.error('[CACHE] Error al guardar en disco:', e.message);
  }
}

/**
 * Carga la caché desde disco y reconstruye índices.
 */
async function loadCacheFromDisk() {
  try {
    const raw = await fs.readFile(CACHE_PATH, 'utf8');
    const data = JSON.parse(raw);
    const byZona = buildIndexes(data.alerts || []);
    const loaded = {
      version: data.version || '1.0',
      generatedAt: data.generatedAt || null,
      areas: Array.isArray(data.areas) ? data.areas : [],
      files: Array.isArray(data.files) ? data.files : [],
      alerts: Array.isArray(data.alerts) ? data.alerts : [],
      byZona
    };
    cache = loaded;
    lastGoodCache = loaded; // importante: lo tratamos como última válida también
    console.log(`[CACHE] Cargada desde ${CACHE_PATH}. generatedAt=${loaded.generatedAt}, zonas=${byZona.size}`);
    return true;
  } catch (e) {
    console.warn(`[CACHE] No hay caché previa o no se pudo leer ${CACHE_PATH}:`, e.message);
    return false;
  }
}

// ------------------ Utilidades HTTP y TAR/XML ----------------

function requireApiKey() {
  if (!API_KEY) {
    const e = new Error('Falta AEMET_API_KEY en variables de entorno.');
    e.status = 500;
    throw e;
  }
}

function isGzip(buf) {
  return buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b;
}

async function fetchJSON(url, headers = {}) {
  const r = await fetch(url, { headers: { accept: 'application/json', 'user-agent': UA, ...headers } });
  if (!r.ok) throw new Error(`HTTP ${r.status} en ${url}`);
  return r.json();
}

async function fetchBuffer(url, headers = {}) {
  const r = await fetch(url, { headers: { 'user-agent': UA, ...headers } });
  if (!r.ok) throw new Error(`HTTP ${r.status} al descargar datos (TAR/XML): ${url}`);
  const ab = await r.arrayBuffer();
  return Buffer.from(ab);
}

async function fetchJSONSmart(url, headers = {}) {
  // Decodificación robusta (UTF-8/Latin-1) por si AEMET devuelve charset extraño
  const r = await fetch(url, { headers: { accept: 'application/json,*/*;q=0.8', 'user-agent': UA, ...headers } });
  if (!r.ok) throw new Error(`HTTP ${r.status} en ${url}`);
  const buf = Buffer.from(await r.arrayBuffer());
  const ct = (r.headers.get('content-type') || '').toLowerCase();

  let text;
  if (ct.includes('iso-8859') || ct.includes('latin1')) {
    text = buf.toString('latin1');
  } else {
    const utf8 = buf.toString('utf8');
    const lat1 = buf.toString('latin1');
    const bads = (s) => (s.match(/\uFFFD/g) || []).length;
    text = bads(lat1) < bads(utf8) ? lat1 : utf8;
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return JSON.parse(text);
}

function gunzipIfNeeded(buf) {
  return isGzip(buf) ? zlib.gunzipSync(buf) : buf;
}

async function tarEntries(buf) {
  const tarBuf = gunzipIfNeeded(buf);
  const out = [];
  await new Promise((resolve, reject) => {
    const extract = tar.extract();
    extract.on('entry', (hdr, stream, next) => {
      const chunks = [];
      stream.on('data', c => chunks.push(c));
      stream.on('end', () => {
        const buffer = Buffer.concat(chunks);
        const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
        out.push({ name: hdr.name, size: buffer.length, buffer, sha1 });
        next();
      });
      stream.on('error', reject);
    });
    extract.on('finish', resolve);
    extract.on('error', reject);
    extract.end(tarBuf);
  });
  return out;
}

function decodeToString(b) {
  try { return b.toString('utf8'); } catch { return b.toString('latin1'); }
}

// ------------------ Parseo CAP v1.2 -------------------------

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  textNodeName: '#text',
  trimValues: true,
});

function asArray(x) { return Array.isArray(x) ? x : x == null ? [] : [x]; }

function parseCapXml(xmlText) {
  const root = parser.parse(xmlText);
  const alerts = asArray(root?.alert || root?.['cap:alert']);
  return alerts.map((alert) => {
    const header = {
      identifier: alert?.identifier ?? null,
      sender: alert?.sender ?? null,
      sent: alert?.sent ?? null,
      status: alert?.status ?? null,
      msgType: alert?.msgType ?? null,
      scope: alert?.scope ?? null,
    };

    const infoList = asArray(alert?.info).map((info) => {
      const category = asArray(info?.category).map(String);
      const responseType = asArray(info?.responseType).map(String);

      const parameters = asArray(info?.parameter).map((p) => ({
        valueName: p?.valueName ?? p?.['@_valueName'] ?? p?.name ?? null,
        value: p?.value ?? p?.['#text'] ?? null,
      }));

      const eventCode = asArray(info?.eventCode).map((ec) => ({
        name: ec?.name ?? ec?.['@_name'] ?? null,
        value: ec?.value ?? ec?.['#text'] ?? null,
      }));

      const areas = asArray(info?.area).map((a) => ({
        areaDesc: a?.areaDesc ?? null,
        altitude: a?.altitude ?? null,
        ceiling: a?.ceiling ?? null,
        polygons: asArray(a?.polygon).map(String),
        circles: asArray(a?.circle).map(String),
        geocodes: asArray(a?.geocode).map((g) => ({
          valueName: g?.valueName ?? g?.['@_valueName'] ?? null,
          value: g?.value ?? g?.['#text'] ?? null,
        })),
      }));

      return {
        language: info?.language ?? null,
        category,
        event: info?.event ?? null,
        responseType,
        urgency: info?.urgency ?? null,
        severity: info?.severity ?? null,
        certainty: info?.certainty ?? null,
        effective: info?.effective ?? null,
        onset: info?.onset ?? null,
        expires: info?.expires ?? null,
        headline: info?.headline ?? null,
        description: info?.description ?? null,
        instruction: info?.instruction ?? null,
        web: info?.web ?? null,
        contact: info?.contact ?? null,
        parameters,
        eventCode,
        areas,
      };
    });

    return { header, info: infoList };
  });
}

function buildIndexes(allAlerts) {
  // Índice por zona (6 dígitos): por nombre de fichero y por geocodes en el CAP
  const byZona = new Map();

  function add(zona, alert) {
    if (!/^\d{6}$/.test(zona)) return;
    if (!byZona.has(zona)) byZona.set(zona, []);
    byZona.get(zona).push(alert);
  }

  for (const a of allAlerts) {
    // 1) Zonas en el nombre del fichero (Z_..._614102...xml)
    const m = (a.file || '').match(/(\d{6})/g);
    if (m) for (const z of new Set(m)) add(z, a);

    // 2) Zonas en geocodes dentro del XML CAP
    for (const inf of a.info || []) {
      for (const ar of inf.areas || []) {
        for (const g of ar.geocodes || []) {
          const val = String(g.value || '');
          const gzs = val.match(/(\d{6})/g);
          if (gzs) for (const z of new Set(gzs)) add(z, a);
        }
      }
    }
  }

  return byZona;
}

// ------------------ Descarga por área ------------------------

async function fetchAreaAlerts(area) {
  const urlCatalogo = `https://opendata.aemet.es/opendata/api/avisos_cap/ultimoelaborado/area/${area}?api_key=${encodeURIComponent(API_KEY)}`;
  const cat = await fetchJSON(urlCatalogo);
  const urlDatos = cat?.datos;
  const urlMetadatos = cat?.metadatos || null;
  if (!urlDatos) throw new Error(`Catálogo sin "datos" para área ${area}`);

  const dataBuf = await fetchBuffer(urlDatos);

  let entries = [];
  let isTar = true;
  try {
    entries = await tarEntries(dataBuf);
  } catch {
    isTar = false;
  }

  const files = [];
  const alerts = [];
  const metadatos = urlMetadatos ? await (async () => {
    try { return await fetchJSONSmart(urlMetadatos); } catch { return null; }
  })() : null;

  if (isTar) {
    for (const ent of entries) {
      files.push({ area, name: ent.name, size: ent.size, sha1: ent.sha1 });
      if (!ent.name.toLowerCase().endsWith('.xml')) continue;
      const xml = decodeToString(ent.buffer);
      const parsedList = parseCapXml(xml);
      for (const pa of parsedList) {
        alerts.push({ area, file: ent.name, ...pa, raw_xml: xml });
      }
    }
  } else {
    const xml = decodeToString(dataBuf);
    const parsedList = parseCapXml(xml);
    for (const pa of parsedList) {
      alerts.push({ area, file: 'datos.xml', ...pa, raw_xml: xml });
    }
    files.push({ area, name: 'datos.xml', size: xml.length, sha1: crypto.createHash('sha1').update(xml).digest('hex') });
  }

  return { files, alerts, metadatos };
}

// ------------------ Refresco completo de caché ---------------

async function refreshCache() {
  requireApiKey();

  const started = Date.now();
  const allFiles = [];
  const allAlerts = [];

  for (const area of AREAS) {
    try {
      const { files, alerts } = await fetchAreaAlerts(area);
      allFiles.push(...files);
      allAlerts.push(...alerts);
    } catch (e) {
      // registramos error de área pero seguimos con el resto
      allFiles.push({ area, name: '[ERROR]', size: 0, sha1: null, error: String(e.message || e) });
    }
  }

  const byZona = buildIndexes(allAlerts);
  const newCache = {
    version: cache.version,
    generatedAt: new Date().toISOString(), // hora del último éxito de refresco
    areas: [...AREAS],
    files: allFiles,
    alerts: allAlerts,
    byZona
  };

  cache = newCache;
  lastGoodCache = newCache;

  // Persistimos la caché en disco
  await saveCacheToDisk(newCache);

  const ms = Date.now() - started;
  return { areasTried: AREAS.length, files: allFiles.length, alerts: allAlerts.length, ms };
}

// ------------------ API --------------------------------------

app.get('/', (_, res) => {
  res.type('text/plain').send('AEMET avisos – caché por zona (España) – OK (con persistencia)');
});

app.get('/health', (_, res) => {
  res.json({ ok: true, last_success_at: cache.generatedAt });
});

app.get('/stats', (_, res) => {
  const zonesIndexed = cache.byZona.size;
  const topZones = [];
  for (const [z, arr] of cache.byZona) topZones.push({ zona: z, count: arr.length });
  topZones.sort((a, b) => b.count - a.count);
  res.json({
    version: cache.version,
    generatedAt: cache.generatedAt,
    areas: cache.areas,
    files: cache.files.length,
    alerts: cache.alerts.length,
    zonesIndexed,
    topZones: topZones.slice(0, 10)
  });
});

app.get('/refresh', async (_, res) => {
  try {
    const r = await refreshCache();
    res.json({ ok: true, ...r, generatedAt: cache.generatedAt, stale: false });
  } catch (e) {
    // Si existe caché previa en memoria o disco, degradamos con 200
    if (lastGoodCache) {
      return res.status(200).json({
        ok: false,
        error: String(e.message || e),
        generatedAt: lastGoodCache.generatedAt,
        stale: true
      });
    }
    // Sin caché previa (muy raro si hay persistencia), devolvemos error real
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

app.get('/avisos', async (req, res) => {
  try {
    const zona = String(req.query.zona || '').trim();
    if (!/^\d{6}$/.test(zona)) {
      const e = new Error('Parámetro "zona" inválido. Debe ser 6 dígitos (p.ej. 614102).');
      e.status = 400;
      throw e;
    }

    // Si la caché está vacía (p.ej. primer arranque), intentamos cargar de disco
    if (!cache.generatedAt) {
      await loadCacheFromDisk();
    }

    const effectiveCache = cache.generatedAt ? cache : (lastGoodCache || cache);
    const list = effectiveCache.byZona.get(zona) || [];

    res.json({
      query: { zona, last_success_at: effectiveCache.generatedAt },
      count: list.length,
      avisos: list
    });
  } catch (err) {
    const status = err.status || 500;
    res.status(status).json({ error: String(err.message || err), status });
  }
});

// ------------------ Arranque --------------------------------

app.listen(PORT, async () => {
  console.log(`AEMET avisos cache (persistente) escuchando en :${PORT}`);
  // Intentamos precargar desde disco para estar listos inmediatamente
  await loadCacheFromDisk();
  // El cron externo llamará a /refresh de forma periódica
});
