// server.js
// Microservicio: Avisos AEMET por zona (CAP v1.2) – “toda su info”
// ------------------------------------------------------------------
// GET  /avisos?zona=614102        --> usa AEMET OpenData “último elaborado” del área (61 para 614xxx)
//      Opcional: &api_key=...     --> si no llega, usa process.env.AEMET_API_KEY
//
// Respuesta JSON (resumen):
// {
//   query: { zona, area, url_catalogo, url_datos, url_metadatos },
//   metadatos: {...} | null,                 // <-- ahora con tildes/ñ bien decodificados
//   ficheros: [ { name, matched_by, size, sha1 }, ...],
//   avisos: [ { file, header:{...}, info:[...], raw_xml:"<alert>...</alert>" }, ... ]
// }
//
// Notas:
// - AEMET devuelve un TAR/TAR.GZ con muchos XML CAP. Filtramos por nombre que contenga la “zona” (614102).
//   Si no hay coincidencias por nombre, parseamos todos y filtramos por geocodes (best-effort).
// - Parche de decodificación: los METADATOS pueden venir en Latin-1/ISO-8859. Se añade fetchJSONSmart()
//   para leerlos sin “símbolos raros �”.
// ------------------------------------------------------------------

import express from 'express';
import { fetch } from 'undici';
import * as zlib from 'zlib';
import tar from 'tar-stream';
import crypto from 'crypto';
import { XMLParser } from 'fast-xml-parser';

const app = express();
const PORT = process.env.PORT || 3000;
const UA = 'MT-Neo-Avisos-Zona/1.0';

app.use(express.json({ limit: '4mb' }));

// ---------- Utilidades generales -------------------------------------------

function assertZona(z) {
  if (!/^\d{6}$/.test(z || '')) {
    const e = new Error('Parámetro "zona" inválido. Debe ser 6 dígitos (p.ej. 614102).');
    e.status = 400;
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
  if (!r.ok) throw new Error(`HTTP ${r.status} al descargar datos (TAR/XML)`);
  const ab = await r.arrayBuffer();
  return Buffer.from(ab);
}

// *** NUEVO ***: decodificación robusta para JSON con posibles ISO-8859/Latin-1
async function fetchJSONSmart(url, headers = {}) {
  const r = await fetch(url, { headers: { accept: 'application/json,*/*;q=0.8', 'user-agent': UA, ...headers } });
  if (!r.ok) throw new Error(`HTTP ${r.status} en ${url}`);

  const buf = Buffer.from(await r.arrayBuffer());
  const ct = (r.headers.get('content-type') || '').toLowerCase();

  let text;
  if (ct.includes('iso-8859') || ct.includes('latin1')) {
    // El servidor declara Latin-1 → decodificar en latin1
    text = buf.toString('latin1');
  } else {
    // Heurística: elegir la decodificación con menos caracteres de reemplazo � (U+FFFD)
    const utf8 = buf.toString('utf8');
    const lat1 = buf.toString('latin1');
    const bads = (s) => (s.match(/\uFFFD/g) || []).length;
    text = bads(lat1) < bads(utf8) ? lat1 : utf8;
  }

  // Quitar BOM si existe
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

  return JSON.parse(text);
}

function gunzipIfNeeded(buf) {
  return isGzip(buf) ? zlib.gunzipSync(buf) : buf;
}

async function tarEntries(buf) {
  // Devuelve [{name, buffer, size, sha1}] leyendo un TAR (o TAR.GZ ya descomprimido)
  const tarBuf = gunzipIfNeeded(buf);
  const out = [];
  await new Promise((resolve, reject) => {
    const extract = tar.extract();
    extract.on('entry', (hdr, stream, next) => {
      const chunks = [];
      stream.on('data', (c) => chunks.push(c));
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
  // Los XML de AEMET suelen ser UTF-8; si fallara, probar Latin-1
  try {
    return b.toString('utf8');
  } catch {
    return b.toString('latin1');
  }
}

// ---------- Parseo CAP v1.2 -----------------------------------------------

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  textNodeName: '#text',
  trimValues: true,
});

function asArray(x) {
  return Array.isArray(x) ? x : x == null ? [] : [x];
}

function parseCapXml(xmlText) {
  const root = parser.parse(xmlText);
  const alerts = asArray(root?.alert || root?.['cap:alert']); // por si viene con namespace
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

function fileMatchesZonaByName(fileName, zona) {
  return fileName.includes(zona);
}

function alertHasZonaByGeocode(parsedAlert, zona) {
  // Busca el código exacto en cualquier geocode.value
  for (const inf of parsedAlert.info) {
    for (const area of inf.areas) {
      for (const g of area.geocodes) {
        if (String(g.value || '').includes(zona)) return true;
      }
    }
  }
  return false;
}

// ---------- Endpoints ------------------------------------------------------

app.get('/', (_, res) => {
  res.type('text/plain').send('AEMET avisos por zona – OK');
});

app.get('/avisos', async (req, res) => {
  try {
    const zona = String(req.query.zona || '').trim();
    assertZona(zona);

    // api_key por query o variable de entorno
    const apiKey = String(req.query.api_key || process.env.AEMET_API_KEY || '').trim();
    if (!apiKey) {
      const e = new Error('Falta api_key (query ?api_key=... o variable de entorno AEMET_API_KEY).');
      e.status = 400;
      throw e;
    }

    // Área = 2 primeros dígitos de la zona (ej. 61 -> Andalucía)
    const area = zona.substring(0, 2);

    // 1) HATEOAS: obtener URL real de datos (TAR/TAR.GZ)
    const urlCatalogo = `https://opendata.aemet.es/opendata/api/avisos_cap/ultimoelaborado/area/${area}?api_key=${encodeURIComponent(apiKey)}`;
    const cat = await fetchJSON(urlCatalogo);
    const urlDatos = cat?.datos;
    const urlMetadatos = cat?.metadatos || null;
    if (!urlDatos) {
      const e = new Error('Respuesta de AEMET sin "datos".');
      e.status = 502;
      throw e;
    }

    // 2) Descarga de datos (TAR/TAR.GZ o, excepcionalmente, XML directo)
    const dataBuf = await fetchBuffer(urlDatos);

    // 3) Si es TAR: extraer; si no, tratar como XML directo
    let entries = [];
    let isTar = true;
    try {
      entries = await tarEntries(dataBuf);
    } catch {
      isTar = false;
    }

    const ficheros = [];
    const avisos = [];

    if (isTar) {
      // --- TAR con múltiples XML CAP ---
      for (const ent of entries) {
        ficheros.push({
          name: ent.name,
          size: ent.size,
          sha1: ent.sha1,
          matched_by: fileMatchesZonaByName(ent.name, zona) ? 'file_name' : null,
        });
      }

      // 3.a) Filtrar por nombre de fichero
      let objetivos = entries.filter(
        (e) => fileMatchesZonaByName(e.name, zona) && e.name.toLowerCase().endsWith('.xml')
      );

      // 3.b) Si no hay por nombre, parsear todos y filtrar por geocode
      if (objetivos.length === 0) {
        for (const e of entries) {
          if (!e.name.toLowerCase().endsWith('.xml')) continue;
          const xml = decodeToString(e.buffer);
          const parsedList = parseCapXml(xml);
          for (const pa of parsedList) {
            if (alertHasZonaByGeocode(pa, zona)) {
              avisos.push({ file: e.name, ...pa, raw_xml: xml });
              // Marcar fichero como matched_by=geocode
              const ff = ficheros.find((x) => x.name === e.name);
              if (ff && !ff.matched_by) ff.matched_by = 'geocode';
            }
          }
        }
      } else {
        // Parsear únicamente los objetivos (por nombre)
        for (const e of objetivos) {
          const xml = decodeToString(e.buffer);
          const parsedList = parseCapXml(xml);
          for (const pa of parsedList) {
            avisos.push({ file: e.name, ...pa, raw_xml: xml });
          }
        }
      }
    } else {
      // --- XML directo (caso raro) ---
      const xml = decodeToString(dataBuf);
      const parsedList = parseCapXml(xml);
      for (const pa of parsedList) {
        const matched = alertHasZonaByGeocode(pa, zona);
        avisos.push({ file: 'datos.xml', ...pa, raw_xml: xml, matched_by: matched ? 'geocode' : null });
      }
    }

    // 4) Recuperar metadatos (opcional) con decodificación robusta (UTF-8 o Latin-1)
    let metadatos = null;
    if (urlMetadatos) {
      try {
        metadatos = await fetchJSONSmart(urlMetadatos);
      } catch {
        // opcional: si falla, ignoramos metadatos
      }
    }

    // 5) Respuesta completa
    res.json({
      query: {
        zona,
        area,
        url_catalogo: urlCatalogo,
        url_datos: urlDatos,
        url_metadatos: urlMetadatos,
      },
      metadatos,
      ficheros,
      avisos,
    });
  } catch (err) {
    const status = err.status || 500;
    res.status(status).json({ error: String(err.message || err), status });
  }
});

// Salud
app.get('/health', (_, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`AEMET avisos por zona escuchando en :${PORT}`);
});
