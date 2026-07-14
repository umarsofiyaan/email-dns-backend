const express = require('express');
const dns = require('dns').promises;
const https = require('https');
const dgram = require('dgram');
const net = require('net');

const app = express();

/* ─────────────────────────────────────────────
   CORS
───────────────────────────────────────────── */
const allowedOrigins = [
  'https://email-dns-frontend.pages.dev',
  'https://dns.umarsofiyaan.shop',
   'https://gervacio-dns.umarsofiyaan.shop',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: '16kb' }));

/* ─────────────────────────────────────────────
   INPUT VALIDATION
───────────────────────────────────────────── */
const DOMAIN_LABEL_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function normalizeDomain(input) {
  const raw = String(input || '').trim().toLowerCase();
  if (!raw) return '';

  let host = raw;
  try {
    host = new URL(raw.includes('://') ? raw : `http://${raw}`).hostname;
  } catch {
    host = raw.split('/')[0].split('?')[0].split('#')[0];
  }

  return host.replace(/\.$/, '');
}

function isValidDomain(domain) {
  if (!domain || domain.length > 253 || domain.includes('..') || domain.includes('_')) return false;
  if (net.isIP(domain)) return false;

  const labels = domain.split('.');
  if (labels.length < 2) return false;

  return labels.every(label => DOMAIN_LABEL_REGEX.test(label));
}

function normalizeIp(input) {
  const value = String(input || '').trim();
  return value || null;
}

function isValidOptionalIp(ip) {
  return !ip || net.isIP(ip) !== 0;
}

function asyncTimeout(promise, milliseconds, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${milliseconds}ms`)), milliseconds);
  });

  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/* ─────────────────────────────────────────────
   MX PROVIDER MAP
───────────────────────────────────────────── */
const MX_PROVIDERS = [
  { name: 'Google Workspace', patterns: ['google.com', 'googlemail.com'] },
  { name: 'Microsoft 365', patterns: ['outlook.com', 'protection.outlook.com'] },
  { name: 'Zoho Mail', patterns: ['zoho.com', 'zoho.in', 'zohomail.com'] },
  { name: 'Proton Mail', patterns: ['protonmail', 'proton.me'] },
  { name: 'Fastmail', patterns: ['fastmail.com'] },
  { name: 'Mimecast', patterns: ['mimecast.com'] },
  { name: 'Proofpoint', patterns: ['pphosted.com'] }
];

function detectMXProvider(mxRecords) {
  const hosts = mxRecords.map(r => r.exchange.toLowerCase());
  for (const provider of MX_PROVIDERS) {
    for (const p of provider.patterns) {
      const match = hosts.find(h => h.includes(p));
      if (match) {
        return { name: provider.name, confidence: 'high', matchedBy: match };
      }
    }
  }
  return { name: 'Custom / Self-hosted', confidence: 'low', matchedBy: null };
}


/* ─────────────────────────────────────────────
   DNS PROVIDER MAP
───────────────────────────────────────────── */
const DNS_PROVIDERS = [
  { name: 'Cloudflare', patterns: ['cloudflare.com', 'cloudflare.net'], score: 95 },
  { name: 'Amazon Route 53', patterns: ['awsdns-'], score: 94 },
  { name: 'Google Cloud DNS', patterns: ['googledomains.com', 'google.com'], score: 92 },
  { name: 'Microsoft Azure DNS', patterns: ['azure-dns.com', 'azure-dns.net', 'azure-dns.org', 'azure-dns.info'], score: 91 },
  { name: 'Akamai', patterns: ['akam.net', 'akamai.com', 'akadns.net'], score: 92 },
  { name: 'NS1', patterns: ['nsone.net', 'ns1.com'], score: 91 },
  { name: 'DNS Made Easy', patterns: ['dnsmadeeasy.com'], score: 90 },
  { name: 'DigitalOcean', patterns: ['digitalocean.com'], score: 86 },
  { name: 'Hetzner', patterns: ['hetzner.com', 'your-server.de'], score: 84 },
  { name: 'Namecheap', patterns: ['registrar-servers.com'], score: 82 },
  { name: 'GoDaddy', patterns: ['domaincontrol.com'], score: 80 },
  { name: 'Porkbun', patterns: ['porkbun.com'], score: 82 },
  { name: 'Hostinger', patterns: ['dns-parking.com', 'hostinger.com'], score: 78 },
  { name: 'Bluehost', patterns: ['bluehost.com'], score: 76 },
  { name: 'Squarespace Domains', patterns: ['squarespacedns.com'], score: 82 }
];

function normalizeHost(host) {
  return String(host || '').trim().toLowerCase().replace(/\.$/, '');
}

function encodeDnsName(domain) {
  return Buffer.concat(domain.split('.').map(label => {
    const value = Buffer.from(label, 'ascii');
    return Buffer.concat([Buffer.from([value.length]), value]);
  }).concat(Buffer.from([0])));
}

function readDnsName(buffer, offset, depth = 0) {
  if (depth > 10) throw new Error('DNS compression pointer loop detected');

  const labels = [];
  let current = offset;
  let consumed = 0;

  while (current < buffer.length) {
    const length = buffer[current];

    if ((length & 0xc0) === 0xc0) {
      const pointer = ((length & 0x3f) << 8) | buffer[current + 1];
      const pointed = readDnsName(buffer, pointer, depth + 1);
      labels.push(pointed.name);
      consumed += 2;
      return { name: labels.filter(Boolean).join('.'), offset: offset + consumed };
    }

    if (length === 0) {
      consumed += 1;
      return { name: labels.join('.'), offset: offset + consumed };
    }

    current += 1;
    labels.push(buffer.slice(current, current + length).toString('ascii'));
    current += length;
    consumed += length + 1;
  }

  throw new Error('Invalid DNS name in response');
}

function queryDnsNsOverUdp(domain, server) {
  return new Promise((resolve, reject) => {
    const family = server.includes(':') ? 'udp6' : 'udp4';
    const socket = dgram.createSocket(family);
    const id = Math.floor(Math.random() * 65535);
    const question = encodeDnsName(domain);
    const packet = Buffer.concat([
      Buffer.from([
        (id >> 8) & 0xff, id & 0xff,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00
      ]),
      question,
      Buffer.from([0x00, 0x02, 0x00, 0x01])
    ]);

    let settled = false;
    const done = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      error ? reject(error) : resolve(result);
    };

    const timer = setTimeout(() => done(new Error(`DNS UDP query timed out for ${server}`)), 4000);

    socket.on('message', (message) => {
      try {
        const responseId = message.readUInt16BE(0);
        if (responseId !== id) return;

        const answerCount = message.readUInt16BE(6);
        const authorityCount = message.readUInt16BE(8);
        let offset = 12;

        for (let i = 0; i < message.readUInt16BE(4); i += 1) {
          offset = readDnsName(message, offset).offset + 4;
        }

        const records = [];
        for (let i = 0; i < answerCount + authorityCount; i += 1) {
          offset = readDnsName(message, offset).offset;
          const type = message.readUInt16BE(offset);
          offset += 2;
          offset += 2; // class
          offset += 4; // ttl
          const rdLength = message.readUInt16BE(offset);
          offset += 2;
          const rdStart = offset;

          if (type === 2) {
            records.push(readDnsName(message, offset).name);
          }

          offset = rdStart + rdLength;
        }

        done(null, records);
      } catch (e) {
        done(e);
      }
    });

    socket.on('error', done);
    socket.send(packet, 53, server);
  });
}

async function resolveNameServers(domain) {
  try {
    return await dns.resolveNs(domain);
  } catch (e) {
    if (e.code && !['ENOTIMP', 'ENODATA', 'ENOTFOUND', 'ESERVFAIL', 'ETIMEOUT'].includes(e.code)) {
      throw e;
    }

    const servers = [...new Set([...dns.getServers(), '1.1.1.1', '8.8.8.8'])]
      .map(server => server.replace(/^\[|\]$/g, '').replace(/#\d+$/, ''));

    try {
      return await Promise.any(servers.map(async (server) => {
        const records = await queryDnsNsOverUdp(domain, server);
        if (!records.length) throw new Error(`No NS records returned from ${server}`);
        return records;
      }));
    } catch (fallbackError) {
      const reason = fallbackError.errors?.[0]?.message || fallbackError.message || e.message;
      throw new Error(reason || 'No NS records found');
    }
  }
}

function detectDNSProvider(host) {
  const normalized = normalizeHost(host);
  for (const provider of DNS_PROVIDERS) {
    const matchedBy = provider.patterns.find(pattern => normalized.includes(pattern));
    if (matchedBy) {
      return {
        name: provider.name,
        score: provider.score,
        confidence: 'high',
        matchedBy
      };
    }
  }
  return {
    name: 'Custom / Unknown DNS',
    score: 60,
    confidence: 'low',
    matchedBy: normalized || null
  };
}

function selectPrimaryDNSProvider(records) {
  if (!records.length) {
    return {
      name: 'Unknown',
      score: 'N/A',
      confidence: 'low',
      matchedBy: null
    };
  }

  const counts = new Map();
  for (const record of records) {
    const current = counts.get(record.provider.name) || { ...record.provider, count: 0 };
    current.count += 1;
    counts.set(record.provider.name, current);
  }

  const [primary] = [...counts.values()].sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    return Number(b.score || 0) - Number(a.score || 0);
  });

  return {
    name: primary.name,
    score: primary.score,
    confidence: primary.confidence,
    matchedBy: primary.matchedBy
  };
}

/* ─────────────────────────────────────────────
   SPF HELPERS
───────────────────────────────────────────── */
function extractSPF(txt) {
  const records = txt.map(r => Array.isArray(r) ? r.join('') : r).filter(r => r.startsWith('v=spf1'));
  if (!records.length) return null;
  return { record: records[0], multiple: records.length > 1 };
}

function countSPFLookups(spf) {
  let count = 0;
  count += (spf.match(/include:/g) || []).length;
  count += (spf.match(/\ba:/g) || []).length;
  count += (spf.match(/\bmx\b/g) || []).length;
  count += (spf.match(/\bptr\b/g) || []).length;
  count += (spf.match(/exists:/g) || []).length;
  return count;
}

function spfPolicy(spf) {
  if (spf.includes('-all')) return 'Fail (Reject)';
  if (spf.includes('~all')) return 'SoftFail (Accept but mark)';
  if (spf.includes('?all')) return 'Neutral (No policy)';
  if (spf.includes('+all')) return 'Pass (Accept all - DANGEROUS)';
  return 'Unknown';
}

function spfMechanisms(spf) {
  const mechanisms = [];
  const includes = spf.match(/include:[^\s]+/g) || [];
  includes.forEach(inc => mechanisms.push({ type: 'include', value: inc.replace('include:', '') }));
  
  const ip4 = spf.match(/ip4:[^\s]+/g) || [];
  ip4.forEach(ip => mechanisms.push({ type: 'ip4', value: ip.replace('ip4:', '') }));
  
  const ip6 = spf.match(/ip6:[^\s]+/g) || [];
  ip6.forEach(ip => mechanisms.push({ type: 'ip6', value: ip.replace('ip6:', '') }));
  
  if (/\ba\b/.test(spf)) mechanisms.push({ type: 'a', value: 'Current domain A record' });
  if (/\bmx\b/.test(spf)) mechanisms.push({ type: 'mx', value: 'Current domain MX records' });
  
  return mechanisms;
}

/* ─────────────────────────────────────────────
   DKIM HELPERS
───────────────────────────────────────────── */
function dkimKeyType(rec) {
  return rec.includes('k=ed25519') ? 'Ed25519' : 'RSA';
}

function dkimKeySize(rec) {
  const m = rec.match(/p=([A-Za-z0-9+/=]+)/);
  if (!m) return 'Unknown';
  const bits = Math.round((m[1].length * 6) / 8) * 8;
  if (bits >= 2048) return '2048-bit';
  if (bits >= 1024) return '1024-bit';
  return `${bits}-bit`;
}

/* ─────────────────────────────────────────────
   DMARC PARSER
───────────────────────────────────────────── */
function parseDMARC(record) {
  return {
    policy: record.match(/p=([^;]+)/)?.[1] || 'none',
    subdomainPolicy: record.match(/sp=([^;]+)/)?.[1] || null,
    percentage: record.match(/pct=([^;]+)/)?.[1] || '100',
    rua: record.match(/rua=([^;]+)/)?.[1] || null,
    ruf: record.match(/ruf=([^;]+)/)?.[1] || null,
    dkimAlignment: record.match(/adkim=([^;]+)/)?.[1] || 'r',
    spfAlignment: record.match(/aspf=([^;]+)/)?.[1] || 'r',
    reportFormat: record.match(/rf=([^;]+)/)?.[1] || 'afrf',
    reportInterval: record.match(/ri=([^;]+)/)?.[1] || '86400'
  };
}


/* ─────────────────────────────────────────────
   RDAP HELPERS
───────────────────────────────────────────── */
function requestJson(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        'Accept': 'application/rdap+json, application/json',
        'User-Agent': 'email-dns-inspector/1.0'
      },
      timeout: 8000
    }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        return resolve(requestJson(new URL(res.headers.location, url).toString()));
      }

      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error(`RDAP request failed with HTTP ${res.statusCode}`));
        }
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(new Error(`RDAP response was not valid JSON: ${e.message}`));
        }
      });
    });

    req.on('timeout', () => req.destroy(new Error('RDAP request timed out')));
    req.on('error', reject);
  });
}

function vcardValue(entity, key) {
  const entries = entity?.vcardArray?.[1] || [];
  const item = entries.find(([name]) => name === key);
  return item?.[3] || null;
}

function findRegistrarEntity(entities = []) {
  return entities.find(entity => (entity.roles || []).includes('registrar')) || null;
}

function publicIdValue(entity, typePattern) {
  const item = (entity?.publicIds || []).find(id => typePattern.test(id.type || ''));
  return item?.identifier || null;
}

function linkHref(links = [], rels = ['about', 'self']) {
  const link = links.find(l => rels.includes(l.rel) && l.href);
  return link?.href || null;
}

function eventDate(events = [], actions = []) {
  const event = events.find(e => actions.includes(e.eventAction));
  return event?.eventDate || null;
}

function parseRegistrarFromRDAP(data) {
  const registrar = findRegistrarEntity(data.entities || []);
  const name = vcardValue(registrar, 'fn') || data.registrarName || null;
  const ianaId = publicIdValue(registrar, /IANA Registrar ID/i) || data.registrarIANAID || null;

  return {
    status: name ? 'PASS' : 'WARN',
    name,
    registrar: name,
    ianaId,
    registrarId: ianaId,
    whoisServer: data.port43 || null,
    url: vcardValue(registrar, 'url') || linkHref(registrar?.links || []) || null,
    createdAt: eventDate(data.events || [], ['registration']),
    updatedAt: eventDate(data.events || [], ['last changed', 'last update of RDAP database']),
    expiresAt: eventDate(data.events || [], ['expiration']),
    domainStatus: data.status || [],
    source: 'RDAP',
    issues: name ? [] : ['RDAP response did not include registrar details']
  };
}

/* ─────────────────────────────────────────────
   CHECKS
───────────────────────────────────────────── */

async function checkNameServers(domain) {
  try {
    const records = (await resolveNameServers(domain))
      .map(host => normalizeHost(host))
      .sort()
      .map(host => ({
        host,
        provider: detectDNSProvider(host)
      }));

    const issues = [];
    if (records.length === 0) issues.push('No NS records found');

    const provider = selectPrimaryDNSProvider(records);
    const uniqueProviders = new Set(records.map(record => record.provider.name));
    if (uniqueProviders.size > 1) {
      issues.push(`Multiple DNS providers detected: ${[...uniqueProviders].join(', ')}`);
    }

    return {
      status: issues.length ? 'WARN' : 'PASS',
      checkedAt: new Date().toISOString(),
      provider,
      records,
      issues
    };
  } catch (e) {
    return {
      status: 'FAIL',
      checkedAt: new Date().toISOString(),
      provider: selectPrimaryDNSProvider([]),
      records: [],
      issues: [`NS lookup failed: ${e.message}`]
    };
  }
}

async function checkRegistrar(domain) {
  try {
    const data = await requestJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    return parseRegistrarFromRDAP(data);
  } catch (e) {
    return {
      status: 'WARN',
      name: null,
      registrar: null,
      ianaId: null,
      registrarId: null,
      whoisServer: null,
      url: null,
      createdAt: null,
      updatedAt: null,
      expiresAt: null,
      domainStatus: [],
      source: 'RDAP',
      issues: [`Registrar lookup unavailable: ${e.message || String(e) || 'Unknown RDAP error'}`]
    };
  }
}

async function checkMX(domain) {
  try {
    const records = await dns.resolveMx(domain);
    records.sort((a, b) => a.priority - b.priority);
    const provider = detectMXProvider(records);
    const issues = [];
    
    if (records.length === 0) issues.push('No MX records found');
    
    return { 
      status: issues.length > 0 ? 'WARN' : 'PASS', 
      records, 
      provider, 
      issues 
    };
  } catch (e) {
    return { 
      status: 'FAIL', 
      records: [], 
      provider: null, 
      issues: [e.message] 
    };
  }
}

async function checkSPF(domain) {
  try {
    const txt = await dns.resolveTxt(domain);
    const spf = extractSPF(txt);
    if (!spf) {
      return { 
        status: 'FAIL', 
        record: null,
        policy: null,
        lookupCount: 0,
        mechanisms: [],
        issues: ['No SPF record found'] 
      };
    }

    const lookups = countSPFLookups(spf.record);
    const policy = spfPolicy(spf.record);
    const mechanisms = spfMechanisms(spf.record);
    const issues = [];

    if (spf.multiple) issues.push('Multiple SPF records detected');
    if (lookups > 10) issues.push(`SPF lookup count (${lookups}) exceeds limit of 10`);
    if (policy.includes('Neutral') || policy.includes('DANGEROUS')) {
      issues.push('SPF policy is too permissive');
    }

    return {
      status: issues.length ? 'WARN' : 'PASS',
      record: spf.record,
      policy,
      lookupCount: lookups,
      mechanisms,
      issues
    };
  } catch (e) {
    return { 
      status: 'FAIL', 
      record: null,
      policy: null,
      lookupCount: 0,
      mechanisms: [],
      issues: [e.message] 
    };
  }
}

async function checkDKIM(domain) {
  const selectors = ['google', 'selector1', 'selector2', 'default', 's1', 's2', 'dkim', 'k1'];

  const checks = await Promise.all(selectors.map(async (s) => {
    try {
      const recs = await asyncTimeout(dns.resolveTxt(`${s}._domainkey.${domain}`), 3000, `DKIM lookup for ${s}`);
      const record = recs[0] ? (Array.isArray(recs[0]) ? recs[0].join('') : recs[0]) : '';
      if (record.includes('p=')) {
        return {
          selector: s,
          host: `${s}._domainkey.${domain}`,
          record,
          keyType: dkimKeyType(record),
          keySize: dkimKeySize(record)
        };
      }
    } catch {}
    return null;
  }));

  const found = checks.filter(Boolean);

  return found.length
    ? { status: 'PASS', selectors: found, issues: [] }
    : { 
        status: 'WARN', 
        selectors: [], 
        issues: ['No DKIM found on common selectors'] 
      };
}

async function checkDMARC(domain) {
  try {
    const recs = await dns.resolveTxt(`_dmarc.${domain}`);
    const record = recs[0] ? (Array.isArray(recs[0]) ? recs[0].join('') : recs[0]) : '';
    const parsed = parseDMARC(record);
    const issues = [];

    if (parsed.policy === 'none') {
      issues.push('DMARC policy is "none" - monitoring only');
    }
    if (!parsed.rua) {
      issues.push('No aggregate report address configured');
    }

    return { 
      status: issues.length ? 'WARN' : 'PASS', 
      record, 
      parsed,
      issues 
    };
  } catch {
    return { 
      status: 'FAIL', 
      record: null,
      parsed: null,
      issues: ['No DMARC record found'] 
    };
  }
}

async function checkPTR(ip) {
  if (!ip) {
    return { 
      status: 'SKIPPED', 
      hostname: null,
      fcRdns: null,
      issues: ['No IP address provided'] 
    };
  }
  
  try {
    const hostnames = await dns.reverse(ip);
    const hostname = hostnames[0];
    
    try {
      const addrs = await dns.resolve4(hostname);
      const fcRdns = addrs.includes(ip);
      
      return { 
        status: fcRdns ? 'PASS' : 'FAIL', 
        hostname, 
        fcRdns, 
        issues: fcRdns ? [] : ['FC-rDNS failed'] 
      };
    } catch {
      return {
        status: 'FAIL',
        hostname,
        fcRdns: false,
        issues: ['Forward DNS lookup failed']
      };
    }
  } catch (e) {
    return { 
      status: 'FAIL', 
      hostname: null,
      fcRdns: null,
      issues: [`PTR lookup failed: ${e.message}`] 
    };
  }
}

async function checkAllTXT(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const formatted = records.map(r => Array.isArray(r) ? r.join('') : r);
    
    const categorized = {
      spf: formatted.filter(r => r.startsWith('v=spf1')),
      verification: formatted.filter(r => 
        r.includes('verification') || 
        r.startsWith('google-site-verification=') ||
        r.startsWith('MS=')
      ),
      other: formatted.filter(r => 
        !r.startsWith('v=spf1') && 
        !r.includes('verification') &&
        !r.startsWith('google-site-verification=') &&
        !r.startsWith('MS=')
      )
    };
    
    return {
      status: 'PASS',
      all: formatted,
      categorized,
      total: formatted.length
    };
  } catch (e) {
    return {
      status: 'FAIL',
      all: [],
      categorized: { spf: [], verification: [], other: [] },
      total: 0,
      error: e.message
    };
  }
}

function buildReputation({ spf, dkim, dmarc }) {
  let score = 100;
  const notes = [];

  if (!spf?.record) {
    score -= 25;
    notes.push('No SPF record configured');
  } else if (spf.policy?.includes('Neutral') || spf.policy?.includes('DANGEROUS')) {
    score -= 20;
    notes.push('SPF policy is weak');
  }

  if (!dkim?.selectors?.length) {
    score -= 30;
    notes.push('No DKIM detected');
  }

  if (!dmarc?.record) {
    score -= 25;
    notes.push('No DMARC configured');
  } else if (dmarc.parsed?.policy === 'none') {
    score -= 15;
    notes.push('DMARC policy is none');
  }

  let level = 'Good';
  if (score < 80) level = 'Medium';
  if (score < 50) level = 'High Risk';

  return { score, level, notes };
}

app.post('/api/check', async (req, res) => {
  const { domain, ip } = req.body || {};
  const clean = normalizeDomain(domain);
  const cleanIp = normalizeIp(ip);

  if (!clean) return res.status(400).json({ error: 'Domain required' });
  if (!isValidDomain(clean)) return res.status(400).json({ error: 'Invalid domain' });
  if (!isValidOptionalIp(cleanIp)) return res.status(400).json({ error: 'Invalid IP address' });

  const [mx, nameServers, registrar, spf, dkim, dmarc, ptr, txt] = await Promise.all([
    checkMX(clean),
    checkNameServers(clean),
    checkRegistrar(clean),
    checkSPF(clean),
    checkDKIM(clean),
    checkDMARC(clean),
    checkPTR(cleanIp),
    checkAllTXT(clean)
  ]);

  const reputation = buildReputation({ spf, dkim, dmarc });

  res.json({ 
    domain: clean, 
    timestamp: new Date().toISOString(),
    mx,
    nameServers,
    registrar,
    spf, 
    dkim, 
    dmarc, 
    ptr, 
    txt,
    reputation 
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

if (require.main === module) {
  app.listen(process.env.PORT || 3001, () =>
    console.log('🚀 DNS Inspector API running')
  );
}

module.exports = {
  app,
  normalizeDomain,
  isValidDomain,
  normalizeIp,
  isValidOptionalIp,
  buildReputation
};
