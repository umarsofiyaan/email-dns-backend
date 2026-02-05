const express = require('express');
const dns = require('dns').promises;

const app = express();

/* ─────────────────────────────────────────────
   CORS
───────────────────────────────────────────── */
const allowedOrigins = [
  'https://email-dns-frontend.pages.dev',
  'https://dns.umarsofiyaan.shop',
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

app.use(express.json());

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
   CHECKS
───────────────────────────────────────────── */
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
  const found = [];

  for (const s of selectors) {
    try {
      const recs = await dns.resolveTxt(`${s}._domainkey.${domain}`);
      const record = recs[0] ? (Array.isArray(recs[0]) ? recs[0].join('') : recs[0]) : '';
      if (record.includes('p=')) {
        found.push({
          selector: s,
          host: `${s}._domainkey.${domain}`,
          record,
          keyType: dkimKeyType(record),
          keySize: dkimKeySize(record)
        });
      }
    } catch {}
  }

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
  const { domain, ip } = req.body;
  const clean = domain?.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
  if (!clean) return res.status(400).json({ error: 'Domain required' });

  const [mx, spf, dkim, dmarc, ptr, txt] = await Promise.all([
    checkMX(clean),
    checkSPF(clean),
    checkDKIM(clean),
    checkDMARC(clean),
    checkPTR(ip),
    checkAllTXT(clean)
  ]);

  const reputation = buildReputation({ spf, dkim, dmarc });

  res.json({ 
    domain: clean, 
    timestamp: new Date().toISOString(),
    mx, 
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

app.listen(process.env.PORT || 3001, () =>
  console.log('🚀 DNS Inspector API running')
);
