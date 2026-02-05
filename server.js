const express = require('express');
const dns = require('dns').promises;

const app = express();

/* ─────────────────────────────────────────────
   CORS (Cloudflare Pages → Render)
───────────────────────────────────────────── */
const allowedOrigins = [
  'https://email-dns-frontend.pages.dev',
  'https://dns.umarsofiyaan.shop'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json());

/* ─────────────────────────────────────────────
   SPF HELPERS
───────────────────────────────────────────── */
function extractSPFRecord(txtRecords) {
  const spfRecords = txtRecords
    .map(r => Array.isArray(r) ? r.join('') : r)
    .filter(r => r.startsWith('v=spf1'));

  if (spfRecords.length === 0) return null;

  return {
    record: spfRecords[0],
    multiple: spfRecords.length > 1
  };
}

function countSPFLookups(spfRecord) {
  const mechanisms = ['include:', 'a', 'mx', 'ptr', 'exists:'];
  let count = 0;

  mechanisms.forEach(m => {
    const regex = new RegExp(`\\b${m}`, 'g');
    const matches = spfRecord.match(regex);
    if (matches) count += matches.length;
  });

  return count;
}

function parseSPFPolicy(spfRecord) {
  if (spfRecord.includes('-all')) return '-all (Fail)';
  if (spfRecord.includes('~all')) return '~all (SoftFail)';
  if (spfRecord.includes('?all')) return '?all (Neutral)';
  if (spfRecord.includes('+all')) return '+all (Pass)';
  return 'Unknown';
}

/* ─────────────────────────────────────────────
   MX HELPERS
───────────────────────────────────────────── */
function detectEmailProvider(mxRecords) {
  const exchanges = mxRecords.map(mx => mx.exchange.toLowerCase());

  if (exchanges.some(e => e.includes('google.com'))) return 'Google Workspace';
  if (exchanges.some(e => e.includes('outlook.com') || e.includes('protection.outlook.com'))) return 'Microsoft 365';
  if (exchanges.some(e => e.includes('zoho.com'))) return 'Zoho Mail';
  if (exchanges.some(e => e.includes('protonmail'))) return 'Proton Mail';

  return 'Unknown / Custom';
}

function detectMultipleProviders(mxRecords) {
  const providers = new Set();

  mxRecords.forEach(mx => {
    const e = mx.exchange.toLowerCase();
    if (e.includes('google.com')) providers.add('Google');
    if (e.includes('outlook.com')) providers.add('Microsoft');
    if (e.includes('zoho.com')) providers.add('Zoho');
  });

  return providers.size > 1;
}

/* ─────────────────────────────────────────────
   DKIM HELPERS
───────────────────────────────────────────── */
function detectDKIMKeyType(record) {
  if (record.includes('k=ed25519')) return 'Ed25519';
  return 'RSA';
}

function estimateDKIMKeySize(record) {
  const match = record.match(/p=([A-Za-z0-9+/=]+)/);
  if (!match) return 'Unknown';

  // Rough Base64 length → key size estimate
  const bits = Math.round((match[1].length * 6) / 8) * 8;

  if (bits >= 2048) return '2048-bit';
  if (bits >= 1024) return '1024-bit';
  return `${bits}-bit`;
}

/* ─────────────────────────────────────────────
   CHECKS
───────────────────────────────────────────── */
async function checkMX(domain) {
  try {
    const records = await dns.resolveMx(domain);
    records.sort((a, b) => a.priority - b.priority);

    const provider = detectEmailProvider(records);
    const issues = [];

    if (detectMultipleProviders(records)) {
      issues.push('Multiple email providers detected');
    }

    return {
      status: issues.length ? 'WARN' : 'PASS',
      records,
      provider,
      issues
    };
  } catch (e) {
    return {
      status: 'FAIL',
      records: [],
      provider: 'None',
      issues: [e.message]
    };
  }
}

async function checkSPF(domain) {
  try {
    const txt = await dns.resolveTxt(domain);
    const spf = extractSPFRecord(txt);

    if (!spf) {
      return {
        status: 'FAIL',
        record: null,
        policy: null,
        lookupCount: 0,
        issues: ['No SPF record found']
      };
    }

    const issues = [];
    const lookupCount = countSPFLookups(spf.record);
    const policy = parseSPFPolicy(spf.record);

    if (spf.multiple) issues.push('Multiple SPF records detected');
    if (lookupCount > 10) issues.push(`SPF lookup count (${lookupCount}) exceeds 10`);
    if (policy.includes('Neutral') || policy.includes('Pass')) {
      issues.push('SPF policy is too permissive');
    }

    return {
      status: issues.length ? 'WARN' : 'PASS',
      record: spf.record,
      policy,
      lookupCount,
      issues
    };
  } catch (e) {
    return {
      status: 'FAIL',
      record: null,
      policy: null,
      lookupCount: 0,
      issues: [e.message]
    };
  }
}

async function checkDKIM(domain) {
  const selectors = ['google', 'selector1', 'selector2', 'default', 'dkim', 's1', 's2'];
  const found = [];

  for (const s of selectors) {
    try {
      const recs = await dns.resolveTxt(`${s}._domainkey.${domain}`);
      const record = recs[0].join('');

      if (record.includes('p=')) {
        found.push({
          selector: s,
          keyType: detectDKIMKeyType(record),
          keySize: estimateDKIMKeySize(record)
        });
      }
    } catch {}
  }

  return found.length
    ? { status: 'PASS', selectors: found, issues: [] }
    : { status: 'WARN', selectors: [], issues: ['No DKIM found on common selectors'] };
}

async function checkDMARC(domain) {
  try {
    const recs = await dns.resolveTxt(`_dmarc.${domain}`);
    const record = recs[0].join('');
    const issues = [];

    const policy = record.match(/p=([^;]+)/)?.[1] || 'none';
    const rua = record.match(/rua=([^;]+)/)?.[1];

    if (policy === 'none') issues.push('DMARC policy is none');
    if (!rua) issues.push('No DMARC rua configured');

    return {
      status: issues.length ? 'WARN' : 'PASS',
      record,
      policy,
      rua,
      issues
    };
  } catch (e) {
    return {
      status: 'FAIL',
      record: null,
      policy: null,
      issues: ['No DMARC record found']
    };
  }
}

async function checkPTR(ip) {
  if (!ip) {
    return { status: 'SKIPPED', issues: ['No IP provided'] };
  }

  try {
    const hostnames = await dns.reverse(ip);
    const hostname = hostnames[0];

    const addresses = await dns.resolve(hostname);
    const fcRdns = addresses.includes(ip);

    return {
      status: fcRdns ? 'PASS' : 'FAIL',
      hostname,
      fcRdns,
      issues: fcRdns ? [] : ['FC-rDNS failed']
    };
  } catch (e) {
    return {
      status: 'FAIL',
      hostname: null,
      fcRdns: false,
      issues: [e.message]
    };
  }
}

/* ─────────────────────────────────────────────
   API
───────────────────────────────────────────── */
app.post('/api/check', async (req, res) => {
  const { domain, ip } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });

  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');

  const [mx, spf, dkim, dmarc, ptr] = await Promise.all([
    checkMX(cleanDomain),
    checkSPF(cleanDomain),
    checkDKIM(cleanDomain),
    checkDMARC(cleanDomain),
    checkPTR(ip)
  ]);

  res.json({ domain: cleanDomain, mx, spf, dkim, dmarc, ptr });
});

app.get('/health', (_, res) => {
  res.json({ status: 'OK', service: 'Email DNS Inspector' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Email DNS Inspector API running on port ${PORT}`);
});
