const express = require('express');
const dns = require('dns').promises;

const app = express();

/* ─────────────────────────────────────────────
   CORS
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
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json());

/* ─────────────────────────────────────────────
   MX PROVIDER MAP (EXTENSIBLE)
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
      const match = hosts.find(h => h.endsWith(p));
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
  const records = txt.map(r => r.join('')).filter(r => r.startsWith('v=spf1'));
  if (!records.length) return null;
  return { record: records[0], multiple: records.length > 1 };
}

function countSPFLookups(spf) {
  return (spf.match(/\b(include:|a\b|mx\b|ptr\b|exists:)/g) || []).length;
}

function spfPolicy(spf) {
  if (spf.includes('-all')) return 'fail';
  if (spf.includes('~all')) return 'softfail';
  if (spf.includes('?all')) return 'neutral';
  return 'pass';
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
   CHECKS
───────────────────────────────────────────── */
async function checkMX(domain) {
  try {
    const records = await dns.resolveMx(domain);
    records.sort((a, b) => a.priority - b.priority);
    const provider = detectMXProvider(records);
    return { status: 'PASS', records, provider, issues: [] };
  } catch (e) {
    return { status: 'FAIL', records: [], provider: null, issues: [e.message] };
  }
}

async function checkSPF(domain) {
  try {
    const txt = await dns.resolveTxt(domain);
    const spf = extractSPF(txt);
    if (!spf) return { status: 'FAIL', issues: ['No SPF record found'] };

    const lookups = countSPFLookups(spf.record);
    const policy = spfPolicy(spf.record);
    const issues = [];

    if (spf.multiple) issues.push('Multiple SPF records detected');
    if (lookups > 10) issues.push('SPF lookup limit exceeded');
    if (policy !== 'fail' && policy !== 'softfail') issues.push('SPF policy is too permissive');

    return {
      status: issues.length ? 'WARN' : 'PASS',
      record: spf.record,
      policy,
      lookupCount: lookups,
      issues
    };
  } catch (e) {
    return { status: 'FAIL', issues: [e.message] };
  }
}

async function checkDKIM(domain) {
  const selectors = ['google', 'selector1', 'selector2', 'default', 's1', 's2'];
  const found = [];

  for (const s of selectors) {
    try {
      const recs = await dns.resolveTxt(`${s}._domainkey.${domain}`);
      const record = recs[0].join('');
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
    : { status: 'WARN', selectors: [], issues: ['No DKIM found on common selectors'] };
}

async function checkDMARC(domain) {
  try {
    const recs = await dns.resolveTxt(`_dmarc.${domain}`);
    const record = recs[0].join('');
    const policy = record.match(/p=([^;]+)/)?.[1] || 'none';
    const rua = record.match(/rua=([^;]+)/)?.[1];
    const pct = record.match(/pct=([^;]+)/)?.[1] || '100';
    const issues = [];

    if (policy === 'none') issues.push('DMARC policy is none');
    if (!rua) issues.push('No DMARC rua configured');

    return { status: issues.length ? 'WARN' : 'PASS', record, policy, rua, pct, issues };
  } catch {
    return { status: 'FAIL', issues: ['No DMARC record found'] };
  }
}

async function checkPTR(ip) {
  if (!ip) return { status: 'SKIPPED', issues: ['No IP provided'] };
  try {
    const host = (await dns.reverse(ip))[0];
    const addrs = await dns.resolve(host);
    return { status: addrs.includes(ip) ? 'PASS' : 'FAIL', hostname: host, fcRdns: addrs.includes(ip), issues: [] };
  } catch (e) {
    return { status: 'FAIL', issues: [e.message] };
  }
}

/* ─────────────────────────────────────────────
   REPUTATION (HEURISTIC, SAFE)
───────────────────────────────────────────── */
function buildReputation({ spf, dkim, dmarc }) {
  let score = 100;
  const notes = [];

  if (spf?.policy !== 'fail' && spf?.policy !== 'softfail') {
    score -= 20; notes.push('SPF policy is weak');
  }
  if (!dkim?.selectors?.length) {
    score -= 30; notes.push('No DKIM detected');
  } else if (dkim.selectors.some(s => s.keySize === '1024-bit')) {
    score -= 10; notes.push('Weak DKIM key size');
  }
  if (dmarc?.policy === 'none') {
    score -= 20; notes.push('DMARC policy is none');
  }

  let level = 'Good';
  if (score < 80) level = 'Medium';
  if (score < 50) level = 'High Risk';

  return { score, level, notes };
}

/* ─────────────────────────────────────────────
   API
───────────────────────────────────────────── */
app.post('/api/check', async (req, res) => {
  const { domain, ip } = req.body;
  const clean = domain?.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
  if (!clean) return res.status(400).json({ error: 'Domain required' });

  const [mx, spf, dkim, dmarc, ptr] = await Promise.all([
    checkMX(clean),
    checkSPF(clean),
    checkDKIM(clean),
    checkDMARC(clean),
    checkPTR(ip)
  ]);

  const reputation = buildReputation({ spf, dkim, dmarc });

  res.json({ domain: clean, mx, spf, dkim, dmarc, ptr, reputation });
});

app.listen(process.env.PORT || 3001, () =>
  console.log('🚀 Email DNS Inspector API running')
);
