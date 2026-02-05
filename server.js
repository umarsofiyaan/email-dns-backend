const express = require('express');
const dns = require('dns').promises;
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ═══════════════════════════════════════════════════════════════
// HELPER: Extract SPF record from TXT records
// ═══════════════════════════════════════════════════════════════
function extractSPFRecord(txtRecords) {
  const spfRecords = txtRecords.filter(record => {
    const joined = Array.isArray(record) ? record.join('') : record;
    return joined.startsWith('v=spf1');
  });
  
  if (spfRecords.length === 0) return null;
  
  return {
    record: Array.isArray(spfRecords[0]) ? spfRecords[0].join('') : spfRecords[0],
    multiple: spfRecords.length > 1
  };
}

// ═══════════════════════════════════════════════════════════════
// HELPER: Count DNS lookups in SPF record
// ═══════════════════════════════════════════════════════════════
function countSPFLookups(spfRecord) {
  // Mechanisms that trigger DNS lookups: include, a, mx, ptr, exists
  const lookupMechanisms = ['include:', 'a:', 'mx:', 'ptr:', 'exists:'];
  let count = 0;
  
  lookupMechanisms.forEach(mechanism => {
    const regex = new RegExp(mechanism, 'g');
    const matches = spfRecord.match(regex);
    if (matches) count += matches.length;
  });
  
  // Standalone 'a' and 'mx' without colon also count
  if (/\ba\b/.test(spfRecord)) count++;
  if (/\bmx\b/.test(spfRecord)) count++;
  
  return count;
}

// ═══════════════════════════════════════════════════════════════
// HELPER: Parse SPF policy
// ═══════════════════════════════════════════════════════════════
function parseSPFPolicy(spfRecord) {
  if (spfRecord.includes('~all')) return '~all (SoftFail)';
  if (spfRecord.includes('-all')) return '-all (Fail)';
  if (spfRecord.includes('?all')) return '?all (Neutral)';
  if (spfRecord.includes('+all')) return '+all (Pass)';
  return 'Unknown';
}

// ═══════════════════════════════════════════════════════════════
// HELPER: Detect email provider from MX records
// ═══════════════════════════════════════════════════════════════
function detectEmailProvider(mxRecords) {
  const exchanges = mxRecords.map(mx => mx.exchange.toLowerCase());
  
  if (exchanges.some(e => e.includes('google.com') || e.includes('googlemail.com'))) {
    return 'Google Workspace';
  }
  if (exchanges.some(e => e.includes('outlook.com') || e.includes('protection.outlook.com'))) {
    return 'Microsoft 365';
  }
  if (exchanges.some(e => e.includes('zoho.com'))) {
    return 'Zoho Mail';
  }
  if (exchanges.some(e => e.includes('protonmail.ch'))) {
    return 'ProtonMail';
  }
  
  return 'Unknown/Custom';
}

// ═══════════════════════════════════════════════════════════════
// HELPER: Check for multiple email providers
// ═══════════════════════════════════════════════════════════════
function detectMultipleProviders(mxRecords) {
  const providers = new Set();
  
  mxRecords.forEach(mx => {
    const exchange = mx.exchange.toLowerCase();
    if (exchange.includes('google.com')) providers.add('Google');
    if (exchange.includes('outlook.com')) providers.add('Microsoft');
    if (exchange.includes('zoho.com')) providers.add('Zoho');
  });
  
  return providers.size > 1;
}

// ═══════════════════════════════════════════════════════════════
// HELPER: Estimate DKIM key size
// ═══════════════════════════════════════════════════════════════
function estimateDKIMKeySize(dkimRecord) {
  const keyMatch = dkimRecord.match(/p=([A-Za-z0-9+/=]+)/);
  if (!keyMatch) return 'Unknown';
  
  const keyData = keyMatch[1];
  const estimatedBits = (keyData.length * 6) / 8 * 8; // Base64 to bits approximation
  
  if (estimatedBits >= 2000) return '2048-bit';
  if (estimatedBits >= 1000) return '1024-bit';
  return `~${Math.round(estimatedBits)}-bit`;
}

// ═══════════════════════════════════════════════════════════════
// HELPER: Detect DKIM key type
// ═══════════════════════════════════════════════════════════════
function detectDKIMKeyType(dkimRecord) {
  if (dkimRecord.includes('k=ed25519')) return 'Ed25519';
  if (dkimRecord.includes('k=rsa') || !dkimRecord.includes('k=')) return 'RSA';
  return 'Unknown';
}

// ═══════════════════════════════════════════════════════════════
// SECTION: MX Records
// ═══════════════════════════════════════════════════════════════
async function checkMX(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    
    if (mxRecords.length === 0) {
      return {
        status: 'FAIL',
        records: [],
        provider: 'None',
        issues: ['No MX records found']
      };
    }
    
    const provider = detectEmailProvider(mxRecords);
    const multipleProviders = detectMultipleProviders(mxRecords);
    const issues = [];
    
    if (multipleProviders) {
      issues.push('Multiple email providers detected - this may cause delivery issues');
    }
    
    // Sort by priority
    mxRecords.sort((a, b) => a.priority - b.priority);
    
    return {
      status: issues.length > 0 ? 'WARN' : 'PASS',
      records: mxRecords,
      provider,
      issues
    };
  } catch (error) {
    return {
      status: 'FAIL',
      records: [],
      provider: 'None',
      issues: [`DNS lookup failed: ${error.message}`]
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// SECTION: SPF Records
// ═══════════════════════════════════════════════════════════════
async function checkSPF(domain) {
  try {
    const txtRecords = await dns.resolveTxt(domain);
    const spfData = extractSPFRecord(txtRecords);
    
    if (!spfData) {
      return {
        status: 'FAIL',
        record: null,
        policy: null,
        lookupCount: 0,
        issues: ['No SPF record found']
      };
    }
    
    const issues = [];
    
    if (spfData.multiple) {
      issues.push('Multiple SPF records detected - only the first one will be used');
    }
    
    const lookupCount = countSPFLookups(spfData.record);
    if (lookupCount > 10) {
      issues.push(`SPF lookup count (${lookupCount}) exceeds the limit of 10 - this will cause SPF failures`);
    }
    
    const policy = parseSPFPolicy(spfData.record);
    
    if (policy === '?all (Neutral)' || policy === '+all (Pass)') {
      issues.push(`Policy ${policy} is too permissive and may allow spoofing`);
    }
    
    return {
      status: issues.length > 0 ? 'WARN' : 'PASS',
      record: spfData.record,
      policy,
      lookupCount,
      issues
    };
  } catch (error) {
    return {
      status: 'FAIL',
      record: null,
      policy: null,
      lookupCount: 0,
      issues: [`DNS lookup failed: ${error.message}`]
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// SECTION: DKIM Auto-Discovery
// ═══════════════════════════════════════════════════════════════
async function checkDKIM(domain) {
  const commonSelectors = [
    'google',
    'selector1',
    'selector2',
    'default',
    'dkim',
    's1',
    's2',
    'k1'
  ];
  
  const foundSelectors = [];
  
  for (const selector of commonSelectors) {
    try {
      const dkimDomain = `${selector}._domainkey.${domain}`;
      const txtRecords = await dns.resolveTxt(dkimDomain);
      
      if (txtRecords.length > 0) {
        const record = Array.isArray(txtRecords[0]) ? txtRecords[0].join('') : txtRecords[0];
        
        // Check if it's actually a DKIM record
        if (record.includes('p=') || record.includes('k=')) {
          const keyType = detectDKIMKeyType(record);
          const keySize = estimateDKIMKeySize(record);
          
          let provider = 'Unknown';
          if (selector.startsWith('google')) provider = 'Google Workspace';
          if (selector.startsWith('selector')) provider = 'Microsoft 365';
          
          foundSelectors.push({
            selector,
            keyType,
            keySize,
            provider,
            record: record.substring(0, 100) + '...' // Truncate for display
          });
        }
      }
    } catch (error) {
      // Selector doesn't exist, continue
    }
  }
  
  if (foundSelectors.length === 0) {
    return {
      status: 'WARN',
      selectors: [],
      issues: ['No DKIM records found on common selectors. DKIM may be using custom selectors or missing entirely.']
    };
  }
  
  return {
    status: 'PASS',
    selectors: foundSelectors,
    issues: []
  };
}

// ═══════════════════════════════════════════════════════════════
// SECTION: DMARC
// ═══════════════════════════════════════════════════════════════
async function checkDMARC(domain) {
  try {
    const dmarcDomain = `_dmarc.${domain}`;
    const txtRecords = await dns.resolveTxt(dmarcDomain);
    
    if (txtRecords.length === 0) {
      return {
        status: 'FAIL',
        record: null,
        policy: null,
        issues: ['No DMARC record found']
      };
    }
    
    const record = Array.isArray(txtRecords[0]) ? txtRecords[0].join('') : txtRecords[0];
    
    // Parse DMARC components
    const policyMatch = record.match(/p=([^;]+)/);
    const adkimMatch = record.match(/adkim=([^;]+)/);
    const aspfMatch = record.match(/aspf=([^;]+)/);
    const ruaMatch = record.match(/rua=([^;]+)/);
    const rufMatch = record.match(/ruf=([^;]+)/);
    const pctMatch = record.match(/pct=([^;]+)/);
    
    const issues = [];
    const policy = policyMatch ? policyMatch[1] : 'none';
    
    if (policy === 'none') {
      issues.push('DMARC policy is set to "none" - emails will not be protected');
    }
    
    if (!ruaMatch) {
      issues.push('No aggregate reporting address (rua) configured - you won\'t receive DMARC reports');
    }
    
    return {
      status: issues.length > 0 ? 'WARN' : 'PASS',
      record,
      policy: policy,
      adkim: adkimMatch ? adkimMatch[1] : 'r (relaxed)',
      aspf: aspfMatch ? aspfMatch[1] : 'r (relaxed)',
      rua: ruaMatch ? ruaMatch[1] : null,
      ruf: rufMatch ? rufMatch[1] : null,
      pct: pctMatch ? pctMatch[1] : '100',
      issues
    };
  } catch (error) {
    return {
      status: 'FAIL',
      record: null,
      policy: null,
      issues: [`DNS lookup failed: ${error.message}`]
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// SECTION: PTR (Reverse DNS)
// ═══════════════════════════════════════════════════════════════
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
    // Perform reverse lookup
    const hostnames = await dns.reverse(ip);
    
    if (hostnames.length === 0) {
      return {
        status: 'FAIL',
        hostname: null,
        fcRdns: false,
        issues: ['No PTR record found for this IP']
      };
    }
    
    const hostname = hostnames[0];
    
    // Perform forward-confirmed reverse DNS (FC-rDNS)
    try {
      const addresses = await dns.resolve4(hostname);
      const fcRdns = addresses.includes(ip);
      
      return {
        status: fcRdns ? 'PASS' : 'FAIL',
        hostname,
        fcRdns,
        issues: fcRdns ? [] : ['Forward-confirmed reverse DNS (FC-rDNS) failed - PTR hostname does not resolve back to the IP']
      };
    } catch (error) {
      return {
        status: 'FAIL',
        hostname,
        fcRdns: false,
        issues: [`FC-rDNS check failed: ${error.message}`]
      };
    }
  } catch (error) {
    return {
      status: 'FAIL',
      hostname: null,
      fcRdns: false,
      issues: [`PTR lookup failed: ${error.message}`]
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// MAIN API ENDPOINT
// ═══════════════════════════════════════════════════════════════
app.post('/api/check', async (req, res) => {
  const { domain, ip } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }
  
  // Clean domain input
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
  
  try {
    // Run all checks in parallel for speed
    const [mx, spf, dkim, dmarc, ptr] = await Promise.all([
      checkMX(cleanDomain),
      checkSPF(cleanDomain),
      checkDKIM(cleanDomain),
      checkDMARC(cleanDomain),
      checkPTR(ip)
    ]);
    
    res.json({
      domain: cleanDomain,
      mx,
      spf,
      dkim,
      dmarc,
      ptr
    });
  } catch (error) {
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', service: 'Email DNS Inspector' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Email DNS Inspector API running on port ${PORT}`);
});
