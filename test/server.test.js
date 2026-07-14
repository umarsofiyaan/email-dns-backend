const assert = require('assert/strict');
const test = require('node:test');

const {
  normalizeDomain,
  isValidDomain,
  normalizeIp,
  isValidOptionalIp,
  buildReputation
} = require('../server');

test('normalizeDomain extracts and lowercases hostnames from common inputs', () => {
  assert.equal(normalizeDomain(' HTTPS://Example.COM/path?q=1 '), 'example.com');
  assert.equal(normalizeDomain('mail.example.com.'), 'mail.example.com');
  assert.equal(normalizeDomain('example.com/some/path'), 'example.com');
});

test('isValidDomain accepts DNS hostnames and rejects unsafe values', () => {
  assert.equal(isValidDomain('example.com'), true);
  assert.equal(isValidDomain('sub-domain.example.co.uk'), true);
  assert.equal(isValidDomain('localhost'), false);
  assert.equal(isValidDomain('127.0.0.1'), false);
  assert.equal(isValidDomain('bad_domain.example'), false);
  assert.equal(isValidDomain('-bad.example.com'), false);
  assert.equal(isValidDomain('bad-.example.com'), false);
  assert.equal(isValidDomain('example..com'), false);
});

test('optional IP validation allows blank values and valid IPv4/IPv6 only', () => {
  assert.equal(normalizeIp(''), null);
  assert.equal(normalizeIp(' 192.0.2.1 '), '192.0.2.1');
  assert.equal(isValidOptionalIp(null), true);
  assert.equal(isValidOptionalIp('192.0.2.1'), true);
  assert.equal(isValidOptionalIp('2001:db8::1'), true);
  assert.equal(isValidOptionalIp('not-an-ip'), false);
});

test('buildReputation scores strong and weak authentication consistently', () => {
  assert.deepEqual(
    buildReputation({
      spf: { record: 'v=spf1 include:_spf.example.com -all', policy: 'Fail (Reject)' },
      dkim: { selectors: [{ selector: 'default' }] },
      dmarc: { record: 'v=DMARC1; p=reject', parsed: { policy: 'reject' } }
    }),
    { score: 100, level: 'Good', notes: [] }
  );

  assert.deepEqual(
    buildReputation({ spf: null, dkim: null, dmarc: null }),
    {
      score: 20,
      level: 'High Risk',
      notes: ['No SPF record configured', 'No DKIM detected', 'No DMARC configured']
    }
  );
});
