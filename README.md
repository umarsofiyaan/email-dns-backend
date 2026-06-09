# email-dns-backend

Express API for the Email DNS Inspector frontend.

## API

### `POST /api/check`

Accepts a JSON body with a required `domain` and an optional sending `ip`:

```json
{
  "domain": "example.com",
  "ip": "192.0.2.1"
}
```

Returns the existing email authentication checks plus frontend-compatible live name server and registrar panels:

- `mx`, `spf`, `dkim`, `dmarc`, `ptr`, `txt`, and `reputation` for email DNS analysis.
- `nameServers` with live NS records, normalized DNS provider detection, provider scores, a `checkedAt` timestamp, and lookup issues.
- `registrar` with RDAP-derived registrar name, IANA ID, WHOIS server, registrar URL, registration dates, domain status values, source, and lookup issues.

### `GET /health`

Returns a basic process health response:

```json
{ "status": "OK" }
```
