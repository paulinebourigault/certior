# Web Browsing Skill

## Description
Fetch and parse web pages with safety guarantees. All HTTP requests are verified
against URL allowlists/blocklists, rate-limited, and tracked for information flow.

## Capabilities Required
- `network:http:read` - Make outbound HTTP GET requests
- `filesystem:cache:write` - Cache fetched pages locally

## Safety Guarantees
- **URL validation**: Only HTTPS URLs allowed; `.onion`, `.gov`, `.mil` blocked
- **Rate limiting**: Maximum 60 requests per minute
- **Size limits**: Response bodies capped at 10 MB
- **Timeout**: 30-second per-request timeout
- **No data exfiltration**: GET-only, no POST data sent

## Formal Properties (Z3-verified)
1. `no_unauthorized_domains` - All requested URLs match allowlist
2. `rate_limit_respected` - Request count within window ≤ max
3. `no_data_exfiltration` - GET requests carry no POST body

## Compliance
- **HIPAA**: Not applicable (no PHI access)
- **SOX**: Applicable - may access financial sources containing MNPI
- **GDPR**: Applicable - may collect personal data from EU sources

## Usage
```python
skill = loader.load_skill("web_browsing", token)
browser = skill.implementation.SafeWebBrowser(skill.verification)
html = await browser.fetch("https://example.com")
```
