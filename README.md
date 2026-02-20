![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
# HAR Sanitizer

Privacy-focused local HAR file sanitizer with multiple security profiles.

---

## Why this tool exists

HAR (HTTP Archive) files often contain sensitive data:

- Authentication tokens  
- Cookies  
- API keys  
- Internal infrastructure domains  
- Session identifiers  
- Request / response bodies  
- Internal routing information  

This tool allows you to sanitize HAR files **locally** before sharing them.

No external calls. No telemetry. No data leaves your machine.

---

## Features

- Scrubs URLs everywhere in the file
- Masks or aliases hosts
- Redacts sensitive headers
- Removes cookies
- Removes or limits request/response bodies
- Masks UUIDs and numeric IDs in paths
- Multiple security profiles

---

## Security Profiles

### ultra

Maximum privacy. Safe for external sharing.

- All headers redacted
- All cookies redacted
- All bodies removed
- Hosts replaced with `REDACTED_HOST`
- Query strings removed
- IDs masked
- URLs scrubbed everywhere

---

### strict (default)

Safe for internal sharing.

- Sensitive headers redacted
- Non-essential headers removed
- Cookies redacted
- Bodies removed
- Hosts redacted
- IDs masked

Balanced between safety and readability.

---

### debug

Troubleshooting mode.

- Hosts replaced with `HOST_1`, `HOST_2`, etc.
- URL structure preserved (path kept)
- Query strings removed
- IDs masked
- Sensitive headers redacted
- Response bodies kept only for HTTP errors (>= 400)

Allows safe debugging of multi-domain flows.

---

## Installation

Python 3.8+ required.

Clone the repository:

```bash
git clone https://github.com/Lucas-Gourmelon/har-sanitizer.git
cd har-sanitizer
```

---

## Usage

```bash
python sanitize_har.py input.har output.har --profile strict
```

Examples:

```bash
python sanitize_har.py file.har clean_ultra.har --profile ultra
python sanitize_har.py file.har clean_debug.har --profile debug
```

If no profile is specified, `strict` is used by default.

---

## Verification (Optional)

To check for domain leaks after sanitization:

### PowerShell

```powershell
Select-String -Path .\clean.har -Pattern "\.com|\.net|\.org|\.fr|\.lu"
```

### macOS / Linux

```bash
grep -E "\.com|\.net|\.org|\.fr|\.lu" clean.har
```

The command should ideally return no real domain names.

---

## Security Notes

- The tool works entirely offline
- Only URLs starting with `http://` or `https://` are scrubbed
- The `Host` header is explicitly redacted
- UUIDs and numeric path segments are masked
- Designed for safety over convenience

---

## Example

Before:

```json
{
  "url": "https://internal.company.com/users/12345?token=abc123",
  "headers": [
    { "name": "Authorization", "value": "Bearer super_secret_token" }
  ]
}
```

After (`strict` profile):

```json
{
  "url": "https://REDACTED_HOST/users/REDACTED_ID",
  "headers": [
    { "name": "Authorization", "value": "REDACTED" }
  ]
}
```

---

## License

MIT License

---

## Author

Lucas Gourmelon
