# HTTP Header Security Scanner (v3.0)

A Python-based tool for automatically analyzing HTTP security headers and identifying common misconfigurations that could leave web applications vulnerable. See [CHANGELOG.md](CHANGELOG.md) for what's new in v3.

## Features

- 🔍 **Comprehensive Header Analysis**: Checks for essential security headers, including modern cross-origin isolation headers (COOP/COEP/CORP)
- 🛡️ **HSTS Validation**: Verifies proper Strict-Transport-Security implementation
- 🚫 **CSP Evaluation**: Analyzes Content Security Policy headers
- 🔒 **SSL/TLS Inspection**: Examines certificate details and encryption settings
- 📄 **security.txt Discovery**: Checks for an RFC 9116 vulnerability-disclosure contact file
- 🧱 **Fault-Isolated Scanning**: A failure in one check (e.g. a DNS timeout) no longer wipes out the rest of the report
- 📊 **Detailed Reporting**: Human-readable text, JSON, CSV, and a fully styled HTML report with severity color-coding
- ✅ **Tested**: 12-test offline unit test suite (`tests/test_scanner.py`)
- ⚡ **Fast & Efficient**: Concurrent scanning capabilities for multiple URLs

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/Ermiyas411/mishttpchecker.git
cd mishttpchecker

Alternatively, install dependencies directly:

```bash
pip install requests beautifulsoup4 urllib3 cryptography python-dateutil colorama tqdm pyOpenSSL
```

## Usage

### Basic Scanning

```bash
# Scan a single URL
python mishttpchecker.py https://example.com

# Scan with JSON output
python mishttpchecker.py https://example.com --json

# Save results to a file
python mishttpchecker.py https://example.com --output report.txt
```

### Bulk Scanning

```bash
# Scan multiple URLs from a file
python mishttpchecker.py --input urls.txt --output results.json
```

### Advanced Options

```bash
# Set custom timeout (seconds)
python mishttpchecker.py https://example.com --timeout 15

# Disable SSL verification (not recommended)
python mishttpchecker.py https://example.com --no-ssl-verify

# Use specific user agent
python mishttpchecker.py https://example.com --user-agent "MySecurityScanner/1.0"
```

## Security Checks Performed

The tool examines the following security aspects:

### Header Analysis

- **Strict-Transport-Security (HSTS)**: Presence and proper configuration
- **Content-Security-Policy (CSP)**: Implementation and directives
- **X-Content-Type-Options**: Prevents MIME type sniffing
- **X-Frame-Options**: Clickjacking protection
- **X-XSS-Protection**: Cross-site scripting filters
- **Referrer-Policy**: Controls referrer information
- **Permissions-Policy**: Feature access control

### SSL/TLS Analysis

- Certificate validity and expiration
- Supported cipher suites
- TLS/SSL protocol versions

### Cookie Security

- Secure flag implementation
- HttpOnly flag presence
- SameSite attribute configuration

## Output Formats

The tool supports multiple output formats:

1. **Human-readable** (default): Color-coded terminal output
2. **JSON**: Structured data for processing by other tools
3. **CSV**: Spreadsheet-friendly format for bulk analysis
4. **HTML**: Visual report with severity indicators


## Example Output

```
Security Scan Report for https://example.com
==================================================

HSTS:
  Present: True
  Value: max-age=31536000; includeSubDomains
  Issues: None

CSP:
  Present: True
  Value: default-src 'self'; script-src 'self' 'unsafe-inline'
  Issues: ['unsafe-inline directive found']

X-CONTENT-TYPE-OPTIONS:
  Present: True
  Value: nosniff
  Issues: None

SSL CERTIFICATE:
  Valid: True
  Expires: 2023-12-31
  Issuer: Let's Encrypt
  Cipher: TLS_AES_256_GCM_SHA384

OVERALL SCORE: 85/100
```

## Running the Tests

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The suite mocks all network calls, so it runs offline and deterministically — useful for CI.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is designed for security testing and educational purposes only. Always obtain proper authorization before scanning any website or network. The developers are not responsible for misuse of this tool.
