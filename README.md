# 1ntruder - Advanced HTTP Security Scanner

<div align="center">

```
 ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗     ███████╗██████╗ 
 ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     ██╔════╝██╔══██╗
 ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     █████╗  ██████╔╝
 ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     ██╔══╝  ██╔══██╗
 ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗███████╗██║  ██║
 ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
```

**Advanced HTTP Security Scanner & Pentesting Toolkit**

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/purecore-codes/1ntruder)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-audited-brightgreen.svg)](SECURITY_REPORT.md)

</div>

---

## 🚀 Quick Start

```bash
# Install
npm install 1ntruder

# Run security scan
npx 1ntruder scan https://example.com

# Fuzz testing
npx 1ntruder fuzz https://target.com

# Technology reconnaissance
npx 1ntruder recon https://site.com
```

## 🔥 Features

### 🛡️ Security Scanning
- **Header Analysis**: Check HSTS, CSP, X-Frame-Options, and 10+ security headers
- **Vulnerability Detection**: Identify CORS misconfigurations, information disclosure
- **Redirect Analysis**: Detect redirect chains and potential open redirects
- **Security Score**: Get a 0-100 score with prioritized recommendations

### 💣 Fuzzing & Attack Simulation
- **SQL Injection**: Test for common SQLi payloads
- **XSS Detection**: Cross-site scripting vulnerability tests
- **Path Traversal**: LFI/RFI and directory traversal attempts
- **Sensitive Paths**: Enumerate .env, .git, admin panels, backups

### 🔍 Reconnaissance
- **Tech Stack Detection**: Identify 25+ technologies (WordPress, React, Nginx, etc.)
- **Link Extraction**: Discover forms, endpoints, and external resources
- **Cookie Analysis**: Check security flags (HttpOnly, Secure, SameSite)
- **Server Fingerprinting**: Extract server software and version info

### ⚡ Advanced HTTP Client
- **Automatic Retries**: Configurable retry with exponential backoff
- **Request Logging**: Detailed logs for debugging and auditing
- **Batch Requests**: Execute multiple requests efficiently
- **Pattern Matching**: Detect content anomalies and patterns

## 📦 Installation

```bash
npm install 1ntruder
# or
yarn add 1ntruder
# or
bun add 1ntruder
```

## 💻 Usage

### CLI Commands

```bash
# Full security scan
npx 1ntruder scan https://example.com

# Deep scan with all checks
npx 1ntruder scan https://example.com --depth=deep

# Basic fuzzing
npx 1ntruder fuzz https://target.com

# Custom payload fuzzing
npx 1ntruder fuzz https://target.com --payloads=custom

# Technology reconnaissance
npx 1ntruder recon https://site.com

# Header analysis only
npx 1ntruder headers https://example.com

# Show help
npx 1ntruder --help
```

### NPM Scripts

```json
{
  "scripts": {
    "build": "npm run 1ntruder",
    "scan": "1ntruder scan <url>",
    "fuzz": "1ntruder fuzz <url>",
    "recon": "1ntruder recon <url>"
  }
}
```

### Programmatic Usage

```typescript
import { HttpScanner, HttpFuzzer, AdvancedHttpClient } from '1ntruder';

// Security Scan
const scanner = new HttpScanner();
const result = await scanner.scan({
  url: 'https://example.com',
  scanDepth: 'deep'
});
console.log(`Security Score: ${result.score}/100`);

// Fuzzing
const client = new AdvancedHttpClient();
const fuzzer = new HttpFuzzer(client.getInstance());
const vulnerabilities = await fuzzer.performBasicFuzzing('https://target.com');

// Advanced HTTP Client
const httpClient = new AdvancedHttpClient({
  logRequests: true,
  retryCount: 3,
  timeout: 10000
});
const response = await httpClient.get('https://api.example.com');
```

## 🔒 Security Checks Performed

| Category | Checks |
|----------|--------|
| **Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Vulnerabilities** | CORS Misconfiguration, Information Disclosure, Dangerous HTTP Methods |
| **Fuzzing** | SQL Injection, XSS, Path Traversal, Command Injection |
| **Recon** | Technology Detection, Server Fingerprinting, Cookie Analysis |

## 📊 Example Output

```
[1ntruder] Scanning https://example.com...
[1ntruder] ✓ HSTS header present
[1ntruder] ✓ CSP header configured
[1ntruder] ⚠ X-Frame-Options missing
[1ntruder] ⚠ CORS allows all origins
[1ntruder] Security Score: 78/100

Recommendations:
  [HIGH] Add X-Frame-Options header
  [MEDIUM] Restrict CORS origins
  [LOW] Consider adding Permissions-Policy
```

## ⚠️ Disclaimer

**This tool is for educational and authorized security testing only.**

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for misuse of this tool
- Always follow responsible disclosure practices

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/purecore-codes/1ntruder/issues)
- **Documentation**: [PENTEST_GUIDE.md](PENTEST_GUIDE.md)
- **Security Reports**: [SECURITY_REPORT.md](SECURITY_REPORT.md)

---

<div align="center">

**Made with 🔒 by PureCore Codes**

*Simule o ataque antes que eles o façam.*

</div>
