<div align="center">

<table width="1000px" border="0" cellspacing="0" cellpadding="0">
<tr>
<td bgcolor="#010409" align="center">

<br />
<img src="logo.jpg" alt="1ntruder" width="1000" />
<br />

<h1 align="center">1ntruder — Advanced HTTP Security Scanner</h1>

<p align="center">
  <a href="https://www.npmjs.com/package/1ntruder">
    <img src="https://img.shields.io/npm/v/1ntruder.svg?style=for-the-badge&logo=npm&color=CB0000" alt="NPM Version" />
  </a>
  <a href="https://www.npmjs.com/package/1ntruder">
    <img src="https://img.shields.io/npm/dm/1ntruder.svg?style=for-the-badge&logo=npm&color=007ACC" alt="Monthly Downloads" />
  </a>
  <a href="https://github.com/purecore-codes/1ntruder/stargazers">
    <img src="https://img.shields.io/github/stars/purecore-codes/1ntruder.svg?style=for-the-badge&logo=github&color=C69026" alt="GitHub Stars" />
  </a>
  <a href="https://github.com/purecore-codes/1ntruder/issues">
    <img src="https://img.shields.io/github/issues/purecore-codes/1ntruder.svg?style=for-the-badge&logo=github&color=2EA043" alt="GitHub Issues" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/purecore-codes/1ntruder/graphs/commit-activity">
    <img src="https://img.shields.io/github/last-commit/purecore-codes/1ntruder.svg?style=for-the-badge&logo=git&color=F05032" alt="Last Commit" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/purecore-codes/1ntruder.svg?style=for-the-badge&color=6E7681" alt="License" />
  </a>
  <a href="https://github.com/purecore-codes/1ntruder/pulls">
    <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge" alt="PRs Welcome" />
  </a>
  <a href="https://bun.sh">
    <img src="https://img.shields.io/badge/Bun-Compatible-f9f1e1?style=for-the-badge&logo=bun&logoColor=black" alt="Bun Compatible" />
  </a>
</p>

<p align="center">
  <a href="SECURITY_REPORT.md">
    <img src="https://img.shields.io/badge/Security-Audited-brightgreen.svg?style=for-the-badge&logo=checkmarx" alt="Security Audited" />
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Snyk-Vulnerability--Free-82075E?style=for-the-badge&logo=snyk" alt="Snyk" />
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Made%20with-TypeScript-007ACC?style=for-the-badge&logo=typescript" alt="TypeScript" />
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Pentest-Ready-red?style=for-the-badge&logo=target" alt="Pentest Ready" />
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/github/languages/top/purecore-codes/1ntruder?style=for-the-badge&color=blueviolet" alt="Top Language" />
  <img src="https://img.shields.io/github/repo-size/purecore-codes/1ntruder?style=for-the-badge&color=success" alt="Repo Size" />
  <img src="https://img.shields.io/badge/Maintenance-Active-green?style=for-the-badge" alt="Maintenance" />
</p>

<hr width="90%" size="1" color="#30363D" />

<table width="900px" border="0">
<tr>
<td align="left">

<h3 align="left">🚀 Quick Start</h3>

<p>Install and start scanning in seconds:</p>

<pre><code># Global install
npm install -g 1ntruder

# Run a basic security scan
1ntruder scan https://example.com

# Check for CVEs in dependencies
1ntruder cve monitor</code></pre>

<h3 align="left">🔥 Key Features</h3>

<ul>
  <li><b>🛡️ Automated Security Audit:</b> Header analysis (HSTS, CSP, XFO) and CORS verification.</li>
  <li><b>💣 Advanced Fuzzing Engine:</b> Intelligent payloads for SQLi, XSS, and Path Traversal.</li>
  <li><b>🔍 Tech Reconnaissance:</b> Identify 25+ technologies and server fingerprints.</li>
  <li><b>📊 CVE Database Integration:</b> Real-time monitoring of known vulnerabilities.</li>
  <li><b>⚡ High Performance:</b> Built on top of an optimized HTTP client with auto-retries.</li>
</ul>

<hr width="100%" size="1" color="#30363D" />

<h3 align="left">💻 CLI Commands</h3>

<pre><code># Deep scan with all checks
1ntruder scan https://target.com --depth=deep

# Recon tech stack
1ntruder recon https://target.com

# Fuzz sensitive paths (.env, .git, admin)
1ntruder fuzz https://target.com --sensitive</code></pre>

<h3 align="left">🛠️ Programmatic Integration</h3>

<pre><code>import { HttpScanner } from '1ntruder';

const scanner = new HttpScanner();
const result = await scanner.scan({
  url: 'https://example.com',
  depth: 'deep'
});

console.log(`Security Score: ${result.score}/100`);</code></pre>

<br />
<hr width="100%" size="1" color="#30363D" />

<div align="center">
  <p><b>Developed by PureCore Codes</b></p>
  <p><i>Simulate the attack before they do.</i></p>
  <p>
    <a href="https://github.com/purecore-codes/1ntruder">GitHub</a> • 
    <a href="https://www.npmjs.com/package/1ntruder">NPM</a> • 
    <a href="SECURITY_REPORT.md">Security</a>
  </p>
</div>

</td>
</tr>
</table>

<br />
</td>
</tr>
</table>

</div>
