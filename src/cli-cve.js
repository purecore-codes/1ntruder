#!/usr/bin/env node

/**
 * 1ntruder CVE CLI - Vulnerability Monitoring and Dependency Scanning
 * CLI para busca de CVEs, monitoramento e scan de dependências
 */

const path = require('path');
const fs = require('fs');

// Cores para terminal
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bold: '\x1b[1m'
};

const logo = `
${colors.cyan}${colors.bold}
 ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗     ███████╗██████╗
 ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     ██╔════╝██╔══██╗
 ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     █████╗  ██████╔╝
 ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     ██╔══╝  ██╔══██╗
 ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗███████╗██║  ██║
 ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
${colors.reset}
${colors.white}CVE Monitor & Dependency Scanner${colors.reset}
${colors.yellow}v0.1.0 | ${colors.magenta}PureCore Codes${colors.reset}
`;

function log(msg, type = 'info') {
  const colorMap = {
    info: colors.blue,
    success: colors.green,
    warn: colors.yellow,
    error: colors.red,
    security: colors.magenta
  };
  console.log(`${colorMap[type] || colors.white}[1ntruder CVE]${colors.reset} ${msg}`);
}

function showBanner() {
  console.log(logo);
  log('CVE Monitor initialized successfully!', 'success');
  log('Available commands:', 'info');
  console.log(`  ${colors.cyan}1ntruder cve search <keyword>${colors.reset}     - Search CVEs by keyword`);
  console.log(`  ${colors.cyan}1ntruder cve recent [days]${colors.reset}        - Show recent CVEs`);
  console.log(`  ${colors.cyan}1ntruder cve critical${colors.reset}             - Show critical CVEs`);
  console.log(`  ${colors.cyan}1ntruder cve high${colors.reset}                 - Show high severity CVEs`);
  console.log(`  ${colors.cyan}1ntruder cve id <CVE-ID>${colors.reset}          - Get specific CVE`);
  console.log(`  ${colors.cyan}1ntruder cve product <name>${colors.reset}       - Search by product`);
  console.log(`  ${colors.cyan}1ntruder deps [options]${colors.reset}           - Scan dependencies`);
  console.log(`  ${colors.cyan}1ntruder cve monitor${colors.reset}              - Start continuous monitoring`);
  console.log(`  ${colors.cyan}1ntruder cve report [days]${colors.reset}        - Generate report`);
  console.log('');
}

function showHelp() {
  console.log(logo);
  console.log(`${colors.bold}USAGE:${colors.reset}`);
  console.log(`  1ntruder cve <command> [options]`);
  console.log(`  1ntruder deps [options]`);
  console.log('');
  console.log(`${colors.bold}CVE COMMANDS:${colors.reset}`);
  console.log(`  search <keyword>     Search CVEs by keyword, vendor or product`);
  console.log(`  recent [days]        Show CVEs from last N days (default: 7)`);
  console.log(`  critical             Show critical severity CVEs (CVSS >= 9.0)`);
  console.log(`  high                 Show high severity CVEs (CVSS >= 7.0)`);
  console.log(`  id <CVE-ID>          Get details for specific CVE (e.g., CVE-2024-1234)`);
  console.log(`  product <name>       Search CVEs for specific product`);
  console.log(`  monitor              Start continuous monitoring mode`);
  console.log(`  report [days]        Generate vulnerability report`);
  console.log('');
  console.log(`${colors.bold}DEPS COMMAND:${colors.reset}`);
  console.log(`  deps                 Scan project dependencies for vulnerabilities`);
  console.log('');
  console.log(`${colors.bold}OPTIONS:${colors.reset}`);
  console.log(`  --limit <n>          Limit results (default: 20, max: 2000)`);
  console.log(`  --format <fmt>       Output format: table, json, markdown (default: table)`);
  console.log(`  --output <file>      Save output to file`);
  console.log(`  --severity <level>   Filter by severity: critical, high, medium, low`);
  console.log(`  --vendor <name>      Filter by vendor name`);
  console.log(`  --product <name>     Filter by product name`);
  console.log(`  --include-dev        Include devDependencies in deps scan`);
  console.log(`  --min-cvss <score>   Minimum CVSS score filter`);
  console.log('');
  console.log(`${colors.bold}EXAMPLES:${colors.reset}`);
  console.log(`  1ntruder cve search apache --limit 20`);
  console.log(`  1ntruder cve critical --format markdown --output report.md`);
  console.log(`  1ntruder cve id CVE-2024-1234`);
  console.log(`  1ntruder cve recent 14 --format json`);
  console.log(`  1ntruder deps --include-dev --format markdown --output deps-report.md`);
  console.log(`  1ntruder cve monitor`);
  console.log('');
  console.log(`${colors.yellow}⚠️  Note: Uses NVD NIST API. Rate limited to 10 requests/minute without API key.${colors.reset}`);
}

function parseArgs(args) {
  const parsed = {
    command: null,
    subcommand: null,
    value: null,
    options: {}
  };

  let i = 0;
  
  // Skip 'cve' or 'deps' if present as first arg
  if (args[0] === 'cve' || args[0] === 'deps') {
    parsed.command = args[0];
    i = 1;
  }

  // Parse remaining args
  while (i < args.length) {
    const arg = args[i];
    
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const nextArg = args[i + 1];
      
      if (nextArg && !nextArg.startsWith('--')) {
        parsed.options[key] = nextArg;
        i += 2;
      } else {
        parsed.options[key] = true;
        i++;
      }
    } else if (!parsed.subcommand) {
      parsed.subcommand = arg;
      i++;
    } else if (!parsed.value) {
      parsed.value = arg;
      i++;
    } else {
      i++;
    }
  }

  return parsed;
}

function formatTable(data, columns) {
  if (!data || data.length === 0) return 'No data found.';

  const widths = columns.map(col => col.width || col.header.length);
  const rows = [columns.map(c => c.header), ...data.map(row => columns.map(c => {
    const val = row[c.key] !== undefined ? String(row[c.key]) : '';
    return val.length > (widths[columns.indexOf(c)] || 20) 
      ? val.substring(0, widths[columns.indexOf(c)] - 3) + '...' 
      : val;
  }))];

  const separator = '+' + columns.map((c, i) => '-'.repeat(widths[i] + 2)).join('+') + '+';
  const headerRow = '|' + columns.map((c, i) => ' ' + c.header.padEnd(widths[i]) + ' ').join('|') + '|';

  const dataRows = rows.slice(1).map(row => 
    '|' + row.map((cell, i) => ' ' + String(cell).padEnd(widths[i]) + ' ').join('|') + '|'
  );

  return [separator, headerRow, separator, ...dataRows, separator].join('\n');
}

async function runSearch(keyword, options) {
  console.log(`${colors.cyan}🔍 Searching CVEs for: ${keyword}${colors.reset}`);
  
  try {
    // Dynamic import do módulo TypeScript compilado ou usar axios diretamente
    const axios = require('axios');
    
    const params = { searchTerm: keyword };
    if (options.limit) params.resultsPerPage = Math.min(parseInt(options.limit), 2000);
    if (options.severity) params.severity = options.severity.toUpperCase();
    if (options.vendor) params.virtualMatchString = options.vendor;
    if (options.product) params.virtualMatchString = `${options.vendor || ''}:${options.product}`;

    const response = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      params,
      headers: { 'User-Agent': '1ntruder-cve-cli/1.0' },
      timeout: 30000
    });

    const vulns = response.data.vulnerabilities || [];
    
    if (vulns.length === 0) {
      log('No CVEs found matching your criteria.', 'warn');
      return;
    }

    const format = options.format || 'table';
    const output = formatOutput(vulns, format, options);

    if (options.output) {
      fs.writeFileSync(options.output, output, 'utf-8');
      log(`Results saved to ${options.output}`, 'success');
    } else {
      console.log(output);
    }

    log(`Found ${vulns.length} CVE(s)`, 'success');
  } catch (error) {
    log(`Error searching CVEs: ${error.message}`, 'error');
  }
}

async function runRecent(days = 7, options) {
  console.log(`${colors.cyan}📅 Fetching CVEs from last ${days} days...${colors.reset}`);
  
  try {
    const axios = require('axios');
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const response = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      params: {
        pubStartDate: startDate.toISOString(),
        pubEndDate: endDate.toISOString(),
        resultsPerPage: options.limit ? Math.min(parseInt(options.limit), 2000) : 20
      },
      headers: { 'User-Agent': '1ntruder-cve-cli/1.0' },
      timeout: 30000
    });

    const vulns = response.data.vulnerabilities || [];
    
    if (vulns.length === 0) {
      log('No recent CVEs found.', 'warn');
      return;
    }

    const format = options.format || 'table';
    const output = formatOutput(vulns, format, options);

    if (options.output) {
      fs.writeFileSync(options.output, output, 'utf-8');
      log(`Results saved to ${options.output}`, 'success');
    } else {
      console.log(output);
    }

    log(`Found ${vulns.length} recent CVE(s)`, 'success');
  } catch (error) {
    log(`Error fetching recent CVEs: ${error.message}`, 'error');
  }
}

async function runCritical(options) {
  console.log(`${colors.red}🔴 Fetching CRITICAL CVEs (CVSS >= 9.0)...${colors.reset}`);
  options.severity = 'critical';
  await runSearch('', options);
}

async function runHigh(options) {
  console.log(`${colors.yellow}🟠 Fetching HIGH CVEs (CVSS >= 7.0)...${colors.reset}`);
  options.severity = 'high';
  await runSearch('', options);
}

async function runCveId(cveId, options) {
  console.log(`${colors.cyan}🔍 Fetching CVE: ${cveId}${colors.reset}`);
  
  try {
    const axios = require('axios');
    
    const response = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      params: { cveId },
      headers: { 'User-Agent': '1ntruder-cve-cli/1.0' },
      timeout: 30000
    });

    const vulns = response.data.vulnerabilities || [];
    
    if (vulns.length === 0) {
      log(`CVE ${cveId} not found.`, 'warn');
      return;
    }

    const format = options.format || 'table';
    const output = formatOutput(vulns, format, options);

    if (options.output) {
      fs.writeFileSync(options.output, output, 'utf-8');
      log(`Results saved to ${options.output}`, 'success');
    } else {
      console.log(output);
    }
  } catch (error) {
    log(`Error fetching CVE: ${error.message}`, 'error');
  }
}

async function runDeps(options) {
  console.log(`${colors.cyan}📦 Scanning project dependencies...${colors.reset}`);
  
  try {
    const projectPath = process.cwd();
    const packageJsonPath = path.join(projectPath, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
      log('package.json not found in current directory', 'error');
      return;
    }

    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    const deps = {
      ...(pkg.dependencies || {}),
      ...(options.includeDev ? (pkg.devDependencies || {}) : {})
    };

    const depNames = Object.keys(deps);
    log(`Found ${depNames.length} dependencies to check`, 'info');

    const axios = require('axios');
    const vulnerableDeps = [];

    for (const depName of depNames) {
      try {
        console.log(`  🔍 Checking ${depName}...`);
        
        const response = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
          params: { searchTerm: depName, resultsPerPage: 5 },
          headers: { 'User-Agent': '1ntruder-cve-cli/1.0' },
          timeout: 10000
        });

        const vulns = response.data.vulnerabilities || [];
        
        if (vulns.length > 0) {
          vulnerableDeps.push({
            name: depName,
            version: deps[depName],
            vulnerabilities: vulns.map(v => ({
              id: v.cve?.id,
              severity: getSeverity(v.cve),
              cvss: getCvssScore(v.cve),
              description: getDescription(v.cve)
            }))
          });
        }

        // Rate limiting
        await new Promise(resolve => setTimeout(resolve, 6000));
      } catch (error) {
        console.warn(`  ⚠️ Error checking ${depName}: ${error.message}`);
      }
    }

    // Generate report
    const format = options.format || 'table';
    let output = '';

    if (format === 'json') {
      output = JSON.stringify({
        scannedAt: new Date().toISOString(),
        totalDependencies: depNames.length,
        vulnerableDependencies: vulnerableDeps
      }, null, 2);
    } else {
      output = generateDepsReport(vulnerableDeps, depNames.length, format === 'markdown');
    }

    if (options.output) {
      fs.writeFileSync(options.output, output, 'utf-8');
      log(`Report saved to ${options.output}`, 'success');
    } else {
      console.log(output);
    }

    if (vulnerableDeps.length === 0) {
      log('✅ No known vulnerabilities found in dependencies!', 'success');
    } else {
      log(`⚠️ Found ${vulnerableDeps.length} dependency(ies) with vulnerabilities`, 'warn');
    }
  } catch (error) {
    log(`Error scanning dependencies: ${error.message}`, 'error');
  }
}

function getSeverity(cve) {
  const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
  const score = metrics?.cvssData?.baseScore;
  if (!score) return 'UNKNOWN';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

function getCvssScore(cve) {
  const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
  return metrics?.cvssData?.baseScore;
}

function getDescription(cve) {
  const descriptions = cve.descriptions || [];
  const desc = descriptions.find(d => d.lang === 'en') || descriptions[0];
  return desc?.value || 'No description available';
}

function formatOutput(vulns, format, options) {
  if (format === 'json') {
    return JSON.stringify(vulns.map(v => transformCve(v.cve)), null, 2);
  }

  if (format === 'markdown') {
    return formatMarkdown(vulns);
  }

  // Default: table format
  const columns = [
    { header: 'CVE ID', key: 'id', width: 18 },
    { header: 'Severity', key: 'severity', width: 10 },
    { header: 'CVSS', key: 'cvss', width: 6 },
    { header: 'Description', key: 'description', width: 60 }
  ];

  const data = vulns.map(v => ({
    id: v.cve?.id || 'UNKNOWN',
    severity: getSeverity(v.cve),
    cvss: getCvssScore(v.cve) || 'N/A',
    description: getDescription(v.cve)
  }));

  return formatTable(data, columns);
}

function formatMarkdown(vulns) {
  const lines = ['# 🔒 CVE Search Results', '', `**Total:** ${vulns.length} CVE(s)`, ''];
  
  vulns.forEach((v, i) => {
    const cve = v.cve || {};
    const severity = getSeverity(cve);
    const cvss = getCvssScore(cve);
    const desc = getDescription(cve);
    
    lines.push(`## ${i + 1}. ${cve.id || 'UNKNOWN'}`);
    lines.push('');
    lines.push(`**Severity:** ${severity} | **CVSS:** ${cvss || 'N/A'}`);
    lines.push('');
    lines.push(desc);
    lines.push('');
    lines.push('---');
    lines.push('');
  });

  return lines.join('\n');
}

function transformCve(cve) {
  return {
    id: cve.id,
    severity: getSeverity(cve),
    cvss: getCvssScore(cve),
    description: getDescription(cve),
    published: cve.published,
    references: cve.references?.map(r => r.url) || []
  };
}

function generateDepsReport(vulnerableDeps, totalDeps, isMarkdown = false) {
  const lines = [];
  
  if (isMarkdown) {
    lines.push('# 📦 Dependency Vulnerability Report');
    lines.push('');
    lines.push(`**Total Dependencies:** ${totalDeps}`);
    lines.push(`**Vulnerable:** ${vulnerableDeps.length}`);
    lines.push('');
    
    if (vulnerableDeps.length === 0) {
      lines.push('## ✅ Result');
      lines.push('');
      lines.push('No known vulnerabilities found!');
    } else {
      lines.push('## ⚠️ Vulnerable Dependencies');
      lines.push('');
      
      vulnerableDeps.forEach(dep => {
        lines.push(`### ${dep.name}@${dep.version}`);
        lines.push('');
        lines.push('| CVE | Severity | CVSS | Description |');
        lines.push('|-----|----------|------|-------------|');
        
        dep.vulnerabilities.forEach(vuln => {
          lines.push(`| ${vuln.id} | ${vuln.severity} | ${vuln.cvss || 'N/A'} | ${vuln.description.substring(0, 50)}... |`);
        });
        lines.push('');
      });
    }
  } else {
    lines.push('='.repeat(80));
    lines.push('📦 DEPENDENCY VULNERABILITY REPORT');
    lines.push('='.repeat(80));
    lines.push(`Total Dependencies: ${totalDeps}`);
    lines.push(`Vulnerable: ${vulnerableDeps.length}`);
    lines.push('');
    
    if (vulnerableDeps.length === 0) {
      lines.push('✅ No known vulnerabilities found!');
    } else {
      vulnerableDeps.forEach(dep => {
        lines.push(`${dep.name}@${dep.version}`);
        dep.vulnerabilities.forEach(vuln => {
          lines.push(`  - ${vuln.id} [${vuln.severity}] CVSS: ${vuln.cvss || 'N/A'}`);
          lines.push(`    ${vuln.description.substring(0, 80)}...`);
        });
        lines.push('');
      });
    }
    
    lines.push('='.repeat(80));
  }

  return lines.join('\n');
}

async function runMonitor() {
  log('Starting continuous monitoring mode...', 'info');
  log('Press Ctrl+C to stop', 'warn');
  
  const monitoredProducts = ['apache', 'nginx', 'nodejs', 'express', 'react', 'axios'];
  
  async function checkOnce() {
    const axios = require('axios');
    
    for (const product of monitoredProducts) {
      try {
        const response = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
          params: { searchTerm: product, resultsPerPage: 5 },
          headers: { 'User-Agent': '1ntruder-cve-cli/1.0' },
          timeout: 10000
        });

        const vulns = response.data.vulnerabilities || [];
        
        if (vulns.length > 0) {
          const critical = vulns.filter(v => getSeverity(v.cve) === 'CRITICAL');
          if (critical.length > 0) {
            log(`🚨 ALERT: ${critical.length} critical CVE(s) for ${product}!`, 'error');
            critical.forEach(v => {
              console.log(`  ${colors.red}${v.cve.id}${colors.reset} - ${getDescription(v.cve).substring(0, 60)}...`);
            });
          }
        }

        await new Promise(resolve => setTimeout(resolve, 6000)); // Rate limit
      } catch (error) {
        console.warn(`Error checking ${product}: ${error.message}`);
      }
    }
  }

  // Initial check
  await checkOnce();
  
  // Then every hour
  setInterval(checkOnce, 3600000);
}

async function runReport(days = 7, options) {
  console.log(`${colors.cyan}📊 Generating report for last ${days} days...${colors.reset}`);
  await runRecent(days, { ...options, format: options.format || 'markdown' });
}

// Main execution
async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    showHelp();
    return;
  }

  if (args[0] === '--banner' || args[0] === '-b') {
    showBanner();
    return;
  }

  const parsed = parseArgs(args);
  
  // Handle 'cve' command
  if (parsed.command === 'cve') {
    switch (parsed.subcommand) {
      case 'search':
        if (!parsed.value) {
          log('Please provide a search keyword', 'error');
          return;
        }
        await runSearch(parsed.value, parsed.options);
        break;
      
      case 'recent':
        await runRecent(parsed.value || 7, parsed.options);
        break;
      
      case 'critical':
        await runCritical(parsed.options);
        break;
      
      case 'high':
        await runHigh(parsed.options);
        break;
      
      case 'id':
        if (!parsed.value) {
          log('Please provide a CVE ID', 'error');
          return;
        }
        await runCveId(parsed.value, parsed.options);
        break;
      
      case 'product':
        if (!parsed.value) {
          log('Please provide a product name', 'error');
          return;
        }
        await runSearch(parsed.value, { ...parsed.options, product: parsed.value });
        break;
      
      case 'monitor':
        await runMonitor();
        break;
      
      case 'report':
        await runReport(parsed.value || 7, parsed.options);
        break;
      
      default:
        log('Unknown CVE command. Use --help for usage.', 'error');
    }
  } 
  // Handle 'deps' command
  else if (parsed.command === 'deps' || parsed.subcommand === 'deps') {
    await runDeps(parsed.options);
  }
  else {
    showBanner();
    log('No command specified. Use --help for usage information.', 'info');
  }
}

// Export functions for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    log,
    showBanner,
    showHelp,
    parseArgs,
    runSearch,
    runRecent,
    runCritical,
    runHigh,
    runCveId,
    runDeps,
    runMonitor,
    runReport,
    main
  };
}

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}
