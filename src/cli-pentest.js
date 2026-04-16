#!/usr/bin/env node

/**
 * 1ntruder CLI - Advanced HTTP Security Scanner
 * Executado automaticamente durante o build para verificar segurança
 */

const axios = require('axios');
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
${colors.white}Advanced HTTP Security Scanner & Pentesting Toolkit${colors.reset}
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
  console.log(`${colorMap[type] || colors.white}[1ntruder]${colors.reset} ${msg}`);
}

function showBanner() {
  console.log(logo);
  log('Security toolkit initialized successfully!', 'success');
  log('Available commands:', 'info');
  console.log(`  ${colors.cyan}npm run scan <url>${colors.reset}        - Run security scan on target`);
  console.log(`  ${colors.cyan}npm run fuzz <url>${colors.reset}        - Perform basic fuzzing tests`);
  console.log(`  ${colors.cyan}npm run recon <url>${colors.reset}       - Technology reconnaissance`);
  console.log(`  ${colors.cyan}npx 1ntruder --help${colors.reset}       - Show all options`);
  console.log('');
}

async function securityCheck() {
  log('Running pre-build security check...', 'security');
  
  try {
    // Verificar versão do axios
    const packageJson = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'));
    const axiosVersion = packageJson.dependencies?.axios || packageJson.devDependencies?.axios;
    
    if (axiosVersion) {
      log(`Axios version: ${axiosVersion}`, 'info');
      
      // Versões seguras conhecidas
      const safeVersions = ['^1.15.0', '>=1.15.0', 'latest'];
      const isSafe = safeVersions.some(v => axiosVersion.includes(v));
      
      if (!isSafe && !axiosVersion.includes('1.15')) {
        log('WARNING: Axios version may have known vulnerabilities!', 'warn');
        log('Consider updating to axios@^1.15.0', 'warn');
      } else {
        log('Axios version is secure ✓', 'success');
      }
    }
    
    // Verificar se arquivos de pentest existem
    const requiredFiles = [
      'src/pentest/http-scanner.ts',
      'src/pentest/header-analyzer.ts',
      'src/pentest/fuzzer.ts',
      'src/pentest/recon.ts'
    ];
    
    let missingFiles = [];
    requiredFiles.forEach(file => {
      if (!fs.existsSync(path.join(process.cwd(), file))) {
        missingFiles.push(file);
      }
    });
    
    if (missingFiles.length > 0) {
      log('Missing pentest modules:', 'warn');
      missingFiles.forEach(f => console.log(`  - ${f}`));
    } else {
      log('All pentest modules present ✓', 'success');
    }
    
    log('Security check completed!', 'success');
    return true;
  } catch (error) {
    log(`Security check failed: ${error.message}`, 'error');
    return false;
  }
}

function showWelcome() {
  console.log(logo);
  log('Thank you for installing 1ntruder!', 'success');
  log('Quick start guide:', 'info');
  console.log('');
  console.log(`  ${colors.bold}1. Run a security scan:${colors.reset}`);
  console.log(`     ${colors.cyan}npx 1ntruder scan https://example.com${colors.reset}`);
  console.log('');
  console.log(`  ${colors.bold}2. Test for vulnerabilities:${colors.reset}`);
  console.log(`     ${colors.cyan}npx 1ntruder fuzz https://target.com${colors.reset}`);
  console.log('');
  console.log(`  ${colors.bold}3. Reconnaissance:${colors.reset}`);
  console.log(`     ${colors.cyan}npx 1ntruder recon https://site.com${colors.reset}`);
  console.log('');
  log('Stay safe and hack ethically! 🛡️', 'security');
}

function showHelp() {
  console.log(logo);
  console.log(`${colors.bold}USAGE:${colors.reset}`);
  console.log(`  npx 1ntruder <command> [options]`);
  console.log('');
  console.log(`${colors.bold}COMMANDS:${colors.reset}`);
  console.log(`  scan <url>     Full security scan with header analysis`);
  console.log(`  fuzz <url>     Basic fuzzing tests (SQLi, XSS, Path Traversal)`);
  console.log(`  recon <url>    Technology detection and information gathering`);
  console.log(`  headers <url>  Detailed header security analysis`);
  console.log(`  help           Show this help message`);
  console.log('');
  console.log(`${colors.bold}NPM SCRIPTS:${colors.reset}`);
  console.log(`  npm run scan   - Quick scan (requires URL in .env or args)`);
  console.log(`  npm run fuzz   - Quick fuzz test`);
  console.log(`  npm run recon  - Quick recon`);
  console.log(`  npm run build  - Build project with security checks`);
  console.log('');
  console.log(`${colors.bold}EXAMPLES:${colors.reset}`);
  console.log(`  npx 1ntruder scan https://example.com --depth=deep`);
  console.log(`  npx 1ntruder fuzz https://target.com --payloads=custom`);
  console.log(`  npx 1ntruder recon https://site.com --output=json`);
  console.log('');
  console.log(`${colors.yellow}⚠️  DISCLAIMER: Use only on systems you have permission to test.${colors.reset}`);
}

// Main execution
async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  
  switch (command) {
    case '--banner':
    case '-b':
      showBanner();
      break;
      
    case '--security-check':
    case '-s':
      await securityCheck();
      break;
      
    case '--welcome':
    case '-w':
      showWelcome();
      break;
      
    case '--help':
    case '-h':
    case 'help':
      showHelp();
      break;
      
    default:
      showBanner();
      log('No command specified. Use --help for usage information.', 'info');
  }
}

// Export functions for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    log,
    showBanner,
    securityCheck,
    showWelcome,
    showHelp,
    main
  };
}

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}
