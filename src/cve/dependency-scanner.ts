/**
 * Dependency Scanner - Scanner de Vulnerabilidades em Dependências
 * Analisa package.json e busca CVEs nas dependências do projeto
 */

import { CveMonitor, CveItem } from './cve-monitor';
import { CveSummarizer } from './cve-summarizer';
import * as fs from 'fs';
import * as path from 'path';

export interface DependencyInfo {
  name: string;
  version: string;
  isDev: boolean;
}

export interface VulnerableDependency {
  dependency: DependencyInfo;
  vulnerabilities: CveItem[];
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface ScanOptions {
  projectPath?: string;
  includeDevDependencies?: boolean;
  severityFilter?: ('critical' | 'high' | 'medium' | 'low')[];
  minCvssScore?: number;
  maxResultsPerDependency?: number;
}

export interface ScanResult {
  scannedAt: string;
  projectPath: string;
  totalDependencies: number;
  vulnerableDependencies: VulnerableDependency[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

/**
 * Scanner de vulnerabilidades em dependências npm
 */
export class DependencyScanner {
  private monitor: CveMonitor;
  private summarizer: CveSummarizer;

  constructor(nvdApiKey?: string) {
    this.monitor = new CveMonitor(nvdApiKey);
    this.summarizer = new CveSummarizer();
  }

  /**
   * Lê e parseia o package.json do projeto
   */
  readPackageJson(projectPath: string): { dependencies: Record<string, string>, devDependencies: Record<string, string> } {
    const packageJsonPath = path.join(projectPath, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
      throw new Error(`package.json não encontrado em ${packageJsonPath}`);
    }

    const content = fs.readFileSync(packageJsonPath, 'utf-8');
    const packageJson = JSON.parse(content);

    return {
      dependencies: packageJson.dependencies || {},
      devDependencies: packageJson.devDependencies || {},
    };
  }

  /**
   * Extrai lista de dependências do package.json
   */
  extractDependencies(projectPath: string, includeDev: boolean = false): DependencyInfo[] {
    const pkg = this.readPackageJson(projectPath);
    const dependencies: DependencyInfo[] = [];

    // Adicionar dependências normais
    for (const [name, version] of Object.entries(pkg.dependencies)) {
      dependencies.push({
        name,
        version: this.cleanVersion(version),
        isDev: false,
      });
    }

    // Adicionar dev dependencies se solicitado
    if (includeDev) {
      for (const [name, version] of Object.entries(pkg.devDependencies)) {
        dependencies.push({
          name,
          version: this.cleanVersion(version),
          isDev: true,
        });
      }
    }

    return dependencies;
  }

  /**
   * Limpa versão para formato base (remove ^, ~, >=, etc)
   */
  private cleanVersion(version: string): string {
    return version.replace(/^[\^~>=<]+/, '').split(' ')[0];
  }

  /**
   * Realiza scan completo das dependências
   */
  async scan(options: ScanOptions = {}): Promise<ScanResult> {
    const projectPath = options.projectPath || process.cwd();
    const includeDev = options.includeDevDependencies ?? false;
    const severityFilter = options.severityFilter || ['critical', 'high', 'medium', 'low'];
    const maxResults = options.maxResultsPerDependency || 10;

    console.log(`📦 Iniciando scan de dependências em ${projectPath}...`);

    // Extrair dependências
    const dependencies = this.extractDependencies(projectPath, includeDev);
    console.log(`📋 Encontradas ${dependencies.length} dependência(s)`);

    const vulnerableDeps: VulnerableDependency[] = [];
    const summary = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };

    // Buscar vulnerabilidades para cada dependência
    for (const dep of dependencies) {
      try {
        console.log(`🔍 Verificando ${dep.name}@${dep.version}...`);
        
        // Buscar CVEs relacionados à dependência
        const cveResponse = await this.monitor.searchByKeyword(dep.name, {
          limit: maxResults,
        });

        // Filtrar por severidade
        const filteredCVEs = cveResponse.vulnerabilities.filter(cve => {
          if (!severityFilter.includes((cve.severity || 'low').toLowerCase() as any)) {
            return false;
          }
          if (options.minCvssScore && (!cve.cvssScore || cve.cvssScore < options.minCvssScore)) {
            return false;
          }
          return true;
        });

        if (filteredCVEs.length > 0) {
          // Determinar nível de risco
          const riskLevel = this.determineRiskLevel(filteredCVEs);
          
          vulnerableDeps.push({
            dependency: dep,
            vulnerabilities: filteredCVEs,
            riskLevel,
          });

          // Atualizar resumo
          filteredCVEs.forEach(cve => {
            summary.total++;
            switch (cve.severity) {
              case 'CRITICAL': summary.critical++; break;
              case 'HIGH': summary.high++; break;
              case 'MEDIUM': summary.medium++; break;
              case 'LOW': summary.low++; break;
            }
          });
        }
      } catch (error: any) {
        console.warn(`⚠️ Erro ao verificar ${dep.name}: ${error.message}`);
      }
    }

    return {
      scannedAt: new Date().toISOString(),
      projectPath,
      totalDependencies: dependencies.length,
      vulnerableDependencies: vulnerableDeps,
      summary,
    };
  }

  /**
   * Determina nível de risco baseado nas vulnerabilidades encontradas
   */
  private determineRiskLevel(vulnerabilities: CveItem[]): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    const hasCritical = vulnerabilities.some(v => v.severity === 'CRITICAL' || (v.cvssScore && v.cvssScore >= 9.0));
    const hasHigh = vulnerabilities.some(v => v.severity === 'HIGH' || (v.cvssScore && v.cvssScore >= 7.0));
    const hasMedium = vulnerabilities.some(v => v.severity === 'MEDIUM' || (v.cvssScore && v.cvssScore >= 4.0));

    if (hasCritical) return 'CRITICAL';
    if (hasHigh) return 'HIGH';
    if (hasMedium) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Gera relatório formatado do scan
   */
  generateReport(result: ScanResult, format: 'text' | 'json' | 'markdown' = 'text'): string {
    if (format === 'json') {
      return JSON.stringify(result, null, 2);
    }

    if (format === 'markdown') {
      return this.generateMarkdownReport(result);
    }

    return this.generateTextReport(result);
  }

  /**
   * Gera relatório em texto simples
   */
  private generateTextReport(result: ScanResult): string {
    const lines: string[] = [];

    lines.push('='.repeat(80));
    lines.push('📊 RELATÓRIO DE VULNERABILIDADES EM DEPENDÊNCIAS');
    lines.push('='.repeat(80));
    lines.push(`Projeto: ${result.projectPath}`);
    lines.push(`Scan realizado: ${new Date(result.scannedAt).toLocaleString('pt-BR')}`);
    lines.push(`Total de dependências: ${result.totalDependencies}`);
    lines.push('');
    lines.push('📈 RESUMO:');
    lines.push(`  🔴 Critical: ${result.summary.critical}`);
    lines.push(`  🟠 High: ${result.summary.high}`);
    lines.push(`  🟡 Medium: ${result.summary.medium}`);
    lines.push(`  🟢 Low: ${result.summary.low}`);
    lines.push(`  Total: ${result.summary.total}`);
    lines.push('');

    if (result.vulnerableDependencies.length === 0) {
      lines.push('✅ Nenhuma vulnerabilidade conhecida encontrada!');
    } else {
      lines.push(`⚠️ ${result.vulnerableDependencies.length} dependência(s) com vulnerabilidade(s):`);
      lines.push('');

      result.vulnerableDependencies.forEach((vulnDep, index) => {
        const riskEmoji = {
          'CRITICAL': '🔴',
          'HIGH': '🟠',
          'MEDIUM': '🟡',
          'LOW': '🟢',
        }[vulnDep.riskLevel];

        lines.push(`${index + 1}. ${riskEmoji} ${vulnDep.dependency.name}@${vulnDep.dependency.version}`);
        lines.push(`   Risco: ${vulnDep.riskLevel} | ${vulnDep.vulnerabilities.length} CVE(s)`);
        
        vulnDep.vulnerabilities.slice(0, 3).forEach(cve => {
          lines.push(`   - ${cve.id} [${cve.severity}] CVSS: ${cve.cvssScore || 'N/A'}`);
          lines.push(`     ${cve.description.substring(0, 100)}...`);
        });

        if (vulnDep.vulnerabilities.length > 3) {
          lines.push(`   ... e mais ${vulnDep.vulnerabilities.length - 3} CVE(s)`);
        }
        lines.push('');
      });
    }

    lines.push('='.repeat(80));
    lines.push('RECOMENDAÇÕES:');
    lines.push('  1. Atualize todas as dependências para versões mais recentes');
    lines.push('  2. Revise os CVEs críticos e altos prioritariamente');
    lines.push('  3. Considere usar npm audit ou yarn audit para verificações adicionais');
    lines.push('  4. Mantenha seu package.json sempre atualizado');
    lines.push('='.repeat(80));

    return lines.join('\n');
  }

  /**
   * Gera relatório em Markdown
   */
  private generateMarkdownReport(result: ScanResult): string {
    const lines: string[] = [];

    lines.push('# 📊 Relatório de Vulnerabilidades em Dependências');
    lines.push('');
    lines.push(`**Projeto:** ${result.projectPath}`);
    lines.push(`**Scan realizado:** ${new Date(result.scannedAt).toLocaleString('pt-BR')}`);
    lines.push('');

    lines.push('## 📈 Resumo');
    lines.push('');
    lines.push('| Severidade | Quantidade |');
    lines.push('|------------|------------|');
    lines.push(`| 🔴 Critical | ${result.summary.critical} |`);
    lines.push(`| 🟠 High | ${result.summary.high} |`);
    lines.push(`| 🟡 Medium | ${result.summary.medium} |`);
    lines.push(`| 🟢 Low | ${result.summary.low} |`);
    lines.push(`| **Total** | **${result.summary.total}** |`);
    lines.push('');

    if (result.vulnerableDependencies.length === 0) {
      lines.push('## ✅ Resultado');
      lines.push('');
      lines.push('Nenhuma vulnerabilidade conhecida encontrada!');
    } else {
      lines.push('## ⚠️ Dependências Vulneráveis');
      lines.push('');

      result.vulnerableDependencies.forEach((vulnDep, index) => {
        const riskEmoji = {
          'CRITICAL': '🔴',
          'HIGH': '🟠',
          'MEDIUM': '🟡',
          'LOW': '🟢',
        }[vulnDep.riskLevel];

        lines.push(`### ${index + 1}. ${vulnDep.dependency.name}@${vulnDep.dependency.version}`);
        lines.push('');
        lines.push(`**Risco:** ${vulnDep.riskLevel} | **CVEs:** ${vulnDep.vulnerabilities.length}`);
        lines.push('');
        lines.push('| CVE ID | Severidade | CVSS | Descrição |');
        lines.push('|--------|------------|------|-----------|');

        vulnDep.vulnerabilities.forEach(cve => {
          const desc = cve.description.substring(0, 60).replace(/\|/g, '-') + '...';
          lines.push(`| ${cve.id} | ${cve.severity} | ${cve.cvssScore || 'N/A'} | ${desc} |`);
        });

        lines.push('');
      });
    }

    lines.push('## 💡 Recomendações');
    lines.push('');
    lines.push('1. Atualize todas as dependências para versões mais recentes');
    lines.push('2. Revise os CVEs críticos e altos prioritariamente');
    lines.push('3. Considere usar `npm audit` ou `yarn audit` para verificações adicionais');
    lines.push('4. Mantenha seu `package.json` sempre atualizado');
    lines.push('');

    return lines.join('\n');
  }

  /**
   * Verifica uma dependência específica
   */
  async checkDependency(name: string, version?: string): Promise<CveItem[]> {
    const response = await this.monitor.searchByKeyword(name, { limit: 20 });
    
    if (version) {
      // Filtrar CVEs que podem afetar esta versão específica
      // (implementação simplificada - idealmente usaria semver)
      return response.vulnerabilities;
    }
    
    return response.vulnerabilities;
  }

  /**
   * Salva relatório em arquivo
   */
  saveReport(result: ScanResult, filePath: string, format: 'text' | 'json' | 'markdown' = 'text'): void {
    const content = this.generateReport(result, format);
    const dir = path.dirname(filePath);
    
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(filePath, content, 'utf-8');
    console.log(`✅ Relatório salvo em ${filePath}`);
  }
}

export default DependencyScanner;
