#!/usr/bin/env node

/**
 * ATOMIC TYPE MANAGER CLI
 * * Este script gerencia a sincronização de tipos entre o projeto local
 * e o cache global do usuário.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
// --- CONFIGURAÇÕES ---

// Permitir sobreposição via variáveis de ambiente para facilitar testes
const USER_HOME = process.env.ATOMIC_USER_HOME || os.homedir();
const GLOBAL_NAMESPACE = process.env.ATOMIC_GLOBAL_NAMESPACE || ".purecore/atomicbehaviortypes/shared";
const PROJECT_ROOT = process.env.ATOMIC_PROJECT_ROOT || process.cwd();

// Estas variáveis são exportadas para que os testes possam vê-las após a inicialização
function getConfig() {
  const userHome = process.env.ATOMIC_USER_HOME || os.homedir();
  const globalNamespace = process.env.ATOMIC_GLOBAL_NAMESPACE || ".purecore/atomicbehaviortypes/shared";
  const projectRoot = process.env.ATOMIC_PROJECT_ROOT || process.cwd();

  const srcDir = path.join(projectRoot, "src");
  const localTypesDir = path.join(srcDir, "types");

  return {
    GLOBAL_SHARED_PATH: path.join(userHome, globalNamespace, "shared"),
    SRC_DIR: srcDir,
    LOCAL_TYPES_DIR: localTypesDir,
    LOCAL_SHARED_LINK_DIR: path.join(localTypesDir, "shared"),
    INDEX_FILE: path.join(localTypesDir, "index.ts")
  };
}

// Padrão de arquivos de tipos para buscar (ex: user.type.ts ou *.at.ts)
// Vamos assumir que seus tipos terminam com .type.ts ou .interface.ts
const TYPE_FILE_SUFFIX = ".type.ts";

// --- UTILITÁRIOS ---

function log(msg, type = "info") {
  const colors = {
    info: "\x1b[36m%s\x1b[0m", // Cyan
    success: "\x1b[32m%s\x1b[0m", // Green
    warn: "\x1b[33m%s\x1b[0m", // Yellow
    error: "\x1b[31m%s\x1b[0m", // Red
  };
  console.log(colors[type] || colors.info, `[AtomicCLI] ${msg}`);
}

function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

// Varre pastas recursivamente
function findFiles(dir, suffix, fileList = []) {
  if (!fs.existsSync(dir)) return fileList;
  const files = fs.readdirSync(dir);

  files.forEach((file) => {
    const filePath = path.join(dir, file);
    const stat = fs.lstatSync(filePath);

    // Ignora symlinks para evitar ataques de linkagem e loops circulares
    if (stat.isSymbolicLink()) {
      log(`Ignorando link simbólico: ${file}`, "warn");
      return;
    }

    // Ignora node_modules
    if (filePath.includes("node_modules"))
      return;

    if (stat.isDirectory()) {
      findFiles(filePath, suffix, fileList);
    } else if (file.endsWith(suffix)) {
      fileList.push(filePath);
    }
  });
  return fileList;
}

// --- COMANDOS PRINCIPAIS ---

/**
 * 1. HARVEST (COLHEITA)
 * Varre o src, pega os tipos originais e atualiza a Global Store
 */
function harvestTypes() {
  const config = getConfig();
  log("Iniciando varredura de tipos locais...", "info");
  ensureDir(config.GLOBAL_SHARED_PATH);

  const files = findFiles(config.SRC_DIR, TYPE_FILE_SUFFIX);

  if (files.length === 0) {
    log("Nenhum arquivo de tipo encontrado para exportar.", "warn");
    return [];
  }

  const processedFiles = [];

  files.forEach((filePath) => {
    // Avoid harvesting from the types dir itself
    if (filePath.includes(config.LOCAL_TYPES_DIR)) return;

    const content = fs.readFileSync(filePath, "utf-8");
    const filename = path.basename(filePath);
    const globalPath = path.join(config.GLOBAL_SHARED_PATH, filename);

    // Opcional: Verificar se o conteúdo mudou antes de escrever (hash)
    // Aqui vamos apenas sobrescrever para garantir a versão mais recente
    fs.writeFileSync(globalPath, content);
    processedFiles.push(filename);
    log(`Sincronizado globalmente: ${filename}`, "success");
  });

  return processedFiles;
}

/**
 * 2. LINK (VINCULAÇÃO)
 * Cria symlinks no projeto local apontando para a Global Store
 * Baseado no que foi encontrado ou no que já existe na global.
 */
function linkTypes() {
  const config = getConfig();
  log("Gerando links simbólicos e index...", "info");

  // Limpa e recria a pasta local de links compartilhados
  if (fs.existsSync(config.LOCAL_SHARED_LINK_DIR)) {
    fs.rmSync(config.LOCAL_SHARED_LINK_DIR, { recursive: true, force: true });
  }
  ensureDir(config.LOCAL_SHARED_LINK_DIR);

  // Pega tudo que está na pasta Global
  // (Num cenário real, você filtraria apenas o que o projeto usa lendo os imports)
  if (!fs.existsSync(config.GLOBAL_SHARED_PATH)) return [];

  const globalFiles = fs
    .readdirSync(config.GLOBAL_SHARED_PATH)
    .filter((f) => f.endsWith(TYPE_FILE_SUFFIX));
  const exports = [];

  globalFiles.forEach((file) => {
    const sourcePath = path.join(config.GLOBAL_SHARED_PATH, file);
    const destPath = path.join(config.LOCAL_SHARED_LINK_DIR, file);

    try {
      // Cria o Link Simbólico
      // 'junction' é melhor para Windows, 'file' para Linux/Mac
      const linkType = os.platform() === "win32" ? "junction" : "file";

      // Nota: Para arquivos no Windows, fs.symlink requer perm de admin às vezes.
      // Copiar é mais seguro se não tiver perm, mas Symlink é o pedido.
      // Vamos tentar criar symlink.
      fs.symlinkSync(sourcePath, destPath, linkType);

      // Remove a extensão .ts para o import
      const importName = file.replace(".ts", "");
      exports.push(`export * from './shared/${importName}';`);
    } catch (err) {
      log(`Erro ao linkar ${file}: ${err.message}`, "error");
    }
  });

  return exports;
}

/**
 * 3. GENERATE INDEX
 * Cria o arquivo central de exportação
 */
function generateIndex(exports) {
  const config = getConfig();
  const header = `/**
 * ARQUIVO GERADO AUTOMATICAMENTE PELO ATOMIC CLI
 * NÃO EDITE MANUALMENTE ESTE ARQUIVO.
 * * Tipos sincronizados de: ${config.GLOBAL_SHARED_PATH}
 */\n\n`;

  const content = header + exports.join("\n");
  ensureDir(path.dirname(config.INDEX_FILE));
  fs.writeFileSync(config.INDEX_FILE, content);
  log(`Arquivo de índice gerado em: ${config.INDEX_FILE}`, "success");
}

// --- EXECUÇÃO ---

function main() {
  try {
    log("=== ATOMIC TYPE MANAGER ===", "info");

    // 1. Pega tipos espalhados no projeto e joga pra global
    const harvested = harvestTypes();

    // 2. Cria estrutura local baseada na global (Symlinks)
    const exportLines = linkTypes();

    // 3. Gera o arquivo de entrada para o TS reconhecer
    generateIndex(exportLines);

    log("Sincronização concluída com sucesso!", "success");
    log('Agora você pode importar de "src/types"', "info");
  } catch (error) {
    log(`Falha crítica: ${error.message}`, "error");
    console.error(error);
    process.exit(1);
  }
}

// Export functions for testing purposes
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    log,
    ensureDir,
    findFiles,
    harvestTypes,
    linkTypes,
    generateIndex,
    main,
    // Configuration constants for testing
    getConfig,
    TYPE_FILE_SUFFIX
  };
}

// Only run main if this is the main module (not required by another module)
if (require.main === module) {
  main();
}
