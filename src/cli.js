#!/usr/bin/env node

/**
 * ATOMIC TYPE MANAGER CLI
 * * Este script gerencia a sincronização de tipos entre o projeto local
 * e o cache global do usuário.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");

// --- CONFIGURAÇÕES ---

// Pasta Global (na home do usuário)
const USER_HOME = os.homedir();
const GLOBAL_NAMESPACE = ".purecore/atomicbehaviortypes/shared";
const GLOBAL_SHARED_PATH = path.join(USER_HOME, GLOBAL_NAMESPACE, "shared");

// Configurações do Projeto Local
const PROJECT_ROOT = process.cwd();
const SRC_DIR = path.join(PROJECT_ROOT, "src");
const LOCAL_TYPES_DIR = path.join(SRC_DIR, "types");
const LOCAL_SHARED_LINK_DIR = path.join(LOCAL_TYPES_DIR, "shared"); // Onde os symlinks ficarão
const INDEX_FILE = path.join(LOCAL_TYPES_DIR, "index.ts");

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
  // Segurança: Resolve o caminho absoluto e verifica se está dentro do SRC_DIR
  const absoluteDir = path.resolve(dir);
  if (!absoluteDir.startsWith(SRC_DIR)) {
    log(`Tentativa de acesso fora do diretório permitido: ${absoluteDir}`, "warn");
    return fileList;
  }

  const files = fs.readdirSync(dir);

  files.forEach((file) => {
    const filePath = path.join(dir, file);
    const stat = fs.lstatSync(filePath); // Usa lstatSync para detectar symlinks

    // Ignora node_modules, a pasta de tipos gerados e symlinks para evitar loops e escapes
    if (
      filePath.includes("node_modules") ||
      filePath.includes(LOCAL_TYPES_DIR) ||
      stat.isSymbolicLink()
    )
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
  log("Iniciando varredura de tipos locais...", "info");
  ensureDir(GLOBAL_SHARED_PATH);

  const files = findFiles(SRC_DIR, TYPE_FILE_SUFFIX);

  if (files.length === 0) {
    log("Nenhum arquivo de tipo encontrado para exportar.", "warn");
    return [];
  }

  const processedFiles = [];

  files.forEach((filePath) => {
    const filename = path.basename(filePath);

    // Segurança: Impede path traversal no nome do arquivo
    if (filename.includes("..") || filename.includes("/") || filename.includes("\\")) {
      log(`Nome de arquivo inválido detectado: ${filename}`, "error");
      return;
    }

    const content = fs.readFileSync(filePath, "utf-8");
    const globalPath = path.join(GLOBAL_SHARED_PATH, filename);

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
  log("Gerando links simbólicos e index...", "info");

  // Limpa e recria a pasta local de links compartilhados
  if (fs.existsSync(LOCAL_SHARED_LINK_DIR)) {
    fs.rmSync(LOCAL_SHARED_LINK_DIR, { recursive: true, force: true });
  }
  ensureDir(LOCAL_SHARED_LINK_DIR);

  // Pega tudo que está na pasta Global
  // (Num cenário real, você filtraria apenas o que o projeto usa lendo os imports)
  const globalFiles = fs
    .readdirSync(GLOBAL_SHARED_PATH)
    .filter((f) => f.endsWith(TYPE_FILE_SUFFIX));
  const exports = [];

  globalFiles.forEach((file) => {
    const sourcePath = path.join(GLOBAL_SHARED_PATH, file);
    const destPath = path.join(LOCAL_SHARED_LINK_DIR, file);

    // Segurança: Verifica se o sourcePath está realmente dentro de GLOBAL_SHARED_PATH
    const absoluteSource = path.resolve(sourcePath);
    if (!absoluteSource.startsWith(GLOBAL_SHARED_PATH)) {
      log(`Tentativa de linkar arquivo fora do diretório global: ${absoluteSource}`, "error");
      return;
    }

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
  const header = `/**
 * ARQUIVO GERADO AUTOMATICAMENTE PELO ATOMIC CLI
 * NÃO EDITE MANUALMENTE ESTE ARQUIVO.
 * * Tipos sincronizados de: ${GLOBAL_SHARED_PATH}
 */\n\n`;

  const content = header + exports.join("\n");
  fs.writeFileSync(INDEX_FILE, content);
  log(`Arquivo de índice gerado em: ${INDEX_FILE}`, "success");
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
    GLOBAL_SHARED_PATH,
    LOCAL_TYPES_DIR,
    LOCAL_SHARED_LINK_DIR,
    INDEX_FILE,
    TYPE_FILE_SUFFIX,
    PROJECT_ROOT,
    SRC_DIR
  };
}

// Only run main if this is the main module (not required by another module)
if (require.main === module) {
  main();
}
