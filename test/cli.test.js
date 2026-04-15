const fs = require("fs");
const path = require("path");
const os = require("os");

const cliPath = path.join(__dirname, '..', 'src', 'cli.js');

function setupTestEnvironment() {
    const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'atomic-test-cli-'));
    const userHome = path.join(testRoot, 'home');
    const projectRoot = path.join(testRoot, 'project');

    fs.mkdirSync(userHome, { recursive: true });
    fs.mkdirSync(path.join(projectRoot, 'src'), { recursive: true });

    process.env.ATOMIC_USER_HOME = userHome;
    process.env.ATOMIC_PROJECT_ROOT = projectRoot;
    process.env.ATOMIC_GLOBAL_NAMESPACE = ".test_atomic_cli";

    delete require.cache[require.resolve(cliPath)];
    const cli = require(cliPath);

    return { cli, testRoot, userHome, projectRoot };
}

describe("CLI Utility Functions Tests", () => {
    let env;

    beforeEach(() => {
        env = setupTestEnvironment();
    });

    afterEach(() => {
        fs.rmSync(env.testRoot, { recursive: true, force: true });
        delete process.env.ATOMIC_USER_HOME;
        delete process.env.ATOMIC_PROJECT_ROOT;
        delete process.env.ATOMIC_GLOBAL_NAMESPACE;
    });

    test("ensureDir should create directory if it doesn't exist", () => {
        const testDir = path.join(env.testRoot, "test_ensure_dir");
        env.cli.ensureDir(testDir);
        expect(fs.existsSync(testDir)).toBe(true);
    });

    test("findFiles should find all type files recursively", () => {
        const srcDir = path.join(env.projectRoot, "src");
        fs.writeFileSync(path.join(srcDir, "user.type.ts"), "export interface User {}");

        const nestedDir = path.join(srcDir, "nested");
        fs.mkdirSync(nestedDir);
        fs.writeFileSync(path.join(nestedDir, "order.type.ts"), "export interface Order {}");

        const files = env.cli.findFiles(srcDir, ".type.ts");

        expect(files.length).toBe(2);
        const fileNames = files.map(f => path.basename(f));
        expect(fileNames).toContain("user.type.ts");
        expect(fileNames).toContain("order.type.ts");
    });

    test("findFiles should ignore node_modules", () => {
        const srcDir = path.join(env.projectRoot, "src");
        const nodeModulesDir = path.join(srcDir, "node_modules");
        fs.mkdirSync(nodeModulesDir, { recursive: true });
        fs.writeFileSync(path.join(nodeModulesDir, "fake.type.ts"), "export interface Fake {}");

        const files = env.cli.findFiles(srcDir, ".type.ts");
        expect(files.length).toBe(0);
    });
});

describe("CLI Main Functions Integration Tests", () => {
    let env;

    beforeEach(() => {
        env = setupTestEnvironment();
        const srcDir = path.join(env.projectRoot, "src");
        fs.writeFileSync(path.join(srcDir, "user.type.ts"), "export interface User {}");
    });

    afterEach(() => {
        fs.rmSync(env.testRoot, { recursive: true, force: true });
        delete process.env.ATOMIC_USER_HOME;
        delete process.env.ATOMIC_PROJECT_ROOT;
        delete process.env.ATOMIC_GLOBAL_NAMESPACE;
    });

    test("harvestTypes should copy local type files to global directory", () => {
        const harvested = env.cli.harvestTypes();
        expect(harvested).toContain("user.type.ts");

        const globalSharedPath = path.join(env.userHome, ".test_atomic_cli", "shared");
        expect(fs.existsSync(path.join(globalSharedPath, "user.type.ts"))).toBe(true);
    });

    test("generateIndex should create index.ts with proper exports", () => {
        const exports = ["export * from './shared/user.type';"];
        env.cli.generateIndex(exports);

        const indexFile = path.join(env.projectRoot, "src", "types", "index.ts");
        expect(fs.existsSync(indexFile)).toBe(true);
        const content = fs.readFileSync(indexFile, "utf8");
        expect(content).toContain("export * from './shared/user.type';");
    });
});
