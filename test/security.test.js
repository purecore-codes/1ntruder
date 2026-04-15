const fs = require("fs");
const path = require("path");
const os = require("os");

// Load the CLI module
// We will use environment variables to configure it for testing
const cliPath = path.join(__dirname, '..', 'src', 'cli.js');

function setupTestEnvironment() {
    const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'atomic-test-'));
    const userHome = path.join(testRoot, 'home');
    const projectRoot = path.join(testRoot, 'project');

    fs.mkdirSync(userHome, { recursive: true });
    fs.mkdirSync(path.join(projectRoot, 'src'), { recursive: true });

    process.env.ATOMIC_USER_HOME = userHome;
    process.env.ATOMIC_PROJECT_ROOT = projectRoot;
    process.env.ATOMIC_GLOBAL_NAMESPACE = ".test_atomic";

    // Clear require cache for the CLI module
    delete require.cache[require.resolve(cliPath)];
    const cli = require(cliPath);

    return { cli, testRoot, userHome, projectRoot };
}

describe("Security Vulnerability Tests", () => {
    let env;

    beforeEach(() => {
        env = setupTestEnvironment();
    });

    afterEach(() => {
        if (env && env.testRoot) {
            fs.rmSync(env.testRoot, { recursive: true, force: true });
        }
        delete process.env.ATOMIC_USER_HOME;
        delete process.env.ATOMIC_PROJECT_ROOT;
        delete process.env.ATOMIC_GLOBAL_NAMESPACE;
    });

    test("Symlink Attack - Should not follow symlinks to sensitive files during harvest", () => {
        const sensitiveFile = path.join(env.testRoot, "sensitive.txt");
        fs.writeFileSync(sensitiveFile, "SENSITIVE DATA");

        const symlinkPath = path.join(env.projectRoot, "src", "malicious.type.ts");

        try {
            fs.symlinkSync(sensitiveFile, symlinkPath);
        } catch (e) {
            console.warn("Skipping symlink test: symlinkSync failed");
            return;
        }

        // Run harvest
        env.cli.harvestTypes();

        // Verify if sensitive data was leaked to global store
        const globalSharedPath = path.join(env.userHome, ".test_atomic", "shared");
        const leakedFile = path.join(globalSharedPath, "malicious.type.ts");

        expect(fs.existsSync(leakedFile)).toBe(false);
    });

    test("Path Traversal - Filename should not allow escaping the global store", () => {
        // Path traversal in filename itself is tricky because OS usually prevents / in names
        // But we check that the file is created exactly where expected
        const maliciousName = "traversal..etc..passwd.type.ts";
        const maliciousFile = path.join(env.projectRoot, "src", maliciousName);
        fs.writeFileSync(maliciousFile, "export interface Traversal {}");

        env.cli.harvestTypes();

        const globalSharedPath = path.join(env.userHome, ".test_atomic", "shared");
        const expectedFile = path.join(globalSharedPath, maliciousName);

        expect(fs.existsSync(expectedFile)).toBe(true);
        // Ensure it didn't go anywhere else (like parent of global store)
        const parentGlobal = path.dirname(globalSharedPath);
        const filesInParent = fs.readdirSync(parentGlobal);
        expect(filesInParent).not.toContain("passwd.type.ts");
    });
});
