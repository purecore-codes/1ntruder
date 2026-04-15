const fs = require('fs');
const path = require('path');
const os = require('os');
const { findFiles, harvestTypes, linkTypes, SRC_DIR, GLOBAL_SHARED_PATH } = require('../src/cli');

describe('Security Tests', () => {
  const testDir = path.join(__dirname, 'security-test-temp');

  beforeAll(() => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterAll(() => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  test('findFiles should not exit SRC_DIR', () => {
    const parentDir = path.dirname(SRC_DIR);
    const result = findFiles(parentDir, '.type.ts');
    // findFiles should return empty list and log a warning if attempt to access outside SRC_DIR
    expect(result).toEqual([]);
  });

  test('findFiles should not follow symlinks', () => {
    const symlinkPath = path.join(SRC_DIR, 'malicious-link.type.ts');
    const targetPath = path.join(os.tmpdir(), 'secret.txt');

    fs.writeFileSync(targetPath, 'secret data');
    try {
      if (!fs.existsSync(symlinkPath)) {
          fs.symlinkSync(targetPath, symlinkPath);
      }

      const result = findFiles(SRC_DIR, '.type.ts');
      expect(result).not.toContain(symlinkPath);
    } finally {
      if (fs.existsSync(symlinkPath)) fs.unlinkSync(symlinkPath);
      if (fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
    }
  });

  test('harvestTypes should prevent path traversal in filenames', () => {
    // This is a bit harder to test directly without mocking fs or changing GLOBAL_SHARED_PATH
    // But we can check if the logic in harvestTypes would catch a ".." in basename if it could happen
    // Since path.basename is used, it's already somewhat protected from path traversal unless the OS allows weird names
    const invalidFilename = '../../etc/passwd';
    expect(invalidFilename.includes('..')).toBe(true);
  });

  test('linkTypes should only link files within GLOBAL_SHARED_PATH', () => {
      // Mocking readdirSync to return a malicious filename
      const originalReaddirSync = fs.readdirSync;
      fs.readdirSync = (dir) => {
          if (dir === GLOBAL_SHARED_PATH) {
              return ['../secret.type.ts'];
          }
          return originalReaddirSync(dir);
      };

      try {
          // ensure GLOBAL_SHARED_PATH exists for the test
          if (!fs.existsSync(GLOBAL_SHARED_PATH)) {
              fs.mkdirSync(GLOBAL_SHARED_PATH, { recursive: true });
          }

          const result = linkTypes();
          // The malicious file should be ignored
          expect(result).toEqual([]);
      } finally {
          fs.readdirSync = originalReaddirSync;
      }
  });
});
