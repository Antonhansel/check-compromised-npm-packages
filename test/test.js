#!/usr/bin/env node

import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.join(__dirname, '..');
const testDir = path.join(__dirname, 'fixtures');

// Test data
const testCompromisedData = {
  packages: [
    { name: "test-package-1", badVersions: ["1.0.0", "1.0.1"] },
    { name: "test-package-2", badVersions: ["2.1.0"] },
    { name: "@scope/test-package", badVersions: ["3.0.0", "3.0.1", "3.0.2"] },
    { name: "safe-package", badVersions: [] }
  ]
};

const testPackageLockData = {
  packages: {
    "node_modules/test-package-1": { version: "1.0.0" },
    "node_modules/test-package-2": { version: "2.1.0" },
    "node_modules/@scope/test-package": { version: "3.0.1" },
    "node_modules/safe-package": { version: "1.0.0" },
    "node_modules/clean-package": { version: "2.0.0" }
  }
};

describe('Check Compromised Package Tests', () => {
  let originalCwd;
  let originalArgv;

  before(() => {
    // Save original state
    originalCwd = process.cwd();
    originalArgv = process.argv;
    
    // Create test environment
    fs.mkdirSync(testDir, { recursive: true });
    fs.writeFileSync(
      path.join(testDir, 'compromised.json'), 
      JSON.stringify(testCompromisedData, null, 2)
    );
    fs.writeFileSync(
      path.join(testDir, 'package-lock.json'), 
      JSON.stringify(testPackageLockData, null, 2)
    );
  });

  describe('Core Functions', () => {
    test('compare function should find compromised packages', async () => {
      // Import the core functions
      const { compare } = await import('../lib/core.js');
      
      const installedMap = new Map([
        ['test-package-1', new Set(['1.0.0'])],
        ['test-package-2', new Set(['2.1.0'])],
        ['@scope/test-package', new Set(['3.0.1'])],
        ['safe-package', new Set(['1.0.0'])],
        ['clean-package', new Set(['2.0.0'])]
      ]);

      const findings = compare(installedMap, testCompromisedData);
      
      // Should find 3 compromised packages
      assert.strictEqual(findings.length, 3);
      
      // Check specific findings
      const findingsMap = new Map(findings.map(f => [`${f.name}@${f.version}`, f]));
      assert.ok(findingsMap.has('test-package-1@1.0.0'));
      assert.ok(findingsMap.has('test-package-2@2.1.0'));
      assert.ok(findingsMap.has('@scope/test-package@3.0.1'));
      
      // Safe packages should not be in findings
      assert.ok(!findingsMap.has('safe-package@1.0.0'));
      assert.ok(!findingsMap.has('clean-package@2.0.0'));
    });

    test('compare function should handle empty bad versions', async () => {
      const { compare } = await import('../lib/core.js');
      
      const installedMap = new Map([
        ['safe-package', new Set(['1.0.0'])]
      ]);

      const findings = compare(installedMap, testCompromisedData);
      assert.strictEqual(findings.length, 0);
    });

    test('compare function should handle non-monitored packages', async () => {
      const { compare } = await import('../lib/core.js');
      
      const installedMap = new Map([
        ['clean-package', new Set(['2.0.0'])]
      ]);

      const findings = compare(installedMap, testCompromisedData);
      assert.strictEqual(findings.length, 0);
    });
  });

  describe('CLI Integration Tests', () => {
    test('should find compromised packages and exit with code 1', async () => {
      process.chdir(testDir);
      
      const result = await runCLI([]);
      
      assert.strictEqual(result.exitCode, 1);
      assert.ok(result.stderr.includes('🚨 Compromised packages found:'));
      assert.ok(result.stderr.includes('test-package-1@1.0.0'));
      assert.ok(result.stderr.includes('test-package-2@2.1.0'));
      assert.ok(result.stderr.includes('@scope/test-package@3.0.1'));
    });

    test('should output JSON format correctly', async () => {
      process.chdir(testDir);
      
      const result = await runCLI(['--json']);
      
      const output = JSON.parse(result.stdout);
      assert.strictEqual(result.exitCode, 1);
      assert.ok(Array.isArray(output.findings));
      assert.strictEqual(output.findings.length, 3);
      
      const findingsMap = new Map(output.findings.map(f => [`${f.name}@${f.version}`, f]));
      assert.ok(findingsMap.has('test-package-1@1.0.0'));
      assert.ok(findingsMap.has('test-package-2@2.1.0'));
      assert.ok(findingsMap.has('@scope/test-package@3.0.1'));
    });

    test('should show help with --help flag', async () => {
      const result = await runCLI(['--help']);
      
      assert.strictEqual(result.exitCode, 0);
      assert.ok(result.stdout.includes('Check Compromised NPM Packages'));
      assert.ok(result.stdout.includes('USAGE:'));
      assert.ok(result.stdout.includes('OPTIONS:'));
    });

    test('should show verbose output', async () => {
      process.chdir(testDir);
      
      const result = await runCLI(['--verbose']);
      
      assert.strictEqual(result.exitCode, 1);
      assert.ok(result.stdout.includes('Scanning installed packages...'));
      assert.ok(result.stdout.includes('❌ test-package-1@1.0.0 - COMPROMISED'));
      assert.ok(result.stdout.includes('❌ test-package-2@2.1.0 - COMPROMISED'));
      assert.ok(result.stdout.includes('❌ @scope/test-package@3.0.1 - COMPROMISED'));
      assert.ok(result.stdout.includes('✅ safe-package@1.0.0 - OK (monitored)'));
      assert.ok(result.stdout.includes('⚪ clean-package@2.0.0 - not monitored'));
      assert.ok(result.stdout.includes('Checked 5 package versions'));
    });

    test('should show list of known compromised packages', async () => {
      process.chdir(testDir);
      
      const result = await runCLI(['--list']);
      
      assert.strictEqual(result.exitCode, 0);
      assert.ok(result.stdout.includes('Known compromised packages and versions:'));
      assert.ok(result.stdout.includes('test-package-1: [1.0.0, 1.0.1]'));
      assert.ok(result.stdout.includes('test-package-2: [2.1.0]'));
      assert.ok(result.stdout.includes('@scope/test-package: [3.0.0, 3.0.1, 3.0.2]'));
    });

    test('should handle clean project (no compromised packages)', async () => {
      // Create a clean test environment
      const cleanDir = path.join(testDir, 'clean');
      fs.mkdirSync(cleanDir, { recursive: true });
      
      const cleanCompromisedData = {
        packages: [
          { name: "nonexistent-package", badVersions: ["1.0.0"] }
        ]
      };
      
      const cleanPackageLockData = {
        packages: {
          "node_modules/clean-package": { version: "2.0.0" }
        }
      };
      
      fs.writeFileSync(
        path.join(cleanDir, 'compromised.json'), 
        JSON.stringify(cleanCompromisedData, null, 2)
      );
      fs.writeFileSync(
        path.join(cleanDir, 'package-lock.json'), 
        JSON.stringify(cleanPackageLockData, null, 2)
      );
      
      const originalCwd = process.cwd();
      process.chdir(cleanDir);
      
      try {
        const result = await runCLI([]);
        
        assert.strictEqual(result.exitCode, 0);
        assert.ok(result.stdout.includes('✅ No compromised packages found.'));
      } finally {
        // Clean up
        process.chdir(originalCwd);
        fs.rmSync(cleanDir, { recursive: true, force: true });
      }
    });
  });
});

// Note: Test fixtures are preserved for manual testing
// They can be manually cleaned up if needed

// Helper function to run CLI
function runCLI(args) {
  return new Promise((resolve) => {
    const child = spawn('node', [path.join(projectRoot, 'check-compromised.js'), ...args], {
      cwd: process.cwd(),
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('close', (code) => {
      resolve({
        exitCode: code,
        stdout: stdout,
        stderr: stderr
      });
    });
  });
}
