#!/usr/bin/env node
/**
 * Supply chain quick check for compromised npm packages.
 * Scans node_modules and package-lock.json for installed versions.
 * Compares against a known-bad list of exact versions.
 *
 * Usage:
 *   node check-compromised.js
 *   node check-compromised.js --json
 *   node check-compromised.js --list   # print the known-bad list
 *
 * Optional:
 *   Add a file compromised.json at repo root
 *   Format:
 *   {
 *     "packages": [
 *       { "name": "@ctrl/tinycolor", "badVersions": ["4.1.1", "4.1.2"] },
 *       { "name": "angulartics2",     "badVersions": ["14.1.2"] }
 *     ]
 *   }
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { compare, uniqFindings, add, collectFromPackageLock, readJSONSafe } from "./lib/core.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = process.cwd();
const argv = new Set(process.argv.slice(2));
const OUTPUT_JSON = argv.has("--json");
const SHOW_LIST = argv.has("--list");
const VERBOSE = argv.has("--verbose");
const SHOW_HELP = argv.has("--help") || argv.has("-h");


function loadKnownBad() {
  // First try to find compromised.json in current working directory
  let jsonPath = path.join(projectRoot, "compromised.json");
  
  // If not found, try to load the bundled version from the package
  if (!fs.existsSync(jsonPath)) {
    const bundledPath = path.join(__dirname, "compromised.json");
    if (fs.existsSync(bundledPath)) {
      jsonPath = bundledPath;
    } else {
      console.error("ERROR: compromised.json not found in project root or bundled with package.");
      console.error("Please create a compromised.json file in your project root or reinstall the package.");
      process.exit(2);
    }
  }
  
  const data = readJSONSafe(jsonPath);
  if (!data || !Array.isArray(data.packages)) {
    console.error("ERROR: compromised.json is invalid.");
    process.exit(2);
  }
  return data;
}



function collectFromNodeModules() {
  const hits = new Map();
  const nmRoot = path.join(projectRoot, "node_modules");
  if (!fs.existsSync(nmRoot)) return hits;

  function processPkg(pkgDir) {
    const pkgJsonPath = path.join(pkgDir, "package.json");
    if (!fs.existsSync(pkgJsonPath)) return;
    const pkg = readJSONSafe(pkgJsonPath);
    if (!pkg || !pkg.name || !pkg.version) return;
    add(hits, pkg.name, pkg.version);
  }

  function walk(dir, depth = 0) {
    if (depth > 6) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (!ent.isDirectory() || ent.name.startsWith(".")) continue;

      if (ent.name.startsWith("@")) {
        const scopeDir = path.join(dir, ent.name);
        let scoped;
        try {
          scoped = fs.readdirSync(scopeDir, { withFileTypes: true });
        } catch {
          continue;
        }
        for (const s of scoped) {
          if (!s.isDirectory()) continue;
          const pkgDir = path.join(scopeDir, s.name);
          processPkg(pkgDir);
          const nested = path.join(pkgDir, "node_modules");
          if (fs.existsSync(nested)) walk(nested, depth + 1);
        }
        continue;
      }

      const pkgDir = path.join(dir, ent.name);
      processPkg(pkgDir);
      const nested = path.join(pkgDir, "node_modules");
      if (fs.existsSync(nested)) walk(nested, depth + 1);
    }
  }

  walk(nmRoot);
  return hits;
}


function showHelp() {
  console.log(`
Check Compromised NPM Packages v1.0.1

A security tool to scan your project for compromised npm packages by comparing
installed versions against a known list of malicious versions.

USAGE:
  check-compromised-npm-packages [OPTIONS]

OPTIONS:
  --help, -h          Show this help message
  --verbose           Show individual package status (not found)
  --json              Output results in JSON format
  --list              Show the list of known compromised packages

EXAMPLES:
  # Basic scan
  npx check-compromised-npm-packages

  # Verbose output showing each package checked
  npx check-compromised-npm-packages --verbose

  # JSON output for CI integration
  npx check-compromised-npm-packages --json

  # Show known compromised packages list
  npx check-compromised-npm-packages --list

DESCRIPTION:
  This tool scans your node_modules and package-lock.json for installed
  package versions and compares them against a known list of compromised
  versions. It's designed to complement npm audit by catching supply chain
  attacks that may not yet have CVEs.

  The tool looks for a compromised.json file in your project root, or falls
  back to the bundled version if not found.

EXIT CODES:
  0  No compromised packages found
  1  Compromised packages found
  2  Error (missing or invalid compromised.json)

For more information, visit: https://github.com/yourusername/check-compromised
`);
}

function main() {
  if (SHOW_HELP) {
    showHelp();
    process.exit(0);
  }

  const knownBad = loadKnownBad();

  if (SHOW_LIST) {
    if (OUTPUT_JSON) {
      console.log(JSON.stringify(knownBad, null, 2));
    } else {
      console.log("Known compromised packages and versions:");
      for (const p of knownBad.packages) {
        console.log(`  ${p.name}: [${p.badVersions.join(", ")}]`);
      }
    }
    process.exit(0);
  }

  const nm = collectFromNodeModules();
  const lock = collectFromPackageLock(projectRoot);

  const merged = new Map(lock);
  for (const [name, vers] of nm.entries()) {
    if (!merged.has(name)) merged.set(name, new Set());
    for (const v of vers) merged.get(name).add(v);
  }

  const findings = uniqFindings(compare(merged, knownBad));

  if (VERBOSE) {
    console.log("Scanning installed packages...");
    const badIndex = new Map();
    for (const entry of knownBad.packages) {
      badIndex.set(entry.name, new Set(entry.badVersions.map(String)));
    }
    
    let checkedCount = 0;
    let compromisedCount = 0;
    
    // Show all installed packages
    for (const [name, versions] of merged.entries()) {
      for (const v of versions) {
        checkedCount++;
        if (badIndex.has(name) && badIndex.get(name).has(v)) {
          console.log(`❌ ${name}@${v} - COMPROMISED`);
          compromisedCount++;
        } else if (badIndex.has(name)) {
          console.log(`✅ ${name}@${v} - OK (monitored)`);
        } else {
          console.log(`⚪ ${name}@${v} - not monitored`);
        }
      }
    }
    console.log(`\nChecked ${checkedCount} package versions against ${knownBad.packages.length} known compromised packages.`);
    console.log(`Found ${compromisedCount} compromised packages.`);
  }

  if (OUTPUT_JSON) {
    console.log(JSON.stringify({ findings }, null, 2));
    if (findings.length > 0) {
      process.exit(1);
    }
  } else if (findings.length === 0) {
    console.log("✅ No compromised packages found.");
  } else {
    console.error("🚨 Compromised packages found:");
    for (const f of findings) console.error(`  ${f.name}@${f.version}`);
    process.exit(1);
  }
}

main();
