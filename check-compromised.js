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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = process.cwd();
const argv = new Set(process.argv.slice(2));
const OUTPUT_JSON = argv.has("--json");
const SHOW_LIST = argv.has("--list");

function readJSONSafe(p) {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

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

function add(map, name, version) {
  if (!map.has(name)) map.set(name, new Set());
  map.get(name).add(String(version));
}

function collectFromPackageLock() {
  const hits = new Map();
  const lockPath = path.join(projectRoot, "package-lock.json");
  if (!fs.existsSync(lockPath)) return hits;

  const lock = readJSONSafe(lockPath);
  if (!lock) return hits;

  if (lock.packages && typeof lock.packages === "object") {
    for (const [key, meta] of Object.entries(lock.packages)) {
      if (!meta || !meta.version) continue;
      const name = key.replace(/^node_modules\//, "");
      add(hits, name, meta.version);
    }
  }

  function walkDeps(obj) {
    if (!obj || typeof obj !== "object") return;
    for (const [name, meta] of Object.entries(obj)) {
      if (!meta) continue;
      if (meta.version) add(hits, name, meta.version);
      if (meta.dependencies) walkDeps(meta.dependencies);
    }
  }
  if (lock.dependencies) walkDeps(lock.dependencies);

  return hits;
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

function compare(installedMap, knownBad) {
  const badIndex = new Map();
  for (const entry of knownBad.packages) {
    badIndex.set(entry.name, new Set(entry.badVersions.map(String)));
  }
  const findings = [];
  for (const [name, versions] of installedMap.entries()) {
    if (!badIndex.has(name)) continue;
    for (const v of versions) {
      if (badIndex.get(name).has(v)) {
        findings.push({ name, version: v });
      }
    }
  }
  return findings;
}

function uniqFindings(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const key = `${f.name}@${f.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function main() {
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
  const lock = collectFromPackageLock();

  const merged = new Map(lock);
  for (const [name, vers] of nm.entries()) {
    if (!merged.has(name)) merged.set(name, new Set());
    for (const v of vers) merged.get(name).add(v);
  }

  const findings = uniqFindings(compare(merged, knownBad));

  if (OUTPUT_JSON) {
    console.log(JSON.stringify({ findings }, null, 2));
  } else if (findings.length === 0) {
    console.log("✅ No compromised packages found.");
  } else {
    console.error("🚨 Compromised packages found:");
    for (const f of findings) console.error(`  ${f.name}@${f.version}`);
    process.exit(1);
  }
}

main();
