/**
 * Core functions for checking compromised packages
 * Extracted for testing purposes
 */

export function compare(installedMap, knownBad) {
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

export function uniqFindings(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const key = `${f.name}@${f.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function add(map, name, version) {
  if (!map.has(name)) map.set(name, new Set());
  map.get(name).add(String(version));
}

export function collectFromPackageLock(projectRoot) {
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

export function readJSONSafe(p) {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

import fs from "fs";
import path from "path";
