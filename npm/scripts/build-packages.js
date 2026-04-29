#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..");
const NPM_DIR = path.join(ROOT, "npm");
const DIST_DIR = path.join(NPM_DIR, "dist");
const TEMPLATE_DIR = path.join(NPM_DIR, "templates");
const CLI_DIR = path.join(ROOT, "cli");
const BIN_DIR = path.join(ROOT, "bin");

// Read version from single source of truth (D-02)
const VERSION = fs.readFileSync(path.join(CLI_DIR, "VERSION"), "utf-8").trim();

const PLATFORMS = [
  { key: "darwin-arm64",  os: "darwin",  cpu: "arm64", display: "macOS arm64 (Apple Silicon)" },
  { key: "darwin-x64",    os: "darwin",  cpu: "x64",   display: "macOS x64 (Intel)" },
  { key: "linux-x64",     os: "linux",   cpu: "x64",   display: "Linux x64" },
  { key: "linux-arm64",   os: "linux",   cpu: "arm64", display: "Linux arm64" },
  { key: "win32-x64",     os: "win32",   cpu: "x64",   display: "Windows x64" },
];

// Read templates
const pkgTemplate = fs.readFileSync(path.join(TEMPLATE_DIR, "platform-package.json.tmpl"), "utf-8");
const readmeTemplate = fs.readFileSync(path.join(TEMPLATE_DIR, "platform-README.md.tmpl"), "utf-8");

console.log(`Building npm packages for version ${VERSION}`);

// 1. Update wrapper package.json version
const wrapperPkgPath = path.join(NPM_DIR, "skillledger", "package.json");
const wrapperPkg = JSON.parse(fs.readFileSync(wrapperPkgPath, "utf-8"));
wrapperPkg.version = VERSION;
for (const p of PLATFORMS) {
  const depName = `@skillledger/cli-${p.key}`;
  if (wrapperPkg.optionalDependencies[depName] !== undefined) {
    wrapperPkg.optionalDependencies[depName] = VERSION;
  }
}
fs.writeFileSync(wrapperPkgPath, JSON.stringify(wrapperPkg, null, 2) + "\n");
console.log(`  Updated wrapper package.json to ${VERSION}`);

// 2. Generate platform packages (D-03)
for (const p of PLATFORMS) {
  const dir = path.join(DIST_DIR, `cli-${p.key}`);
  const binDir = path.join(dir, "bin");
  fs.mkdirSync(binDir, { recursive: true });

  // Generate package.json from template
  const pkgJson = pkgTemplate
    .replace(/\{PLATFORM\}/g, p.key)
    .replace(/\{VERSION\}/g, VERSION)
    .replace(/\{OS_FIELD\}/g, p.os)
    .replace(/\{CPU_FIELD\}/g, p.cpu);
  fs.writeFileSync(path.join(dir, "package.json"), pkgJson);

  // Generate README from template
  const readme = readmeTemplate
    .replace(/\{PLATFORM\}/g, p.key)
    .replace(/\{PLATFORM_DISPLAY\}/g, p.display)
    .replace(/\{OS_FIELD\}/g, p.os)
    .replace(/\{CPU_FIELD\}/g, p.cpu);
  fs.writeFileSync(path.join(dir, "README.md"), readme);

  // Copy binary if it exists in bin/ (from make build-all)
  const goArch = p.cpu === "x64" ? "amd64" : p.cpu;
  const goPlatform = p.os === "win32" ? "windows" : p.os;
  const ext = p.os === "win32" ? ".exe" : "";
  const srcBinName = `skillledger-${goPlatform}-${goArch}${ext}`;
  const destBinName = `skillledger${ext}`;
  const srcBinPath = path.join(BIN_DIR, srcBinName);

  if (fs.existsSync(srcBinPath)) {
    fs.copyFileSync(srcBinPath, path.join(binDir, destBinName));
    fs.chmodSync(path.join(binDir, destBinName), 0o755);
    console.log(`  ${p.key}: binary copied from ${srcBinName}`);
  } else {
    console.log(`  ${p.key}: binary not found at ${srcBinPath} (will be added by CI)`);
  }
}

console.log(`\nGenerated ${PLATFORMS.length} platform packages in ${DIST_DIR}`);
console.log("Done.");
