#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "..", "..");
const BIN_DIR = path.join(ROOT, "bin");
const DOWNLOAD_JS = path.join(ROOT, "npm", "skillledger", "lib", "download.js");

// Map Go binary names to Node.js platform keys (reverse of platform.js getDownloadURL)
const BINARY_TO_PLATFORM = {
  "skillledger-darwin-arm64":      "darwin-arm64",
  "skillledger-darwin-amd64":      "darwin-x64",
  "skillledger-linux-amd64":       "linux-x64",
  "skillledger-linux-arm64":       "linux-arm64",
  "skillledger-windows-amd64.exe": "win32-x64",
};

console.log("Computing binary checksums...");

const checksums = {};

for (const [binName, platformKey] of Object.entries(BINARY_TO_PLATFORM)) {
  const binPath = path.join(BIN_DIR, binName);
  if (!fs.existsSync(binPath)) {
    console.error("Missing binary: " + binPath);
    process.exit(1);
  }
  const hash = crypto.createHash("sha256").update(fs.readFileSync(binPath)).digest("hex");
  checksums[platformKey] = hash;
  console.log("  " + platformKey + ": " + hash);
}

// Inject checksums into download.js
let content = fs.readFileSync(DOWNLOAD_JS, "utf-8");

const checksumLines = Object.entries(checksums)
  .map(([k, v]) => `  "${k}": "${v}"`)
  .join(",\n");

content = content.replace(
  "const CHECKSUMS = {};",
  `const CHECKSUMS = {\n${checksumLines},\n};`
);

// Validate the replacement happened
if (content.includes("const CHECKSUMS = {};")) {
  console.error("Failed to find CHECKSUMS placeholder in download.js");
  process.exit(1);
}

fs.writeFileSync(DOWNLOAD_JS, content);
console.log("Checksums embedded in download.js");
