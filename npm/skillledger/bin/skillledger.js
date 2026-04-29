#!/usr/bin/env node
"use strict";

// Handle --force-install before anything else (D-11).
// This runs in the JS wrapper, not the Go binary, avoiding the
// chicken-and-egg problem of needing a binary to install itself.
if (process.argv[2] === "--force-install") {
  require("../lib/download").forceInstall(process.argv.slice(3));
  // forceInstall calls process.exit -- control never reaches here
}

const { execFileSync } = require("child_process");
const { existsSync } = require("fs");
const path = require("path");
const { getPlatformKey, getPlatformPackage, getBinaryName } = require("../lib/platform");

const platformKey = getPlatformKey();
const pkg = getPlatformPackage(platformKey);

// Unsupported platform
if (!pkg) {
  console.error(
    `skillledger: unsupported platform ${platformKey}.\n\n` +
    `Supported: darwin-arm64, darwin-x64, linux-x64, linux-arm64, win32-x64\n`
  );
  process.exit(1);
}

const binName = getBinaryName();
let binPath = null;

// 1. Try optionalDependencies platform package (D-06 step 2)
try {
  binPath = require.resolve(`${pkg}/bin/${binName}`);
} catch {
  // Not found -- fall through to cache check
}

// 2. Try postinstall cache (D-06 step 3)
if (!binPath) {
  const cachePath = path.join(__dirname, "..", "cache", binName);
  if (existsSync(cachePath)) {
    binPath = cachePath;
  }
}

// 3. No binary found -- print actionable error (D-06 step 4, D-10)
if (!binPath) {
  console.error(
    `skillledger: native binary for ${platformKey} was not installed.\n\n` +
    `This usually means your package manager skipped optionalDependencies\n` +
    `or postinstall scripts. To fix:\n\n` +
    `    npx skillledger --force-install\n\n` +
    `Or reinstall with optional deps enabled:\n\n` +
    `    npm install -g skillledger --include=optional\n\n` +
    `More: https://github.com/skillledger/skillledger#install\n`
  );
  process.exit(1);
}

// 4. Execute the binary with inherited stdio
try {
  execFileSync(binPath, process.argv.slice(2), { stdio: "inherit" });
} catch (e) {
  // If the binary exited with a status code, propagate it
  if (e.status !== undefined) {
    process.exit(e.status);
  }
  // Detect exec format error = wrong platform (D-07 runtime platform check)
  if (e.code === "ENOEXEC" || (e.message && e.message.includes("exec format error"))) {
    console.error(
      `skillledger: binary at ${binPath} cannot execute on ${platformKey}.\n` +
      `This usually means node_modules was copied from a different platform.\n` +
      `Fix: rm -rf node_modules && npm install\n`
    );
    process.exit(1);
  }
  process.exit(1);
}
