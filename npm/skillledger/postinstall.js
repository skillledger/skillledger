#!/usr/bin/env node
"use strict";

const { getPlatformKey, getPlatformPackage, getBinaryName } = require("./lib/platform");

// Skip conditions per D-09:
// - npm_config_ignore_scripts=true (postinstall should not have run, but safety check)
// - CI=true unless SKILLLEDGER_FORCE_POSTINSTALL=1 (don't slow CI builds)
// - Platform package already resolved via optionalDependencies

function shouldSkip() {
  if (process.env.npm_config_ignore_scripts === "true") return true;
  if (process.env.CI && process.env.SKILLLEDGER_FORCE_POSTINSTALL !== "1") return true;
  return false;
}

function isPlatformPackageInstalled() {
  const platformKey = getPlatformKey();
  const pkg = getPlatformPackage(platformKey);
  if (!pkg) return false;
  const binName = getBinaryName();
  try {
    require.resolve(`${pkg}/bin/${binName}`);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  if (shouldSkip()) {
    return;
  }

  if (isPlatformPackageInstalled()) {
    // Binary already available via optionalDependencies -- nothing to do
    return;
  }

  console.error("skillledger: platform binary not found via optionalDependencies, attempting download...");

  try {
    const { downloadAndVerify } = require("./lib/download");
    await downloadAndVerify();
  } catch (err) {
    // Per D-09: postinstall is best-effort and never fails the parent install
    // (EXCEPT checksum mismatch, which exits 1 inside download.js)
    console.error(`skillledger: postinstall download failed: ${err.message}`);
    console.error("skillledger: you can manually install later with: npx skillledger --force-install");
    // Exit 0 so npm install does not fail
  }
}

main();
