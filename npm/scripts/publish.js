#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..", "..");
const NPM_DIR = path.join(ROOT, "npm");
const DIST_DIR = path.join(NPM_DIR, "dist");
const WRAPPER_DIR = path.join(NPM_DIR, "skillledger");
const CLI_DIR = path.join(ROOT, "cli");

const published = [];
const DRY_RUN = process.env.DRY_RUN === "true" || process.argv.includes("--dry-run");

/**
 * Publishes a single npm package from the given directory.
 * Skips already-published versions (idempotent).
 * Tracks published packages for rollback on failure.
 * @param {string} dir path to the package directory
 */
function npmPublish(dir) {
  const pkgPath = path.join(dir, "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
  const name = pkg.name;
  const version = pkg.version;

  // Idempotency check: skip if version already published
  try {
    const existing = execSync("npm view " + name + "@" + version + " version", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
    if (existing === version) {
      console.log("Skipping " + name + "@" + version + " (already published)");
      return;
    }
  } catch {
    // npm view exits non-zero if package/version does not exist -- proceed to publish
  }

  let cmd = "npm publish --access public --tag latest";
  if (DRY_RUN) {
    cmd += " --dry-run";
  }

  console.log("Publishing " + name + "@" + version + "...");
  execSync(cmd, { cwd: dir, stdio: "inherit" });

  if (!DRY_RUN) {
    published.push({ name, version });
  }

  console.log("Published " + name + "@" + version);
}

/**
 * Rolls back previously published packages from this run.
 * Iterates in reverse order to unpublish wrapper before platform packages.
 */
function rollback() {
  if (published.length === 0) {
    console.log("No packages to roll back.");
    return;
  }

  console.error("Rolling back " + published.length + " published packages...");

  for (let i = published.length - 1; i >= 0; i--) {
    const { name, version } = published[i];
    try {
      console.error("  Unpublishing " + name + "@" + version + "...");
      execSync("npm unpublish " + name + "@" + version, { stdio: "inherit" });
      console.error("  Rolled back " + name + "@" + version);
    } catch (err) {
      console.error("  Failed to roll back " + name + "@" + version + ": " + err.message);
    }
  }
}

async function main() {
  if (DRY_RUN) {
    console.log("DRY RUN MODE -- no packages will be published");
  }

  const version = fs.readFileSync(path.join(CLI_DIR, "VERSION"), "utf-8").trim();
  console.log("Publishing skillledger v" + version);

  // Verify dist/ exists
  if (!fs.existsSync(DIST_DIR)) {
    console.error("dist/ directory not found at " + DIST_DIR);
    console.error("Run 'node npm/scripts/build-packages.js' first.");
    process.exit(1);
  }

  // Publish platform packages first (D-05)
  const platforms = fs.readdirSync(DIST_DIR).filter(d => d.startsWith("cli-"));
  if (platforms.length !== 5) {
    console.error("Expected 5 platform packages, found " + platforms.length);
    process.exit(1);
  }

  for (const p of platforms) {
    npmPublish(path.join(DIST_DIR, p));
  }

  // Publish wrapper last (D-05)
  npmPublish(WRAPPER_DIR);

  console.log("Successfully published " + published.length + " packages");
}

main().catch((err) => {
  console.error("Publish failed: " + err.message);
  rollback();
  process.exit(1);
});
