"use strict";

const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { getPlatformKey, getPlatformPackage, getBinaryName, getDownloadURL } = require("./platform");

// Checksums are embedded at build time by build-packages.js.
// In dev mode, this is an empty object (checksum verification is skipped
// only when CHECKSUMS is empty -- never in production builds).
const CHECKSUMS = {};

/**
 * Downloads a file from a URL, following redirects.
 * @param {string} url
 * @returns {Promise<Buffer>}
 */
function downloadFile(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith("https") ? https : http;
    client.get(url, { headers: { "User-Agent": "skillledger-npm" } }, (res) => {
      // Follow redirects (GitHub releases redirect to S3)
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return downloadFile(res.headers.location).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        reject(new Error(`Download failed: HTTP ${res.statusCode} from ${url}`));
        res.resume();
        return;
      }
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    }).on("error", reject);
  });
}

/**
 * Verifies a buffer's SHA-256 checksum.
 * @param {Buffer} data
 * @param {string} expectedHash hex string
 * @returns {boolean}
 */
function verifyChecksum(data, expectedHash) {
  const actualHash = crypto.createHash("sha256").update(data).digest("hex");
  return actualHash === expectedHash;
}

/**
 * Downloads and verifies the binary for the current (or specified) platform.
 * Per D-09: checksum mismatch deletes partial file and exits 1 (fail-closed).
 * @param {object} opts
 * @param {string} [opts.platform] override process.platform
 * @param {string} [opts.arch] override process.arch
 * @param {string} [opts.version] package version
 * @param {string} [opts.destDir] destination directory
 * @returns {Promise<string>} path to the downloaded binary
 */
async function downloadAndVerify(opts = {}) {
  const platform = opts.platform || process.platform;
  const arch = opts.arch || process.arch;
  const pkg = require("../package.json");
  const version = opts.version || pkg.version;
  const binName = platform === "win32" ? "skillledger.exe" : "skillledger";
  const destDir = opts.destDir || path.join(__dirname, "..", "cache");
  const destPath = path.join(destDir, binName);

  const url = getDownloadURL(version, platform, arch);
  console.error(`skillledger: downloading ${url}`);

  const data = await downloadFile(url);

  // Verify checksum if available (D-09: fail-closed on mismatch)
  const platformKey = `${platform}-${arch}`;
  const expectedChecksum = CHECKSUMS[platformKey];
  if (expectedChecksum) {
    if (!verifyChecksum(data, expectedChecksum)) {
      // Delete partial file if it exists
      try { fs.unlinkSync(destPath); } catch {}
      console.error(
        `skillledger: CHECKSUM MISMATCH for ${platformKey}!\n` +
        `Expected: ${expectedChecksum}\n` +
        `Got:      ${crypto.createHash("sha256").update(data).digest("hex")}\n` +
        `This may indicate a tampered binary. Aborting.`
      );
      process.exit(1);
    }
    console.error("skillledger: checksum verified");
  } else {
    console.error("skillledger: warning: no checksum available for verification (dev build)");
  }

  // Write binary
  fs.mkdirSync(destDir, { recursive: true });
  fs.writeFileSync(destPath, data, { mode: 0o755 });
  console.error(`skillledger: installed to ${destPath}`);

  return destPath;
}

/**
 * Force-install handler for --force-install flag (D-11).
 * Invoked from bin/skillledger.js when process.argv[2] === "--force-install".
 * Supports optional --platform and --arch overrides (D-12).
 * @param {string[]} args remaining argv after --force-install
 */
async function forceInstall(args) {
  const opts = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--platform" && args[i + 1]) {
      opts.platform = args[++i];
    } else if (args[i] === "--arch" && args[i + 1]) {
      opts.arch = args[++i];
    }
  }
  try {
    const binPath = await downloadAndVerify(opts);
    console.error(`skillledger: binary ready at ${binPath}`);
    process.exit(0);
  } catch (err) {
    console.error(`skillledger: force-install failed: ${err.message}`);
    process.exit(1);
  }
}

module.exports = {
  downloadFile,
  verifyChecksum,
  downloadAndVerify,
  forceInstall,
  CHECKSUMS,
};
