"use strict";

const PLATFORM_MAP = {
  "darwin-arm64": "@skillledger/cli-darwin-arm64",
  "darwin-x64":   "@skillledger/cli-darwin-x64",
  "linux-x64":    "@skillledger/cli-linux-x64",
  "linux-arm64":  "@skillledger/cli-linux-arm64",
  "win32-x64":    "@skillledger/cli-win32-x64",
};

const SUPPORTED_PLATFORMS = Object.keys(PLATFORM_MAP);

/**
 * Returns the platform key for the current environment.
 * @returns {string} e.g. "darwin-arm64"
 */
function getPlatformKey() {
  return `${process.platform}-${process.arch}`;
}

/**
 * Returns the scoped package name for the given platform key.
 * @param {string} platformKey e.g. "darwin-arm64"
 * @returns {string|null} e.g. "@skillledger/cli-darwin-arm64" or null if unsupported
 */
function getPlatformPackage(platformKey) {
  return PLATFORM_MAP[platformKey] || null;
}

/**
 * Returns the binary filename for the current platform.
 * @returns {string} "skillledger.exe" on Windows, "skillledger" elsewhere
 */
function getBinaryName() {
  return process.platform === "win32" ? "skillledger.exe" : "skillledger";
}

/**
 * Returns the GitHub Releases download URL for a given version and platform.
 * @param {string} version e.g. "1.0.0"
 * @param {string} platform e.g. "darwin"
 * @param {string} arch e.g. "arm64"
 * @returns {string} Full download URL
 */
function getDownloadURL(version, platform, arch) {
  const ext = platform === "win32" ? ".exe" : "";
  // Map Node.js arch names to Go arch names for the release artifact filename
  const goArch = arch === "x64" ? "amd64" : arch;
  // Map Node.js platform names to Go platform names
  const goPlatform = platform === "win32" ? "windows" : platform;
  return `https://github.com/skillledger/skillledger/releases/download/v${version}/skillledger-${goPlatform}-${goArch}${ext}`;
}

module.exports = {
  PLATFORM_MAP,
  SUPPORTED_PLATFORMS,
  getPlatformKey,
  getPlatformPackage,
  getBinaryName,
  getDownloadURL,
};
