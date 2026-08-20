import { accessSync, constants } from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";

function setting(name) {
  const value = process.env[name];
  if (value === undefined) {
    throw new Error(`missing action setting ${name}`);
  }
  return value;
}

function oneOf(name, allowed) {
  const value = setting(name);
  if (!allowed.includes(value)) {
    throw new Error(`${name} must be one of: ${allowed.join(", ")}`);
  }
  return value;
}

function booleanSetting(name) {
  return oneOf(name, ["true", "false"]) === "true";
}

try {
  const binaryInput = setting("DEPSCAN_ACTION_BINARY");
  const scanPath = setting("DEPSCAN_ACTION_PATH_INPUT");
  if (scanPath.length === 0) {
    throw new Error("path must not be empty");
  }

  let binary;
  if (binaryInput.length > 0) {
    binary = path.resolve(binaryInput);
  } else {
    binary = setting("DEPSCAN_ACTION_INSTALLED_BINARY");
    if (binary.length === 0 || !path.isAbsolute(binary)) {
      throw new Error("installed depscan binary path must be a non-empty absolute path");
    }
  }
  accessSync(binary, constants.X_OK);

  const ecosystem = oneOf("DEPSCAN_ACTION_ECOSYSTEM", [
    "auto",
    "npm",
    "pypi",
    "nuget",
    "cargo",
  ]);
  const format = oneOf("DEPSCAN_ACTION_FORMAT", [
    "table",
    "markdown",
    "json",
    "sarif",
    "summary",
  ]);
  const failOn = oneOf("DEPSCAN_ACTION_FAIL_ON", [
    "critical",
    "high",
    "medium",
    "low",
    "any",
    "never",
  ]);
  const failOnOutdated = oneOf("DEPSCAN_ACTION_FAIL_ON_OUTDATED", [
    "major",
    "minor",
    "patch",
    "never",
  ]);

  const args = ["scan"];
  if (ecosystem !== "auto") {
    args.push("--ecosystem", ecosystem);
  }
  args.push("--format", format);
  const output = setting("DEPSCAN_ACTION_OUTPUT");
  if (output.length > 0) {
    args.push("--output", output);
  }
  args.push("--fail-on", failOn, "--fail-on-outdated", failOnOutdated);

  for (const [settingName, flag] of [
    ["DEPSCAN_ACTION_OFFLINE", "--offline"],
    ["DEPSCAN_ACTION_NO_CACHE", "--no-cache"],
    ["DEPSCAN_ACTION_NO_DEV", "--no-dev"],
    ["DEPSCAN_ACTION_DIRECT_ONLY", "--direct-only"],
    ["DEPSCAN_ACTION_INCLUDE_WITHDRAWN", "--include-withdrawn"],
  ]) {
    if (booleanSetting(settingName)) {
      args.push(flag);
    }
  }
  args.push("--", scanPath);

  const result = spawnSync(binary, args, {
    shell: false,
    stdio: "inherit",
    windowsHide: true,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.signal !== null) {
    throw new Error(`depscan terminated by ${result.signal}`);
  }
  process.exit(result.status ?? 1);
} catch (error) {
  console.error(`depscan action: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(10);
}
