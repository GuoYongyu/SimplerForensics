#!/usr/bin/env node
/**
 * Build the offline DiE-JS signature bundle used by die/.
 *
 * Usage:
 *   node scripts/build-die-db.mjs /path/to/Detect-It-Easy [output.json]
 *
 * The script only reads a local checkout of Detect-It-Easy (db/PE/*.sg and the
 * helper scripts they include) and writes a single JSON file. No network access
 * is performed. The generated bundle is committed so the web page stays fully
 * offline.
 */
import fs from "node:fs";
import path from "node:path";

const sourceRoot = process.argv[2];
const outputPath = process.argv[3] || path.join("die", "db", "pe-signatures.json");

if (!sourceRoot) {
  console.error("Usage: node scripts/build-die-db.mjs /path/to/Detect-It-Easy [output.json]");
  process.exit(1);
}

const dbRoot = path.join(sourceRoot, "db");
const peRoot = path.join(dbRoot, "PE");

if (!fs.existsSync(peRoot)) {
  console.error(`未找到 ${peRoot}，请传入 Detect-It-Easy 仓库根目录。`);
  process.exit(1);
}

// Signatures that require the native disassembler / control-flow emulator.
// They cannot run in the browser engine and would only add a large payload.
const EXCLUDED = new Set([
  "__GenericHeuristicAnalysis_By_DosX.7.sg"
]);

const readText = file => fs.readFileSync(file, "utf8").replace(/^\uFEFF/, "");

const metaPattern = /meta\s*\(\s*["']([^"']*)["']\s*,\s*["']([^"']*)["']/;
const includePattern = /includeScript\s*\(\s*["']([^"']+)["']\s*\)/g;

const signatures = [];
const excluded = [];
const files = fs.readdirSync(peRoot).filter(name => name.endsWith(".sg")).sort();

for (const file of files) {
  if (EXCLUDED.has(file)) {
    excluded.push(file);
    continue;
  }
  const source = readText(path.join(peRoot, file));
  const meta = metaPattern.exec(source);
  signatures.push({
    file,
    type: meta ? meta[1] : "other",
    name: meta ? meta[2] : file.replace(/\.\d+\.sg$/, ""),
    hasDetect: /\bfunction\s+detect\s*\(/.test(source),
    fix: /^_FixDetects/.test(file),
    source
  });
}

// Bundle helper scripts referenced through includeScript(). They are evaluated
// in the signature scope, matching DiE's include semantics.
const includes = {};
const pending = [];
for (const signature of signatures) {
  let match;
  includePattern.lastIndex = 0;
  while ((match = includePattern.exec(signature.source))) pending.push(match[1]);
}

while (pending.length) {
  const name = pending.pop();
  if (Object.prototype.hasOwnProperty.call(includes, name)) continue;
  const file = path.join(dbRoot, name);
  if (!fs.existsSync(file)) {
    console.warn(`跳过缺失的 includeScript 目标：${name}`);
    includes[name] = "";
    continue;
  }
  const source = readText(file);
  includes[name] = source;
  let match;
  includePattern.lastIndex = 0;
  while ((match = includePattern.exec(source))) pending.push(match[1]);
}

const versionFile = path.join(sourceRoot, "die_version.txt");
const engineVersion = fs.existsSync(versionFile) ? readText(versionFile).trim() : "unknown";

const helpersPath = path.join(dbRoot, "_runtime_helpers");
const peInitPath = path.join(peRoot, "_init");
const helpers = fs.existsSync(helpersPath) ? readText(helpersPath) : "";
const peInit = fs.existsSync(peInitPath) ? readText(peInitPath) : "";

const bundle = {
  schema: 1,
  generatedAt: new Date().toISOString(),
  engineVersion,
  source: "Detect-It-Easy (DiE-JS) db/PE",
  excluded,
  helpers,
  peInit,
  includes,
  signatures
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, JSON.stringify(bundle));

const size = fs.statSync(outputPath).size;
const byType = {};
for (const signature of signatures) byType[signature.type] = (byType[signature.type] || 0) + 1;

console.log(`写入 ${outputPath}`);
console.log(`签名 ${signatures.length} 条，${(size / 1024 / 1024).toFixed(2)} MiB，include 脚本 ${Object.keys(includes).length} 个`);
console.log("类型分布：" + Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([type, count]) => `${type}=${count}`).join(", "));
if (excluded.length) console.log("排除：" + excluded.join(", "));
