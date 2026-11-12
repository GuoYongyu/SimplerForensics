/*
 * Regression tests for the browser DiE-JS engine.
 *
 * Run with:
 *   node test/die-engine.test.cjs
 * Optional end-to-end check against a real PE:
 *   DIE_FIXTURE=/path/to/sample.exe node test/die-engine.test.cjs
 */
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const engine = require("../die/engine.js");

function buildFixture() {
  const bytes = new Uint8Array(0x400);
  const view = new DataView(bytes.buffer);
  const put = (offset, text) => {
    for (let i = 0; i < text.length; i++) bytes[offset + i] = text.charCodeAt(i) & 0xff;
  };

  bytes[0] = 0x4d; bytes[1] = 0x5a;
  view.setUint32(0x3c, 0x80, true);
  put(0x80, "PE\u0000\u0000");

  const coff = 0x84;
  view.setUint16(coff, 0x014c, true);
  view.setUint16(coff + 2, 1, true);
  view.setUint32(coff + 4, 0x5f000000, true);
  view.setUint16(coff + 16, 0xe0, true);
  view.setUint16(coff + 18, 0x0102, true);

  const opt = 0x98;
  view.setUint16(opt, 0x010b, true);
  view.setUint8(opt + 2, 14);
  view.setUint8(opt + 3, 0);
  view.setUint32(opt + 4, 0x200, true);
  view.setUint32(opt + 16, 0x1000, true);
  view.setUint32(opt + 20, 0x1000, true);
  view.setUint32(opt + 24, 0x400000, true);
  view.setUint32(opt + 32, 0x1000, true);
  view.setUint32(opt + 36, 0x200, true);
  view.setUint32(opt + 56, 0x2000, true);
  view.setUint32(opt + 60, 0x200, true);
  view.setUint16(opt + 68, 3, true);
  view.setUint16(opt + 70, 0x0140, true);
  view.setUint32(opt + 92, 16, true);

  const section = opt + 0xe0;
  put(section, ".text");
  view.setUint32(section + 8, 0x100, true);
  view.setUint32(section + 12, 0x1000, true);
  view.setUint32(section + 16, 0x200, true);
  view.setUint32(section + 20, 0x200, true);
  view.setUint32(section + 36, 0x60000020, true);

  const code = Uint8Array.from([0x55, 0x8b, 0xec, 0x83, 0xec, 0x10, 0x68, 0x2e, 0x00, 0x40, 0x00]);
  bytes.set(code, 0x200);
  put(0x240, "flag{engine_test}");
  const wide = "wide_flag{engine_test}";
  for (let i = 0; i < wide.length; i++) {
    bytes[0x260 + i * 2] = wide.charCodeAt(i) & 0xff;
    bytes[0x260 + i * 2 + 1] = wide.charCodeAt(i) >>> 8;
  }
  return bytes;
}

const fixture = buildFixture();
const bundle = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "die", "db", "pe-signatures.json"), "utf8"));

// --- PE parsing -----------------------------------------------------------
const pe = engine.parsePE(fixture, "fixture.exe");
assert.equal(pe.valid, true, "synthetic PE should parse");
assert.equal(pe.machine, 0x014c);
assert.equal(pe.entryOffset, 0x200);
assert.equal(pe.entrySection, 0);
assert.equal(pe.sections.length, 1);
assert.equal(pe.sections[0].name, ".text");
assert.equal(pe.overlaySize, 0);
assert.equal(pe.api.is32(), true);
assert.equal(pe.api.getEntryPointOffset(), 0x200);

// --- DiE signature grammar and comparisons --------------------------------
assert.equal(pe.api.compareEP("558BEC"), true, "compareEP should match the entry bytes");
assert.equal(pe.api.compareEP("8BEC", 1), true, "compareEP should honour a relative offset");
assert.equal(pe.api.compareEP("558BED"), false);
assert.equal(pe.api.compare("..8BEC", 0x200), true, "wildcards should match one byte");
assert.equal(pe.api.compare("'flag'", 0x240), true, "quoted text should be translated to bytes");
assert.equal(pe.api.findString(0, fixture.length, "flag{engine_test}"), 0x240);
assert.equal(pe.api.findSignature(0, fixture.length, "fla?{"), -1, "odd wildcard must be invalid");
assert.equal(pe.api.findSignature(0, fixture.length, "666c6167"), 0x240);
assert.equal(pe.api.getSignature(0x200, 4), "558BEC83");

const compiled = engine.compileSignature("55 8B EC");
assert.ok(compiled && compiled.tokens.length === 1);
assert.equal(engine.matchesAt(pe.api, compiled.tokens, 0x200), true);

// A `$` token reads a relative offset and continues at the target, measured
// from the end of the field (matching XBinary::_compareSignature).
const jump = new Uint8Array(0x40);
jump[0] = 0xe9;
jump[1] = 0x04; // field at 1: 1 + 4 + 4 = 9
jump[9] = 0x55;
const jumpContext = { bytes: jump, size: jump.length, offsetToAddress: offset => offset, addressToOffset: address => address };
const jumpSignature = engine.compileSignature("e9$$$$$$$$55");
assert.ok(jumpSignature);
assert.equal(engine.matchesAt(jumpContext, jumpSignature.tokens, 0), true);

// --- Strings and clues ----------------------------------------------------
const strings = engine.extractStrings(fixture);
assert.ok(strings.some(item => item.value === "flag{engine_test}" && item.encoding === "ASCII"));
assert.ok(strings.some(item => item.value === "wide_flag{engine_test}" && item.encoding === "UTF-16LE"));
const findings = engine.classifyStrings(strings);
assert.ok(findings.flagBraces.some(item => item.value === "flag{engine_test}"));

// --- Running a rule and the full official database ------------------------
const rule = {
  file: "test.sg", type: "packer", name: "Test",
  hasDetect: true,
  source: 'meta("packer", "Test"); function detect(){ if (PE.compareEP("558BEC")) { sVersion = "1.0"; bDetected = true; } return result(); }'
};
const scan = engine.runSignatures(engine.parsePE(fixture, "fixture.exe"), { ...bundle, signatures: [rule] }, { maxMs: 5000 });
assert.equal(scan.results.length, 1);
assert.equal(scan.results[0].name, "Test");
assert.equal(scan.results[0].version, "1.0");

const full = engine.runSignatures(engine.parsePE(fixture, "fixture.exe"), bundle, { maxMs: 15000 });
assert.equal(full.stats.total, bundle.signatures.length);
assert.ok(Array.isArray(full.results));
assert.ok(Array.isArray(full.languages));
assert.equal(typeof full.stats.errors, "number");
assert.ok(full.stats.executed > 0, "official rules should execute");
assert.ok(full.stats.executed > 0);

if (process.env.DIE_FIXTURE) {
  const sample = new Uint8Array(fs.readFileSync(process.env.DIE_FIXTURE));
  const parsed = engine.parsePE(sample, path.basename(process.env.DIE_FIXTURE));
  assert.equal(parsed.valid, true, "DIE_FIXTURE should be a valid PE");
  const result = engine.runSignatures(parsed, bundle, { maxMs: 25000 });
  assert.ok(result.results.length >= 0);
  console.log(`fixture: ${path.basename(process.env.DIE_FIXTURE)} → ${result.results.length} results, ${result.stats.errors} rule errors`);
}

console.log("DIE engine tests passed");
