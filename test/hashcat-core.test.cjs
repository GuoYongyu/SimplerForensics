/*
 * Regression tests for the HashCat workbench core.
 *
 * Run with:
 *   node test/hashcat-core.test.cjs
 */
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const core = require("../hashcat/hashcat-core.js");

// --- hash functions -------------------------------------------------------
assert.equal(core.md5(new Uint8Array()), "d41d8cd98f00b204e9800998ecf8427e");
assert.equal(core.md5(new TextEncoder().encode("hashcat")), "8743b52063cd84097a65d1633f5c74f5");
for (let i = 0; i < 40; i++) {
  const text = crypto.randomBytes(i).toString("base64").slice(0, i);
  assert.equal(core.md5(new TextEncoder().encode(text)), crypto.createHash("md5").update(text).digest("hex"), `md5 mismatch for ${JSON.stringify(text)}`);
}
assert.equal(core.md4(new Uint8Array()), "31d6cfe0d16ae931b73c59d7e0c089c0");
assert.equal(core.md4(Buffer.from("abc")), "a448017aaf21d8525fc10ae87aa6729d");
assert.equal(core.ntlm("password"), "8846f7eaee8fb117ad06bdd830b7586c");

// --- mask compiler --------------------------------------------------------
const simple = core.compileMask("?l?l?d", []);
assert.equal(simple.ok, true);
assert.equal(simple.length, 3);
assert.equal(simple.keyspace, 6760n);
assert.deepEqual(core.buildMaskBatch(simple, 0, 3), ["aa0", "aa1", "aa2"]);
assert.deepEqual(core.buildMaskBatch(simple, 6759, 3), ["zz9"]);

const custom = core.compileMask("?1?1", ["?l?d"]);
assert.equal(custom.ok, true);
assert.equal(custom.keyspace, 1296n);
assert.equal(custom.customUsed.length, 1);
assert.deepEqual(core.buildMaskBatch(custom, 0, 2), ["aa", "ab"]);

const unicodeMask = core.compileMask("你好?l", []);
assert.equal(unicodeMask.length, 3);
assert.equal(unicodeMask.keyspace, 26n);
assert.deepEqual(core.buildMaskBatch(unicodeMask, 0, 2), ["你好a", "你好b"]);

assert.equal(core.compileMask("abc??", []).mask, "abc??");
assert.equal(core.compileMask("?u?d", []).keyspace, 260n);
assert.equal(core.compileMask("", []).ok, false);
assert.equal(core.compileMask("?1", [""]).ok, false);
assert.equal(core.compileMask("?9", []).ok, false);
assert.equal(core.compileMask("?b", []).ok, false);
assert.equal(core.compileMask("?l", []).positions[0].chars.length, 26);

const blocks = [
  { type: "literal", text: "ab?" },
  { type: "lower", count: 2 },
  { type: "custom1", count: 1 }
];
assert.equal(core.maskFromBlocks(blocks, []), "ab???l?l?1");

// --- regex parser and counter --------------------------------------------
function regex(pattern, maxLength = 16) {
  const parsed = core.parseRegex(pattern);
  assert.equal(parsed.ok, true, parsed.error);
  return { parsed, info: core.countRegex(parsed.ast, maxLength) };
}

assert.equal(regex("[a-z]{3}\\d{3}").info.total, 17576000);
assert.equal(regex("(?:19|20)\\d{2}").info.total, 200);
assert.equal(regex("a{2,4}").info.total, 3);
assert.equal(regex("[^0-9]{2}").info.total, 7225);
assert.equal(regex("[a-z]{0,2}").info.total, 703);
assert.equal(regex("(ab|c)d").info.total, 2);
assert.equal(regex("[a-z]+", 3).info.total, 26 + 676 + 17576);
assert.equal(regex("a?").info.total, 2);
assert.equal(regex("a|").info.total, 2);
assert.equal(core.parseRegex("[]").ok, false);
assert.equal(core.parseRegex("(?=abc)").ok, false);
assert.match(core.parseRegex("(?=abc)").error, /环视/);
assert.equal(core.parseRegex("(a)\\1").ok, false);
assert.equal(core.parseRegex("a**").ok, false);
assert.equal(core.parseRegex("[z-a]").ok, false);
assert.equal(core.parseRegex("[a-").ok, false);
assert.equal(core.parseRegex("[\\d]{2}").ok, true);

const sample = core.sampleRegex(core.parseRegex("[a-z]{2}\\d").ast, 8, 5);
assert.deepEqual(sample, ["aa0", "aa1", "aa2", "aa3", "aa4"]);
const countInfo = core.countRegex(core.parseRegex("[a-z]{2}\\d").ast, 8);
assert.equal(countInfo.minLength, 3);
assert.equal(countInfo.maxLength, 3);
assert.equal(countInfo.byLength[3], 6760);

// Unbounded quantifiers are bounded by the supplied maximum length.
const unbounded = regex("\\d+", 4);
assert.equal(unbounded.info.total, 10 + 100 + 1000 + 10000);
assert.equal(unbounded.parsed.unbounded, true);

const unicodeRegex = core.parseRegex("[你好]{2}");
assert.equal(unicodeRegex.ok, true);
assert.equal(core.countRegex(unicodeRegex.ast, 4).total, 4);
assert.deepEqual(core.sampleRegex(unicodeRegex.ast, 4, 2), ["你你", "你好"]);

// --- constraints ----------------------------------------------------------
const constraints = core.normalizeConstraints({
  minLength: 4,
  maxLength: 10,
  requireLower: true,
  requireUpper: true,
  requireDigit: true,
  contains: ["ab"],
  containsMode: "all",
  ignoreCase: true,
  requireAny: "!@#",
  requireAll: "ab",
  exclude: "xyz"
});
assert.equal(core.constraintsPass("abC1!", constraints), true);
assert.equal(core.constraintsPass("abc1!", constraints), false, "uppercase missing");
assert.equal(core.constraintsPass("aBc!a", constraints), false, "digit missing");
assert.equal(core.constraintsPass("aBc1", constraints), false, "required any char missing");
assert.equal(core.constraintsPass("aBc1!x", constraints), false, "excluded char present");
assert.equal(core.constraintsPass("aBc1!", core.normalizeConstraints({ minLength: 6 })), false);
assert.equal(core.constraintsPass("aBc1!", core.normalizeConstraints({})), true);
assert.equal(core.constraintsPass("", core.normalizeConstraints({ minLength: null, maxLength: null })), true);

// --- word rules -----------------------------------------------------------
const variants = core.variantsForWord("Password", {
  base: "lower",
  reverse: true,
  duplicate: false,
  leet: true,
  appendChars: "12",
  years: false,
  prefix: "!",
  suffix: "#"
});
assert.ok(variants.includes("password"));
assert.ok(variants.includes("drowssap"));
assert.ok(variants.includes("p@$$w0rd"));
assert.ok(variants.includes("!password"));
assert.ok(variants.includes("password#"));
assert.ok(variants.includes("password1"));
assert.ok(variants.includes("password2"));
assert.equal(core.variantsForWord("abc", { base: "capitalize" })[0], "Abc");
assert.equal(core.variantsForWord("  abc  ", { trim: true })[0], "abc");
assert.ok(core.variantEstimate({ appendChars: "0123456789" }) >= 11);
assert.equal(core.rulesActive({}), false);
assert.equal(core.rulesActive({ base: "lower" }), true);

// --- hash parsing ---------------------------------------------------------
const md5 = "8743b52063cd84097a65d1633f5c74f5";
const sha1 = "b89eaac7e61417341b710b727768294d0e6a277b";
const sha256 = "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48f13fb50f3df1fe7b8f";
const sha512 = "bdbea0a5e9e6e2f20f4e2b0d1e7b0f4e0b2d3c4a5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";
const bcrypt = "$2b$04$abcdefghijklmnopqrstuuJ5Yb0l7w5H6uP1v3sS7s9X0m8Q2c4G6";
function byHash(parsed, hash) {
  return Array.from(parsed.targets.values()).find((target) => target.hash === hash);
}

const parsed = core.parseHashLines([md5, sha1, sha256, sha512, bcrypt, "not-a-hash", ""].join("\n"), "AUTO");
assert.equal(parsed.targets.size, 5);
assert.equal(byHash(parsed, md5).mode, "MD5");
assert.equal(byHash(parsed, sha1).mode, "SHA1");
assert.equal(byHash(parsed, sha256).mode, "SHA256");
assert.equal(byHash(parsed, sha512).mode, "SHA512");
assert.equal(byHash(parsed, bcrypt).mode, "BCRYPT");
assert.equal(parsed.invalid.length, 1);
assert.equal(parsed.invalid[0].line, 6);

const ntlmParsed = core.parseHashLines(md5, "NTLM");
assert.equal(byHash(ntlmParsed, md5).mode, "NTLM");
const wrongMode = core.parseHashLines(md5, "SHA1");
assert.equal(wrongMode.targets.size, 0);
assert.equal(wrongMode.invalid.length, 1);
const duplicate = core.parseHashLines([md5, md5.toUpperCase()].join("\n"), "MD5");
assert.equal(duplicate.targets.size, 1);

// Generic salted modes: per-line salt and a global salt fallback.
const saltedAfter = core.parseHashLines(md5 + ":s1", "MD5_SALT_AFTER");
assert.equal(saltedAfter.targets.size, 1);
assert.equal(Array.from(saltedAfter.targets.values())[0].salt, "s1");
assert.equal(Array.from(saltedAfter.targets.values())[0].saltPosition, "after");

const saltedBeforeGlobal = core.parseHashLines(md5, "MD5_SALT_BEFORE", "user@example.com");
assert.equal(saltedBeforeGlobal.targets.size, 1);
assert.equal(Array.from(saltedBeforeGlobal.targets.values())[0].salt, "user@example.com");
assert.equal(Array.from(saltedBeforeGlobal.targets.values())[0].saltPosition, "before");

const saltedMissing = core.parseHashLines(md5, "MD5_SALT_AFTER");
assert.equal(saltedMissing.targets.size, 0);
assert.equal(saltedMissing.invalid.length, 1);
assert.match(saltedMissing.invalid[0].reason, /hash:salt/);

// Windows NetNTLMv2 and DCC2 formats.
const netntlmLine = "User::DOMAIN:1122334455667788:35af6750aacb513b7b9e44ae4b60fbf4:0101000000000000aabbccddeeff00112233445566778899";
const netntlmParsed = core.parseHashLines(netntlmLine, "AUTO");
const netntlmTarget = Array.from(netntlmParsed.targets.values())[0];
assert.equal(netntlmTarget.mode, "NETNTLMv2");
assert.equal(netntlmTarget.username, "User");
assert.equal(netntlmTarget.domain, "DOMAIN");
assert.equal(netntlmTarget.challenge, "1122334455667788");

const dcc2Line = "$DCC2$10240#Administrator#4c253e4b65c007a8cd683ea57bc43c76";
const dcc2Parsed = core.parseHashLines(dcc2Line, "AUTO");
const dcc2Target = Array.from(dcc2Parsed.targets.values())[0];
assert.equal(dcc2Target.mode, "DCC2");
assert.equal(dcc2Target.username, "Administrator");
assert.equal(dcc2Target.iterations, 10240);

const windowsCombined = core.parseHashLines([
  "\uFEFF" + netntlmLine,
  dcc2Line
].join("\r\n"), "AUTO");
assert.equal(windowsCombined.targets.size, 2);

// HMAC-MD5 and DCC2 intermediate vectors.
assert.equal(
  Buffer.from(core.hmacMd5(Buffer.from("key"), Buffer.from("The quick brown fox jumps over the lazy dog"))).toString("hex"),
  "80070713463e7749b90c2dc24911e275"
);
const ntHashBytes = core.hexToBytes(core.md4(core.utf16leBytes("password")));
const dcc2Salt = core.utf16leBytes("administrator");
const dcc2Secret = core.hexToBytes(core.md4(core.concatBytes(ntHashBytes, dcc2Salt)));
assert.equal(
  crypto.pbkdf2Sync(Buffer.from(dcc2Secret), Buffer.from(dcc2Salt), 10240, 16, "sha1").toString("hex"),
  "4c253e4b65c007a8cd683ea57bc43c76"
);
const netntlmHash = crypto.createHmac("md5", Buffer.from(ntHashBytes))
  .update(Buffer.from(core.utf16leBytes("USER" + "DOMAIN")))
  .digest();
const netntlmProof = crypto.createHmac("md5", netntlmHash)
  .update(Buffer.concat([
    Buffer.from("1122334455667788", "hex"),
    Buffer.from("0101000000000000aabbccddeeff00112233445566778899", "hex")
  ]))
  .digest("hex");
assert.equal(netntlmProof, "35af6750aacb513b7b9e44ae4b60fbf4");
// Official hashcat 5600 self-test vector (ST_PASS = "hashcat").
const officialNet = core.parseNetNTLMv2Line("0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700");
assert.equal(officialNet.ok, true);
const officialNt = core.hexToBytes(core.md4(core.utf16leBytes("hashcat")));
const officialV2 = core.hmacMd5(officialNt, core.utf16leBytes(officialNet.target.username.toUpperCase() + officialNet.target.domain));
const officialProof = core.hexOf(core.hmacMd5(officialV2, core.concatBytes(
  core.hexToBytes(officialNet.target.challenge),
  core.hexToBytes(officialNet.target.blob)
)));
assert.equal(officialProof, officialNet.target.proof);


// --- hashcat command building --------------------------------------------
const maskCommand = core.hashcatCommand({
  attack: "mask", modes: ["MD5"], mask: "?l?l?d",
  customSets: ["?l?d"], customUsed: [0], constraints: null, rules: {}
});
assert.match(maskCommand, /hashcat -m 0 -a 3 -1 '\?l\?d' hash\.txt '\?l\?l\?d'/);

const dictCommand = core.hashcatCommand({
  attack: "dict", modes: ["MD5"], constraints: null, rules: { base: "lower" }
});
assert.match(dictCommand, /hashcat -m 0 -a 0 hash\.txt dict\.txt -r best64\.rule/);

const hybridCommand = core.hashcatCommand({
  attack: "hybrid", modes: ["NTLM"], mask: "?d?d", direction: "prefix", constraints: null, rules: {}
});
assert.match(hybridCommand, /hashcat -m 1000 -a 7 hash\.txt '\?d\?d' dict\.txt/);

const regexCommand = core.hashcatCommand({
  attack: "regex", modes: ["SHA256"], constraints: null, rules: {}
});
assert.match(regexCommand, /hashcat -m 1400 -a 0 hash\.txt candidates\.txt/);

const saltedCommand = core.hashcatCommand({
  attack: "dict", modes: ["MD5_SALT_AFTER"], constraints: null, rules: {}
});
assert.match(saltedCommand, /hashcat -m 10 -a 0 hash\.txt dict\.txt/);
assert.match(saltedCommand, /hash:salt/);

const windowsCommand = core.hashcatCommand({
  attack: "dict", modes: ["NETNTLMv2", "DCC2"], constraints: null, rules: {}
});
assert.match(windowsCommand, /hashcat -m 5600 -a 0/);
assert.match(windowsCommand, /hashcat -m 2100 -a 0/);
assert.match(windowsCommand, /NetNTLMv2 行格式/);
assert.match(windowsCommand, /DCC2 行格式/);

// --- formatting -----------------------------------------------------------
assert.equal(core.formatCount(0n), "0");
assert.equal(core.formatCount(999n), "999");
assert.equal(core.formatCount(10000n), "10,000（约 1 万）");
assert.match(core.formatCount(123456789n), /1\.23 亿/);
assert.match(core.formatCount(500000000n), /5 亿/);
assert.equal(core.formatDuration(500), "500 毫秒");
assert.match(core.formatDuration(65000), /^1 分 5\.0 秒$/);

console.log("hashcat-core: all tests passed");
