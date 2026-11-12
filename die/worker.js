/* global DIEEngine */
importScripts("engine.js?v=20261112-7");

const MAX_FILE_SIZE = 128 * 1024 * 1024;
const MAX_STRINGS = 8000;
const MAX_IMPORT_ROWS = 1500;
const MAX_EXPORT_ROWS = 800;
const MAX_RESOURCE_ROWS = 600;
const MAX_MANIFEST = 32 * 1024;

let bundlePromise = null;
let cachedBundle = null;

function loadBundle() {
  if (bundlePromise) return bundlePromise;
  const url = new URL("db/pe-signatures.json?v=20261112-7", self.location.href);
  bundlePromise = fetch(url)
    .then(response => {
      if (!response.ok) throw new Error(`签名库 HTTP ${response.status}`);
      return response.json();
    })
    .then(bundle => {
      cachedBundle = bundle;
      return bundle;
    })
    .catch(error => {
      bundlePromise = null;
      throw error;
    });
  return bundlePromise;
}

function md5(data) {
  const bitLength = data.length * 8;
  const padded = ((data.length + 9 + 63) >> 6) << 6;
  const message = new Uint8Array(padded);
  message.set(data);
  message[data.length] = 0x80;
  const view = new DataView(message.buffer);
  view.setUint32(padded - 8, bitLength >>> 0, true);
  view.setUint32(padded - 4, Math.floor(bitLength / 4294967296), true);
  const shifts = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  const table = new Int32Array(64);
  for (let i = 0; i < 64; i++) table[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;
  let a0 = 0x67452301 | 0, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476 | 0;
  for (let offset = 0; offset < padded; offset += 64) {
    const block = new Int32Array(16);
    for (let j = 0; j < 16; j++) block[j] = view.getInt32(offset + j * 4, true);
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f, g, s;
      if (i < 16) { f = (b & c) | (~b & d); g = i; s = shifts[i & 3]; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; s = shifts[4 + (i & 3)]; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; s = shifts[8 + (i & 3)]; }
      else { f = c ^ (b | ~d); g = (7 * i) & 15; s = shifts[12 + (i & 3)]; }
      const x = (a + f + table[i] + block[g]) | 0;
      const rotated = (x << s) | (x >>> (32 - s));
      a = d; d = c; c = b; b = (b + rotated) | 0;
    }
    a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
  }
  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer);
  [a0, b0, c0, d0].forEach((value, index) => outView.setInt32(index * 4, value, true));
  return [...out].map(value => value.toString(16).padStart(2, "0")).join("");
}

async function digest(algorithm, bytes) {
  if (!self.crypto || !self.crypto.subtle) return null;
  const buffer = await self.crypto.subtle.digest(algorithm, bytes);
  return [...new Uint8Array(buffer)].map(value => value.toString(16).padStart(2, "0")).join("");
}

async function computeHashes(bytes, report) {
  report.hashes = { MD5: md5(bytes) };
  const algorithms = [["SHA-1", "SHA-1"], ["SHA-256", "SHA-256"], ["SHA-384", "SHA-384"], ["SHA-512", "SHA-512"]];
  if (!self.crypto || !self.crypto.subtle) {
    report.hashNote = "当前环境未提供 Web Crypto，仅计算了 MD5。请通过本机启动脚本打开页面以计算 SHA 系列摘要。";
    return;
  }
  for (const [label, algorithm] of algorithms) {
    try {
      const value = await digest(algorithm, bytes);
      if (value) report.hashes[label] = value;
    } catch {
      report.hashNote = (report.hashNote ? report.hashNote + " " : "") + `无法计算 ${label}。`;
    }
  }
}

function buildReport(bytes, fileName, bundle) {
  const report = {
    file: { name: fileName, size: bytes.length },
    engine: { version: bundle.engineVersion, signatureCount: bundle.signatures.length, excluded: bundle.excluded || [] },
    pe: null,
    die: null,
    hashes: {},
    strings: { total: 0, items: [], findings: {} },
    clues: [],
    limits: {
      maxFileSize: MAX_FILE_SIZE,
      maxStrings: MAX_STRINGS,
      stringScanBytes: bytes.length
    }
  };

  const started = Date.now();
  let pe;
  try {
    pe = DIEEngine.parsePE(bytes, fileName);
  } catch (error) {
    report.pe = { valid: false, reason: "PE 解析器异常：" + (error && error.message ? error.message : String(error)) };
    return report;
  }

  report.pe = publicPE(pe);
  report.clues = DIEEngine.packingHeuristics(pe);

  if (pe.valid) {
    const scan = DIEEngine.runSignatures(pe, bundle, {
      maxMs: 25000,
      onProgress: (done, total) => self.postMessage({ type: "progress", phase: "die", value: total ? Math.round((done / total) * 100) : 100 })
    });
    report.die = {
      results: scan.results.map(item => ({
        type: item.type, name: item.name, version: item.version, options: item.options, source: item.source
      })),
      languages: scan.languages,
      stats: {
        total: scan.stats.total,
        executed: scan.stats.executed,
        withResults: scan.stats.withResults,
        errors: scan.stats.errors,
        skippedNoDetect: scan.stats.skippedNoDetect,
        aborted: scan.stats.aborted,
        elapsedMs: scan.stats.elapsedMs,
        missing: Object.entries(scan.stats.missing).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count })),
        errorSamples: scan.stats.errorSamples
      }
    };
  }

  report.analysisMs = Date.now() - started;
  return report;
}

function publicPE(pe) {
  if (!pe.valid) {
    return { valid: false, reason: pe.reason, warnings: pe.warnings.slice(0, 12) };
  }
  const importFunctions = [];
  let importFunctionTotal = 0;
  for (const library of pe.imports) {
    importFunctionTotal += library.functions.length;
    if (importFunctions.length < MAX_IMPORT_ROWS) {
      for (const fn of library.functions) {
        if (importFunctions.length >= MAX_IMPORT_ROWS) break;
        importFunctions.push({ dll: library.name, name: fn.name || `序号 ${fn.ordinal}`, ordinal: fn.ordinal });
      }
    }
  }
  const exportRows = pe.exports.filter(item => item.name).slice(0, MAX_EXPORT_ROWS).map(item => ({ ordinal: item.ordinal, name: item.name, rva: item.rva }));
  const resources = pe.resources.slice(0, MAX_RESOURCE_ROWS).map(item => ({
    type: item.type, name: item.name, id: item.nameId, language: item.language, offset: item.offset, size: item.size
  }));
  const overlayHead = pe.overlaySize > 0
    ? Array.from(pe.bytes.subarray(pe.overlayOffset, pe.overlayOffset + Math.min(64, pe.overlaySize))).map(value => value.toString(16).padStart(2, "0").toUpperCase()).join(" ")
    : "";

  return {
    valid: true,
    machine: pe.machine,
    machineName: pe.machineName,
    is64: pe.is64,
    isDll: pe.isDll,
    isDriver: pe.isDriver,
    isConsole: pe.isConsole,
    subsystem: pe.subsystem,
    subsystemName: pe.subsystemName,
    characteristics: pe.characteristics,
    dllCharacteristics: pe.dllCharacteristics,
    linkerVersion: `${pe.linkerMajor}.${pe.linkerMinor}`,
    imageBase: pe.imageBase,
    entryRva: pe.entryRva,
    entryOffset: pe.entryOffset,
    entrySection: pe.entrySection,
    entrySectionName: pe.sections[pe.entrySection] ? (pe.sections[pe.entrySection].name || "") : "",
    entryBytes: pe.entryBytes || "",
    sizeOfImage: pe.sizeOfImage,
    sizeOfHeaders: pe.sizeOfHeaders,
    sectionAlignment: pe.sectionAlignment,
    fileAlignment: pe.fileAlignment,
    checksum: pe.checksum,
    timestamp: pe.timestamp && pe.timestamp !== 0xffffffff ? new Date(pe.timestamp * 1000).toISOString() : null,
    osVersion: pe.osVersion,
    subsystemVersion: pe.subsystemVersion,
    sections: pe.sections.map(section => ({
      index: section.index, name: section.name, virtualAddress: section.virtualAddress, virtualSize: section.virtualSize,
      rawPointer: section.rawPointer, rawSize: section.rawSize, entropy: section.entropy, flagsText: section.flagsText,
      characteristics: section.characteristics, readable: section.readable, writable: section.writable,
      executable: section.executable, rangeValid: section.rangeValid
    })),
    overlayOffset: pe.overlayOffset,
    overlaySize: pe.overlaySize,
    overlayHead,
    imports: {
      libraries: pe.imports.length,
      functions: importFunctionTotal,
      rows: importFunctions,
      truncated: importFunctionTotal > MAX_IMPORT_ROWS,
      hash32: pe.importHash32.toString(16).padStart(8, "0").toUpperCase()
    },
    exports: {
      total: pe.exports.length,
      named: pe.exports.filter(item => item.name).length,
      module: pe.exportModule || "",
      rows: exportRows,
      truncated: pe.exports.filter(item => item.name).length > MAX_EXPORT_ROWS
    },
    resources: {
      total: pe.resources.length,
      rows: resources,
      truncated: pe.resources.length > MAX_RESOURCE_ROWS
    },
    versionInfo: pe.versionInfo ? { strings: pe.versionInfo.strings, fixed: pe.versionInfo.fixed } : null,
    manifest: pe.manifest ? pe.manifest.slice(0, MAX_MANIFEST) : "",
    manifestTruncated: pe.manifest.length > MAX_MANIFEST,
    pdb: pe.pdb || "",
    rich: pe.rich ? { offset: pe.rich.offset, entries: pe.rich.entries.slice(0, 64), count: pe.rich.entries.length } : null,
    debugRecords: pe.debugRecords.slice(0, 32),
    security: pe.security,
    tls: pe.tls,
    net: pe.net && pe.net.valid ? {
      version: pe.net.version,
      assemblyName: pe.net.assemblyName || "",
      moduleName: pe.net.moduleName || "",
      typeCount: pe.net.typeCount || 0,
      methodCount: pe.net.methodCount || 0
    } : null,
    warnings: pe.warnings.slice(0, 24)
  };
}

async function analyze(buffer, fileName, runId) {
  const analysisStart = Date.now();
  const bytes = new Uint8Array(buffer);
  let bundle;
  let dbError = "";
  try {
    bundle = await loadBundle();
  } catch (error) {
    dbError = error && error.message ? error.message : String(error);
    bundle = { engineVersion: "未加载", signatures: [], includes: {}, helpers: "", peInit: "", excluded: [] };
  }
  self.postMessage({ type: "progress", phase: "parse", value: 8 });
  const report = buildReport(bytes, fileName, bundle);
  if (dbError) report.engine.dbError = dbError;
  self.postMessage({ type: "progress", phase: "hash", value: 70 });
  await computeHashes(bytes, report);
  self.postMessage({ type: "progress", phase: "strings", value: 85 });

  // CTF samples often append the flag after the last section. The 8,000-string
  // cap can be reached long before the overlay, so scan it separately and merge
  // its strings into both the list and the clue classification.
  let overlayStrings = [];
  if (report.pe.valid && report.pe.overlaySize > 0) {
    overlayStrings = DIEEngine.extractStrings(bytes.subarray(report.pe.overlayOffset), {
      max: 64,
      maxBytes: Math.min(report.pe.overlaySize, 512 * 1024)
    }).map(item => ({ ...item, offset: item.offset + report.pe.overlayOffset }));
    report.overlayStrings = overlayStrings.filter(item => item.value.length >= 5).slice(0, 12);
  }

  const strings = DIEEngine.extractStrings(bytes, { max: MAX_STRINGS, maxBytes: bytes.length });
  const merged = strings.slice();
  const seenStrings = new Set(merged.map(item => item.offset + "|" + item.value));
  for (const item of overlayStrings) {
    const key = item.offset + "|" + item.value;
    if (!seenStrings.has(key)) { seenStrings.add(key); merged.push(item); }
  }
  report.strings.total = merged.length;
  report.strings.items = merged;
  report.strings.findings = DIEEngine.classifyStrings(merged);
  report.strings.truncated = strings.length >= MAX_STRINGS;
  self.postMessage({ type: "progress", phase: "done", value: 100 });
  report.analysisMs = Date.now() - analysisStart;
  return report;
}

self.onmessage = async event => {
  const data = event.data || {};
  if (data.type === "init") {
    try {
      const bundle = await loadBundle();
      self.postMessage({ type: "ready", signatureCount: bundle.signatures.length, engineVersion: bundle.engineVersion, excluded: bundle.excluded || [] });
    } catch (error) {
      self.postMessage({ type: "db-error", message: error && error.message ? error.message : String(error) });
    }
    return;
  }
  if (data.type === "analyze") {
    const runId = data.runId;
    try {
      if (data.size > MAX_FILE_SIZE) throw new Error(`文件超过 ${MAX_FILE_SIZE / 1024 / 1024} MiB 上限。`);
      const report = await analyze(data.buffer, data.fileName || "sample.exe", runId);
      self.postMessage({ type: "result", runId, report });
    } catch (error) {
      self.postMessage({ type: "error", runId, message: error && error.message ? error.message : String(error) });
    }
  }
};
