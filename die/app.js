(() => {
  "use strict";

  const $ = selector => document.querySelector(selector);
  const MAX_FILE_SIZE = 128 * 1024 * 1024;
  const MAX_STRING_ROWS = 400;
  const MAX_IMPORT_ROWS = 400;
  const MAX_RESOURCE_ROWS = 300;

  const TYPE_LABELS = {
    protector: "保护器", packer: "压缩壳", cryptor: "加密器", protection: "保护方案",
    compiler: "编译器", linker: "链接器", installer: "安装器", sfx: "自解压",
    joiner: "捆绑器", tool: "工具", library: "运行库", "game engine": "游戏引擎",
    format: "格式", archive: "归档", "sign tool": "签名工具", "operation system": "操作系统",
    "debug data": "调试数据", marker: "标记", emulator: "模拟器", other: "其他"
  };
  const TYPE_KIND = {
    protector: "shell", packer: "shell", cryptor: "shell", protection: "shell",
    compiler: "build", linker: "build",
    installer: "tool", sfx: "tool", joiner: "tool", tool: "tool", "sign tool": "tool",
    library: "lib", "game engine": "lib"
  };
  const TYPE_ORDER = ["protector", "packer", "cryptor", "protection", "compiler", "linker", "installer", "sfx", "joiner", "tool", "library", "game engine", "format", "archive", "other"];
  const RESOURCE_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR",
    8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
    14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD",
    21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST"
  };
  const FINDING_LABELS = {
    flagBraces: "Flag / 花括号线索", flag: "口令与键值线索", url: "URL", ip: "IP 地址",
    registry: "注册表路径", path: "文件路径", email: "邮箱", pdb: "PDB 路径",
    upx: "UPX 标记", base64: "Base64 长串"
  };
  const FINDING_ORDER = ["flagBraces", "flag", "url", "ip", "registry", "path", "email", "pdb", "upx", "base64"];

  const fileInput = $("#file"), drop = $("#drop"), status = $("#status");
  const results = $("#results"), progressWrap = $("#progress-wrap");
  const progress = $("#progress"), progressLabel = $("#progress-label");
  const cancelButton = $("#cancel"), clearButton = $("#clear"), exportButton = $("#export-json");
  const dbStatus = $("#db-status");

  let worker = null;
  let runId = 0;
  let report = null;
  let currentFile = null;
  let busy = false;
  let dbReady = false;

  const fmt = value => Number(value || 0).toLocaleString("zh-CN");
  const offset = value => (value === null || value === undefined || value < 0)
    ? "—"
    : `${fmt(value)} (0x${Number(value).toString(16).toUpperCase()})`;
  const setStatus = (message, kind = "") => {
    status.className = "status" + (kind ? " " + kind : "");
    status.textContent = message;
  };
  const clearNode = node => { while (node && node.firstChild) node.removeChild(node.firstChild); };
  const node = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = text;
    return element;
  };
  const addRow = (body, values) => {
    const row = document.createElement("tr");
    for (const value of values) {
      const cell = document.createElement("td");
      if (value instanceof Node) cell.append(value);
      else cell.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
      row.append(cell);
    }
    body.append(row);
    return row;
  };
  const setProgress = (value, label) => {
    progressWrap.hidden = false;
    progress.value = Math.max(0, Math.min(100, value));
    progressLabel.textContent = label || `${Math.round(value)}%`;
  };
  const hideProgress = () => { progressWrap.hidden = true; progress.value = 0; progressLabel.textContent = ""; };

  function setBusy(value) {
    busy = value;
    cancelButton.disabled = !value;
    clearButton.disabled = false;
  }

  function resetResults() {
    report = null;
    results.hidden = true;
    exportButton.disabled = true;
    hideProgress();
    $("#analysis-time").textContent = "";
  }

  function createWorker() {
    if (worker) { worker.terminate(); worker = null; }
    try {
      worker = new Worker("worker.js?v=20261112-7");
    } catch (error) {
      worker = null;
      const isFile = location.protocol === "file:";
      setStatus(
        isFile
          ? "无法启动本地分析线程：浏览器禁止 file:// 页面创建 Web Worker。请双击 launch.command（macOS）或 launch.bat（Windows）启动本机服务后再打开本页。"
          : "无法启动本地分析线程：" + (error && error.message ? error.message : String(error)) + "。请刷新页面或使用本机启动脚本重试。",
        "error"
      );
      dbStatus.textContent = "当前页面没有可用的 Web Worker，PE 解析与 DIE 规则无法执行。";
      return;
    }
    worker.onmessage = event => {
      const data = event.data || {};
      if (data.type === "ready") {
        dbReady = true;
        dbStatus.textContent = `已加载 ${fmt(data.signatureCount)} 条 DiE-JS PE 签名（DIE ${data.engineVersion || "3.x"}）；签名库随页面离线提供，不会联网更新。`;
        if (!busy) setStatus("签名库已就绪。选择 EXE / DLL 后开始本地静态分析。");
        return;
      }
      if (data.type === "db-error") {
        dbReady = false;
        const isFile = location.protocol === "file:";
        setStatus(
          isFile
            ? "签名库加载失败：浏览器限制 file:// 页面读取本地 JSON。请双击 launch.command（macOS）或 launch.bat（Windows）启动本机服务后再打开本页。"
            : "签名库加载失败：" + data.message + "。请确认 die/db/pe-signatures.json 存在，并通过本机启动脚本打开页面。",
          "error"
        );
        dbStatus.textContent = "签名库未能加载，DIE 规则暂时无法执行；PE 结构、哈希和字符串分析仍可进行。";
        return;
      }
      if (data.type === "progress") {
        const phase = data.phase;
        let value = data.value;
        let label = "解析 PE…";
        if (phase === "die") { value = 10 + value * 0.55; label = `执行 DiE 签名… ${Math.round(data.value)}%`; }
        else if (phase === "hash") { value = 70; label = "计算文件摘要…"; }
        else if (phase === "strings") { value = 86; label = "提取字符串与线索…"; }
        else if (phase === "done") { value = 100; label = "整理结果…"; }
        setProgress(value, label);
        return;
      }
      if (data.type === "result") {
        if (data.runId !== runId) return;
        report = data.report;
        setBusy(false);
        hideProgress();
        renderReport(report);
        const count = report.die ? report.die.results.length : 0;
        const dieText = !report.pe.valid ? "DIE 未执行" : report.engine.dbError ? "签名库未加载" : `DIE 命中 ${count} 条`;
        setStatus(`分析完成：${report.pe.valid ? "PE 结构已解析" : "未能解析为 PE"}，${dieText}。结果仅在本机生成。`, "success");
        return;
      }
      if (data.type === "error") {
        if (data.runId !== runId) return;
        setBusy(false);
        hideProgress();
        setStatus("分析失败：" + data.message, "error");
      }
    };
    worker.onerror = event => {
      setBusy(false);
      hideProgress();
      setStatus("分析线程异常：" + (event.message || "未知错误") + "。请刷新页面后重试。", "error");
    };
    worker.postMessage({ type: "init" });
  }

  function analyzeFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_SIZE) {
      resetResults();
      setStatus(`文件大小 ${fmt(file.size)} 字节，超过 ${MAX_FILE_SIZE / 1024 / 1024} MiB 上限。`, "error");
      return;
    }
    if (!worker) createWorker();
    if (!worker) return;
    currentFile = file;
    resetResults();
    setBusy(true);
    const id = ++runId;
    setStatus(`正在读取 ${file.name}（${fmt(file.size)} 字节）并解析 PE 结构…`);
    setProgress(2, "读取文件…");
    file.arrayBuffer().then(buffer => {
      if (id !== runId) return;
      worker.postMessage({ type: "analyze", buffer, fileName: file.name, size: file.size, runId: id }, [buffer]);
    }).catch(error => {
      setBusy(false);
      hideProgress();
      setStatus("读取文件失败：" + (error && error.message ? error.message : String(error)), "error");
    });
  }

  /* ------------------------------------------------------------------ */

  function renderReport(data) {
    results.hidden = false;
    exportButton.disabled = false;
    $("#file-name").textContent = data.file.name;
    $("#analysis-time").textContent = data.analysisMs ? `耗时 ${(data.analysisMs / 1000).toFixed(1)} 秒` : "";

    const pe = data.pe;
    const die = data.die;
    const detected = die ? die.results : [];
    const shells = detected.filter(item => ["packer", "protector", "cryptor", "protection"].includes(item.type));
    const compilers = detected.filter(item => ["compiler", "linker"].includes(item.type));

    const summary = $("#summary");
    clearNode(summary);
    const addStat = (label, value, small) => {
      const box = node("div", "die-stat");
      box.append(node("span", "", label), node("strong", "", value));
      if (small) box.append(node("small", "", small));
      summary.append(box);
    };
    addStat("文件大小", `${fmt(data.file.size)} 字节`);
    addStat("格式 / 架构", pe.valid ? `${pe.is64 ? "PE32+" : "PE32"} · ${pe.machineName}` : "未能解析 PE", pe.valid ? (pe.isDll ? "DLL" : pe.isDriver ? "驱动" : pe.isConsole ? "控制台程序" : "GUI 程序") : pe.reason);
    if (!pe.valid) {
      addStat("DIE 命中", "未执行", "DIE 仅分析 PE32 / PE32+");
      addStat("查壳结论", "未运行", "文件未能解析为 PE");
      addStat("编译器 / 链接器", "未运行", "文件未能解析为 PE");
    } else if (data.engine.dbError) {
      addStat("DIE 命中", "未执行", "签名库未能加载");
      addStat("查壳结论", "未运行", "签名库未能加载");
      addStat("编译器 / 链接器", "未运行", "签名库未能加载");
    } else {
      addStat("DIE 命中", die ? `${detected.length} 条` : "未执行", die ? `执行 ${fmt(die.stats.executed)} / ${fmt(die.stats.total)} 条规则` : "签名库未就绪");
      addStat("查壳结论", shells.length ? shells.map(item => item.name).join("、") : "未命中壳 / 保护器签名", shells.length ? "签名匹配，不代表已确认加壳或已脱壳" : "未命中不等于没有加壳");
      addStat("编译器 / 链接器", compilers.length ? compilers.map(item => item.name).join("、") : "未识别", compilers.length ? "依据 DIE 规则与 PE 元数据" : "可能被裁剪、混淆或规则未覆盖");
    }

    renderDie(data);
    renderFacts(data);
    renderHashes(data);
    renderClues(data);
    renderRich(data);
    renderEP(data);
    renderSections(data);
    renderOverlay(data);
    renderImports(data);
    renderExports(data);
    renderVersion(data);
    renderResources(data);
    renderFindings(data);
    renderStrings(data);
    renderCoverage(data);
  }

  function renderDie(data) {
    const box = $("#die-results");
    const emptyBox = $("#die-empty");
    clearNode(box);
    clearNode(emptyBox);
    const pe = data.pe;
    if (!data.die || data.engine.dbError) {
      $("#result-count").textContent = "未执行";
      emptyBox.append(node("div", "die-empty-state", data.engine.dbError
        ? "签名库未能加载（" + data.engine.dbError + "），DIE 规则没有执行。PE 结构、哈希和字符串结果仍然可用。"
        : pe.valid
          ? "签名库未加载，DIE 规则没有执行。PE 结构、哈希和字符串结果仍然可用。"
          : "文件未能解析为 PE，DIE 签名没有执行。请确认目标是 PE32 / PE32+ 可执行文件。"));
      $("#die-language").replaceChildren();
      renderDieStats(data);
      return;
    }
    const list = data.die.results;
    $("#result-count").textContent = `命中 ${list.length} 条`;
    if (!list.length) {
      emptyBox.append(node("div", "die-empty-state", "DiE 签名库已完整执行，但没有命中任何规则。常见的未命中原因包括：样本被二次修改、使用了规则库尚未覆盖的保护器、文件被裁剪，或者本身没有明显的编译器/壳特征。未命中不代表安全。"));
    }
    const ordered = [...list].sort((a, b) => {
      const ai = TYPE_ORDER.indexOf(a.type); const bi = TYPE_ORDER.indexOf(b.type);
      return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi) || a.name.localeCompare(b.name, "zh-CN");
    });
    for (const item of ordered) {
      const row = node("div", "die-result");
      const type = node("span", "die-type", TYPE_LABELS[item.type] || item.type);
      type.dataset.kind = TYPE_KIND[item.type] || "other";
      const main = node("div", "die-result-main");
      const nameLine = node("div", "die-result-name");
      nameLine.append(node("strong", "", item.name));
      if (item.version) nameLine.append(node("code", "", "v" + item.version));
      const source = node("small", "die-result-source", "规则：" + item.source);
      main.append(nameLine);
      if (item.options) main.append(node("p", "die-result-note", item.options));
      main.append(source);
      const badge = node("span", "die-result-badge", item.type === "compiler" || item.type === "linker" ? "工具链" : item.type === "library" ? "依赖" : "");
      row.append(type, main, badge);
      box.append(row);
    }

    const languageBox = $("#die-language");
    clearNode(languageBox);
    if (data.die.languages && data.die.languages.length) {
      languageBox.append(node("span", "die-language-label", "语言线索："));
      for (const language of data.die.languages) {
        languageBox.append(node("span", "chip", language.name + (language.version ? " " + language.version : "")));
      }
    }
    renderDieStats(data);
  }

  function renderDieStats(data) {
    const box = $("#die-stats-info");
    clearNode(box);
    if (!data.die) {
      box.append(node("p", "hint", data.engine.dbError ? "签名库未能加载：" + data.engine.dbError : "签名库未加载，无法统计规则执行情况。"));
      return;
    }
    const stats = data.die.stats;
    const grid = node("div", "die-stats die-stats-compact");
    const add = (label, value, small) => {
      const item = node("div", "die-stat");
      item.append(node("span", "", label), node("strong", "", value));
      if (small) item.append(node("small", "", small));
      grid.append(item);
    };
    add("签名库条目", fmt(data.engine.signatureCount), `DIE ${data.engine.version || "3.x"}`);
    add("已执行规则", fmt(stats.executed), `${fmt(stats.total)} 条加载`);
    add("产生结果", fmt(stats.withResults), "至少命中一条的规则数");
    add("规则异常 / 跳过", `${fmt(stats.errors)} / ${fmt(stats.skippedNoDetect)}`, "异常多为浏览器引擎未实现的 API");
    add("扫描用时", `${(stats.elapsedMs / 1000).toFixed(2)} 秒`, stats.aborted ? "达到时间上限，结果可能不完整" : "未中断");
    box.append(grid);

    if (stats.missing && stats.missing.length) {
      const details = node("details", "die-discovery");
      details.open = false;
      const summary = node("summary", "", `浏览器引擎未实现的 API（${stats.missing.length} 项）`);
      const list = node("div", "die-discovery-body");
      list.append(node("p", "hint", "调用这些 API 的规则会抛出错误并被跳过；它们不会产生未经验证的猜测结果。"));
      const ul = node("ul", "hint");
      for (const item of stats.missing.slice(0, 12)) ul.append(node("li", "", `${item.name}（${item.count} 条规则）`));
      list.append(ul);
      details.append(summary, list);
      box.append(details);
    }
    if (stats.errorSamples && stats.errorSamples.length) {
      const details = node("details", "die-discovery");
      const summary = node("summary", "", "其他规则错误样本");
      const list = node("div", "die-discovery-body");
      for (const sample of stats.errorSamples) list.append(node("p", "hint", `${sample.file}：${sample.message}`));
      details.append(summary, list);
      box.append(details);
    }
    if (data.engine.excluded && data.engine.excluded.length) {
      box.append(node("p", "hint", `未加载的规则：${data.engine.excluded.join("、")}（依赖原生反汇编与流程模拟，浏览器引擎无法安全执行）。`));
    }
  }

  function renderFacts(data) {
    const box = $("#facts");
    clearNode(box);
    const pe = data.pe;
    if (!pe.valid) {
      box.append(node("div", "die-stat", pe.reason || "未能解析为 PE。"));
      return;
    }
    const add = (label, value, small) => {
      const item = node("div", "die-stat");
      item.append(node("span", "", label), node("strong", "", value));
      if (small) item.append(node("small", "", small));
      box.append(item);
    };
    add("子系统", pe.subsystemName, `Subsystem = ${pe.subsystem}`);
    add("链接器版本", pe.linkerVersion, "来自 Optional Header");
    add("入口点 RVA", `0x${Number(pe.entryRva).toString(16).toUpperCase()}`, pe.entrySectionName ? `位于 ${pe.entrySectionName}` : "不落在已知节区");
    add("入口点文件偏移", offset(pe.entryOffset), pe.entryBytes ? "EP 字节 " + pe.entryBytes.slice(0, 24) : "");
    add("ImageBase", `0x${Number(pe.imageBase).toString(16).toUpperCase()}`, pe.is64 ? "64 位镜像基址" : "32 位镜像基址");
    add("节区数量", String(pe.sections.length), `文件对齐 ${fmt(pe.fileAlignment)} · 节对齐 ${fmt(pe.sectionAlignment)}`);
    add("PE 时间戳", pe.timestamp ? new Date(pe.timestamp).toLocaleString("zh-CN", { hour12: false }) : "0 或无效", pe.timestamp ? pe.timestamp + "（UTC 存储，可伪造）" : "未提供可解释时间");
    add("数字签名", pe.security ? "存在 Security Directory" : "未发现", pe.security ? `${fmt(pe.security.size)} 字节，页面不验证签名链` : "无 Authenticode 数据");
    add(".NET / CLI", pe.net ? `是（${pe.net.version || "版本未知"}）` : "否", pe.net ? `${pe.net.moduleName || "模块名未知"} · ${fmt(pe.net.typeCount)} 个类型 / ${fmt(pe.net.methodCount)} 个方法` : "未发现 CLI Header");
    add("TLS 回调", pe.tls ? "存在 TLS Directory" : "未发现", pe.tls ? "TLS 回调可能在入口点前执行" : "");
    add("Overlay", pe.overlaySize ? `${fmt(pe.overlaySize)} 字节` : "无", pe.overlaySize ? `文件尾部偏移 ${offset(pe.overlayOffset)}` : "原始节区之外没有附加数据");
    add("PDB 路径", pe.pdb || "未发现", pe.pdb ? "调试目录中的 CodeView 记录，可被伪造" : "无 CodeView 记录");
  }

  function renderHashes(data) {
    const box = $("#hashes");
    clearNode(box);
    const entries = Object.entries(data.hashes || {});
    for (const [label, value] of entries) {
      const row = node("div", "hash-row");
      const name = node("strong", "", label);
      const code = node("code", "", value);
      const button = node("button", "btn btn-small", "复制");
      button.type = "button";
      button.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(value);
          button.textContent = "已复制";
          setTimeout(() => { button.textContent = "复制"; }, 1600);
        } catch {
          const range = document.createRange();
          range.selectNodeContents(code);
          const selection = window.getSelection();
          selection.removeAllRanges();
          selection.addRange(range);
          button.textContent = "请手动复制";
        }
      });
      row.append(name, code, button);
      box.append(row);
    }
    const note = $("#hash-note");
    note.hidden = !data.hashNote;
    note.textContent = data.hashNote || "";
  }

  function renderClues(data) {
    const box = $("#clues");
    clearNode(box);
    if (!data.clues || !data.clues.length) {
      box.append(node("p", "hint", "没有发现内置启发式线索。该结果只覆盖本页列出的结构规则，不代表文件没有任何保护。"));
      return;
    }
    for (const clue of data.clues) {
      const item = node("div", "die-clue");
      item.dataset.severity = clue.severity;
      item.append(node("span", "", clue.severity === "warning" ? "需复核" : "线索"), node("strong", "", clue.text));
      box.append(item);
    }
  }

  function renderRich(data) {
    const wrap = $("#rich-wrap");
    const body = $("#rich");
    clearNode(body);
    const pe = data.pe;
    if (!pe.valid || !pe.rich) {
      wrap.hidden = true;
      return;
    }
    wrap.hidden = false;
    $("#rich-note").textContent = `Rich Header 位于文件偏移 ${offset(pe.rich.offset)}，共 ${fmt(pe.rich.count)} 条记录。它常被用于推测 MSVC 工具链版本，也可以被伪造。`;
    for (const [index, entry] of pe.rich.entries.entries()) {
      addRow(body, [String(index), "0x" + entry.productId.toString(16).toUpperCase(), String(entry.build), fmt(entry.count)]);
    }
  }

  function renderEP(data) {
    const box = $("#ep-facts");
    clearNode(box);
    const pe = data.pe;
    if (!pe.valid) { box.append(node("div", "die-stat", "无 PE 入口点。")); return; }
    const add = (label, value) => {
      const item = node("div", "die-stat");
      item.append(node("span", "", label), node("strong", "", value));
      box.append(item);
    };
    add("入口点 RVA", `0x${Number(pe.entryRva).toString(16).toUpperCase()}`);
    add("入口点文件偏移", offset(pe.entryOffset));
    add("所在节区", pe.entrySectionName || "不在已知节区");
    add("入口点字节", pe.entryBytes || "—");
    add("SizeOfImage", fmt(pe.sizeOfImage));
    add("SizeOfHeaders", fmt(pe.sizeOfHeaders));
    add("校验和", pe.checksum ? "0x" + Number(pe.checksum).toString(16).toUpperCase() : "0");
  }

  function renderSections(data) {
    const body = $("#sections");
    clearNode(body);
    const pe = data.pe;
    if (!pe.valid || !pe.sections.length) {
      addRow(body, ["无节区数据", "—", "—", "—", "—", "—"]);
      return;
    }
    for (const section of pe.sections) {
      const entropyWrap = node("div", "entropy-cell");
      const meter = node("span", "entropy-meter");
      const fill = node("i");
      fill.style.width = Math.max(2, Math.min(100, (section.entropy / 8) * 100)) + "%";
      meter.dataset.high = section.entropy >= 7.2 ? "1" : "0";
      meter.append(fill);
      entropyWrap.append(meter, node("span", "", section.entropy.toFixed(2)));
      addRow(body, [
        section.name || "(无名)",
        "0x" + Number(section.virtualAddress).toString(16).toUpperCase(),
        offset(section.rawPointer),
        `${fmt(section.virtualSize)} / ${fmt(section.rawSize)}`,
        section.flagsText,
        entropyWrap
      ]);
    }
  }

  function renderOverlay(data) {
    const wrap = $("#overlay-wrap");
    const box = $("#overlay");
    const strings = $("#overlay-strings");
    clearNode(box);
    clearNode(strings);
    const pe = data.pe;
    if (!pe.valid || !pe.overlaySize) { wrap.hidden = true; return; }
    wrap.hidden = false;
    const ratio = (pe.overlaySize / Math.max(1, data.file.size)) * 100;
    box.append(node("div", "", `附加数据起点：${offset(pe.overlayOffset)}，大小 ${fmt(pe.overlaySize)} 字节（占文件 ${ratio.toFixed(1)}%）。`));
    if (pe.overlayHead) {
      const head = node("div", "", "前 64 字节：");
      head.append(node("code", "", pe.overlayHead));
      box.append(head);
    }
    if (data.overlayStrings && data.overlayStrings.length) {
      for (const item of data.overlayStrings) {
        const row = node("div");
        row.append(node("code", "", item.value));
        strings.append(row);
      }
    }
  }

  function renderImports(data) {
    const body = $("#imports");
    const note = $("#import-note");
    const countChip = $("#import-count");
    const pe = data.pe;
    clearNode(body);
    countChip.textContent = "";
    note.textContent = "";
    if (!pe.valid || !pe.imports || !pe.imports.rows.length) {
      addRow(body, ["无导入表", "文件没有声明常规导入函数。"]);
      note.textContent = "没有常规导入表的 PE 可能被加壳、修复过，或为特殊构造样本。";
      return;
    }
    const render = query => {
      clearNode(body);
      const q = query.trim().toLowerCase();
      const filtered = pe.imports.rows.filter(item => !q || item.dll.toLowerCase().includes(q) || item.name.toLowerCase().includes(q));
      for (const item of filtered.slice(0, MAX_IMPORT_ROWS)) addRow(body, [item.dll, item.name]);
      countChip.textContent = `${fmt(filtered.length)} 条匹配 / 展示 ${fmt(Math.min(filtered.length, MAX_IMPORT_ROWS))}`;
      note.textContent = `导入表共 ${fmt(pe.imports.libraries)} 个 DLL、${fmt(pe.imports.functions)} 个函数；页面最多展示 ${fmt(MAX_IMPORT_ROWS)} 条。导入哈希 ${pe.imports.hash32}。`;
    };
    render($("#import-filter").value || "");
    $("#import-filter").oninput = event => render(event.target.value);
  }

  function renderExports(data) {
    const body = $("#exports");
    const label = $("#export-count");
    clearNode(body);
    const pe = data.pe;
    if (!pe.valid || !pe.exports) {
      label.textContent = "";
      addRow(body, ["—", "无导出数据", "—"]);
      return;
    }
    label.textContent = pe.exports.total
      ? `共 ${fmt(pe.exports.total)} 个导出槽位，其中 ${fmt(pe.exports.named)} 个有名称${pe.exports.module ? "；模块名 " + pe.exports.module : ""}。`
      : "未发现导出表。";
    if (!pe.exports.rows.length) {
      addRow(body, ["—", "无命名导出函数", "—"]);
      return;
    }
    for (const item of pe.exports.rows) addRow(body, [String(item.ordinal), item.name, "0x" + Number(item.rva).toString(16).toUpperCase()]);
  }

  function renderVersion(data) {
    const box = $("#version-info");
    const manifestWrap = $("#manifest-wrap");
    const manifest = $("#manifest");
    clearNode(box);
    const pe = data.pe;
    manifest.textContent = pe.valid ? pe.manifest || "" : "";
    manifestWrap.hidden = !manifest.textContent;
    if (manifest.textContent && pe.manifestTruncated) manifest.textContent += "\n\n…（Manifest 过长，页面仅显示前 32 KiB）";
    const strings = pe.valid && pe.versionInfo ? pe.versionInfo.strings : null;
    if (!strings || !Object.keys(strings).length) {
      $("#version-note").textContent = "未发现可读的 VS_VERSIONINFO 字符串资源。版本信息不是必需的，也可能被加壳或裁剪移除。";
      return;
    }
    $("#version-note").textContent = "以下字段直接读取自 RT_VERSION 资源，可能被构建流程或作者修改，不能作为可信来源证明。";
    for (const [key, value] of Object.entries(strings)) {
      const item = node("div", "die-version-item");
      item.append(node("span", "", key), node("strong", "", value));
      box.append(item);
    }
    if (pe.versionInfo.fixed) {
      const item = node("div", "die-version-item");
      item.append(node("span", "", "VS_FIXEDFILEINFO"), node("strong", "", `文件 ${pe.versionInfo.fixed.fileVersion} · 产品 ${pe.versionInfo.fixed.productVersion}`));
      box.append(item);
    }
  }

  function renderResources(data) {
    const body = $("#resources");
    const count = $("#resource-count");
    clearNode(body);
    const pe = data.pe;
    if (!pe.valid || !pe.resources || !pe.resources.rows.length) {
      count.textContent = "未发现资源目录或资源条目。";
      addRow(body, ["—", "无资源", "—", "—", "—"]);
      return;
    }
    count.textContent = `资源共 ${fmt(pe.resources.total)} 条；页面展示前 ${fmt(Math.min(pe.resources.total, MAX_RESOURCE_ROWS))} 条。`;
    for (const item of pe.resources.rows) {
      const typeName = RESOURCE_TYPES[item.type] || (item.type ? "0x" + Number(item.type).toString(16).toUpperCase() : "命名类型");
      const name = item.name || (item.id ? "ID " + item.id : "—");
      addRow(body, [typeName, name, item.language ? String(item.language) : "—", offset(item.offset), fmt(item.size)]);
    }
    if (pe.resources.truncated) count.textContent += " 结果已截断。";
  }

  function renderFindings(data) {
    const box = $("#findings");
    clearNode(box);
    const findings = data.strings.findings || {};
    let total = 0;
    for (const key of FINDING_ORDER) {
      const list = findings[key];
      if (!list || !list.length) continue;
      total += list.length;
      const group = node("div", "die-finding-group");
      group.append(node("h4", "", `${FINDING_LABELS[key] || key}（${list.length}）`));
      const ul = node("ul");
      for (const item of list) {
        const li = node("li");
        li.append(node("code", "", item.value));
        if (item.offset !== undefined) li.append(node("span", "hint", ` · 偏移 ${offset(item.offset)}`));
        ul.append(li);
      }
      group.append(ul);
      box.append(group);
    }
    if (!total) box.append(node("p", "hint", "未提取到符合内置模式的 Flag、URL、IP、注册表路径等线索。字符串命中不等于行为发生，未命中也不代表不存在。"));
  }

  function renderStrings(data) {
    const body = $("#strings");
    const chip = $("#string-count");
    const note = $("#string-note");
    const items = (data.strings && data.strings.items) || [];
    let timer = 0;
    const render = query => {
      clearNode(body);
      const q = String(query || "").trim().toLowerCase();
      const filtered = q ? items.filter(item => item.value.toLowerCase().includes(q)) : items;
      for (const item of filtered.slice(0, MAX_STRING_ROWS)) addRow(body, [offset(item.offset), item.encoding, item.value]);
      chip.textContent = `${fmt(filtered.length)} 条匹配 / 共 ${fmt(items.length)} 条`;
      const notes = [];
      notes.push(`页面最多显示 ${fmt(MAX_STRING_ROWS)} 条；使用搜索框可缩小范围。`);
      if (data.strings && data.strings.truncated) notes.push(`字符串提取达到 ${fmt(data.limits.maxStrings)} 条上限，文件中可能还有未展示的字符串。`);
      if (!filtered.length) notes.push("没有匹配的字符串。");
      note.textContent = notes.join(" ");
    };
    render($("#string-filter").value || "");
    $("#string-filter").oninput = event => {
      clearTimeout(timer);
      const value = event.target.value;
      timer = setTimeout(() => render(value), 160);
    };
  }

  function renderCoverage(data) {
    const box = $("#coverage");
    clearNode(box);
    const add = (label, value, small) => {
      const item = node("div", "die-stat");
      item.append(node("span", "", label), node("strong", "", value));
      if (small) item.append(node("small", "", small));
      box.append(item);
    };
    add("签名库", `${fmt(data.engine.signatureCount)} 条`, `DIE ${data.engine.version || "3.x"} · 仅 PE`);
    if (data.die) {
      add("规则执行", `${fmt(data.die.stats.executed)} 条`, data.die.stats.aborted ? "达到 25 秒时间上限" : "全部执行");
      add("规则错误", fmt(data.die.stats.errors), "多为未实现的 API，已跳过");
    }
    add("字符串扫描", `${fmt(data.strings.total)} 条`, `上限 ${fmt(data.limits.maxStrings)} 条`);
    add("文件上限", "128 MiB", "超出后不分析");

    const notes = $("#coverage-notes");
    clearNode(notes);
    const list = node("ul", "hint");
    const messages = [
      "本页是 DIE 签名引擎的浏览器移植，不是完整 DIE 客户端；原生反汇编、IL 方法体模拟、深度启发式和读取相邻文件的规则不会执行。",
      "规则结果按 DiE-JS 的 meta/result 语义收集，并对重复结果做了上限去重；仍可能出现误报或漏报。",
      "签名库固定随页面发布，不会自动更新；请以 DIE 官方数据库版本为参照评估覆盖范围。",
      "所有分析都在本地 Web Worker 中完成，不上传文件、不执行样本、不访问网络。"
    ];
    for (const message of messages) list.append(node("li", "", message));
    notes.append(list);
  }

  /* ------------------------------------------------------------------ */

  function readFileFromInput(event) {
    const file = event.target.files && event.target.files[0];
    if (file) analyzeFile(file);
  }

  fileInput.addEventListener("change", readFileFromInput);

  drop.addEventListener("dragover", event => {
    event.preventDefault();
    drop.classList.add("dragover");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("dragover"));
  drop.addEventListener("drop", event => {
    event.preventDefault();
    drop.classList.remove("dragover");
    const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) analyzeFile(file);
  });

  cancelButton.addEventListener("click", () => {
    if (!busy) return;
    runId++;
    setBusy(false);
    hideProgress();
    if (worker) { worker.terminate(); worker = null; }
    createWorker();
    if (worker) setStatus("已取消本次分析。可以重新选择文件。", "warning");
  });

  clearButton.addEventListener("click", () => {
    runId++;
    if (worker) { worker.terminate(); worker = null; }
    createWorker();
    currentFile = null;
    fileInput.value = "";
    setBusy(false);
    resetResults();
    if (worker) setStatus("已清空结果。选择文件后开始新的本地分析。");
  });

  exportButton.addEventListener("click", () => {
    if (!report) return;
    const payload = {
      tool: "SimplerForensics DIE 查壳识别",
      generatedAt: new Date().toISOString(),
      report
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const base = (report.file.name || "sample").replace(/\.[^.]+$/, "");
    link.href = url;
    link.download = `${base}-die-report.json`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    setStatus("JSON 报告已生成本地下载。", "success");
  });

  createWorker();
})();
