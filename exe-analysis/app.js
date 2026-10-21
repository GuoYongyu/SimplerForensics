(() => {
  const $ = selector => document.querySelector(selector);
  const fileInput = $("#file"), drop = $("#drop"), status = $("#status");
  const resultPanel = $("#results"), progressWrap = $("#progress-wrap");
  const progress = $("#progress"), progressLabel = $("#progress-label");
  const cancelButton = $("#cancel"), clearButton = $("#clear");
  const MAX_FILE_SIZE = 128 * 1024 * 1024;
  let worker = null, runId = 0, currentResult = null, currentFile = null, customRules = [];

  const fmt = value => Number(value || 0).toLocaleString("zh-CN");
  const offset = value => value === null || value === undefined ? "—" : fmt(value) + " (" + Number(value).toString(16).toUpperCase().padStart(8, "0") + "h)";
  const setStatus = (message, kind = "") => { status.className = "status" + (kind ? " " + kind : ""); status.textContent = message; };
  const addCell = (row, value) => { const cell = document.createElement("td"); cell.textContent = value ?? "—"; row.append(cell); return cell; };
  const addRow = (body, values) => { const row = document.createElement("tr"); values.forEach(value => addCell(row, value)); body.append(row); return row; };
  const clearNode = node => { while (node.firstChild) node.removeChild(node.firstChild); };
  const stopWorker = (keepProgress = false) => { if (worker) { worker.terminate(); worker = null; } cancelButton.disabled = true; if (!keepProgress) progressWrap.hidden = true; };

  function drawSummary(result) {
    $("#file-name").textContent = result.file.name;
    const items = [["文件大小", fmt(result.file.size) + " 字节"], ["PE 状态", result.pe.valid ? "结构已识别" : "未能解析 PE"], ["架构", result.pe.valid ? result.pe.architecture : "—"], ["分析范围", "静态分析"]];
    const box = $("#summary"); clearNode(box);
    for (const pair of items) {
      const card = document.createElement("div"); card.className = "analysis-stat";
      const small = document.createElement("span"); small.textContent = pair[0];
      const strong = document.createElement("strong"); strong.textContent = pair[1];
      card.append(small, strong); box.append(card);
    }
  }

  function drawHashes(hashes) {
    const box = $("#hashes"); clearNode(box);
    for (const pair of Object.entries(hashes)) {
      const row = document.createElement("div"); row.className = "hash-row";
      const label = document.createElement("strong"); label.textContent = pair[0];
      const code = document.createElement("code"); code.textContent = pair[1];
      const button = document.createElement("button"); button.className = "btn btn-small"; button.type = "button"; button.textContent = "复制";
      button.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(pair[1]); button.textContent = "已复制"; }
        catch { const selection = window.getSelection(); const range = document.createRange(); range.selectNodeContents(code); selection.removeAllRanges(); selection.addRange(range); button.textContent = "请手动复制"; }
      });
      row.append(label, code, button); box.append(row);
    }
  }

  function drawLanguage(language, pe) {
    const box = $("#language"); clearNode(box);
    const title = document.createElement("p"); title.className = "language-result";
    title.textContent = (language.language || "无法确定") + " · 置信度：" + (language.confidence || "低");
    box.append(title);
    if (!language.candidates || !language.candidates.length) {
      const empty = document.createElement("p"); empty.className = "status warning";
      empty.textContent = pe && pe.valid
        ? "识别流程已完成，但这个文件没有暴露足以判断源代码语言或具体工具链的特征。静态编译后的原生代码常会丢失语言标记；这不代表识别功能没有运行。"
        : "识别流程已完成，但文件未能解析为有效 PE，因此无法据此判断其源代码语言。";
      box.append(empty);
    }
    if (language.compiler && language.compiler.length) {
      const compiler = document.createElement("p"); compiler.textContent = "工具链 / 运行时线索：" + language.compiler.join("、"); box.append(compiler);
    }
    for (const candidate of language.candidates || []) {
      const details = document.createElement("details"); details.className = "evidence-detail";
      const summary = document.createElement("summary"); summary.textContent = candidate.language + "（内部评分 " + candidate.score + "）";
      const ul = document.createElement("ul");
      for (const item of candidate.evidence) { const li = document.createElement("li"); li.textContent = item; ul.append(li); }
      details.append(summary, ul); box.append(details);
    }
    if (language.note) { const note = document.createElement("p"); note.className = "hint"; note.textContent = language.note; box.append(note); }
  }

  function drawPE(pe) {
    const summary = $("#pe-summary"); clearNode(summary);
    if (!pe.valid) { summary.textContent = pe.reason || "不是可识别的 PE 文件。"; $("#sections").replaceChildren(); $("#imports").replaceChildren(); $("#import-count").textContent = ""; return; }
    const fields = [["Machine", pe.machine], ["PE 类型", pe.is64 ? "PE32+" : "PE32"], ["入口点 RVA", pe.entryPointRva], ["ImageBase", pe.imageBase], ["子系统", String(pe.subsystem)], ["节区数量", String(pe.sectionsCount)], ["文件对齐", fmt(pe.fileAlignment)], ["节区对齐", fmt(pe.sectionAlignment)], ["SizeOfImage", fmt(pe.sizeOfImage)], ["PE 时间戳", pe.compileDate || "无效或特殊值"], ["Overlay", fmt(pe.overlayBytes) + " 字节"]];
    for (const pair of fields) { const item = document.createElement("div"); item.className = "analysis-stat"; const l = document.createElement("span"); l.textContent = pair[0]; const v = document.createElement("strong"); v.textContent = pair[1]; item.append(l, v); summary.append(item); }
    const sectionBody = $("#sections"); clearNode(sectionBody);
    for (const section of pe.sections) {
      const perms = (section.readable ? "R" : "-") + (section.writable ? "W" : "-") + (section.executable ? "X" : "-");
      addRow(sectionBody, [section.name, section.virtualAddress, offset(section.rawPointer), fmt(section.virtualSize) + " / " + fmt(section.rawSize), perms, section.entropy + " bits/byte"]);
    }
    const warnings = $("#pe-warnings"); clearNode(warnings);
    for (const message of pe.warnings || []) { const p = document.createElement("p"); p.className = "status warning"; p.textContent = message; warnings.append(p); }
    drawImports(pe.imports || []);
  }

  function drawImports(imports, query = "") {
    const body = $("#imports"); clearNode(body);
    const q = query.trim().toLowerCase();
    const filtered = imports.filter(item => !q || item.dll.toLowerCase().includes(q) || item.name.toLowerCase().includes(q)).slice(0, 1000);
    for (const item of filtered) addRow(body, [item.dll, item.name]);
    $("#import-count").textContent = fmt(filtered.length) + " 条显示" + (imports.length > filtered.length ? "（当前结果最多展示 1,000 条，导入表共 " + fmt(imports.length) + " 条）" : "");
  }

  function drawStrings(strings, query = "") {
    const body = $("#strings"); clearNode(body);
    const q = query.trim().toLowerCase();
    const filtered = strings.filter(item => !q || item.value.toLowerCase().includes(q)).slice(0, 500);
    for (const item of filtered) addRow(body, [offset(item.offset), item.encoding, item.value]);
    $("#string-count").textContent = fmt(filtered.length) + " 条显示 / 本次提取 " + fmt(currentResult?.stringsTotal || strings.length) + " 条";
    const limit = $("#string-limit");
    limit.hidden = (currentResult?.stringsTotal || 0) <= strings.length;
    if (!limit.hidden) limit.textContent = "提取结果达到 " + fmt(strings.length) + " 条上限；文件中可能还有未展示的字符串。";
  }

  function drawIocs(iocs) {
    const box = $("#iocs"); clearNode(box);
    if (!iocs || !iocs.length) { const p = document.createElement("p"); p.className = "hint"; p.textContent = "未提取到符合内置模式的 IOC 字符串。"; box.append(p); return; }
    for (const item of iocs) { const row = document.createElement("div"); row.className = "ioc-row"; const at = document.createElement("span"); at.textContent = offset(item.offset); const value = document.createElement("code"); value.textContent = item.value; row.append(at, value); box.append(row); }
  }

  function drawRules(rules) {
    const box = $("#rules"); clearNode(box);
    if (!rules.length) { const p = document.createElement("p"); p.className = "status"; p.textContent = "未触发内置规则。未命中不代表文件安全。"; box.append(p); return; }
    for (const rule of rules) {
      const item = document.createElement("article"); item.className = "rule-hit" + (rule.severity === "warning" ? " rule-warning" : "");
      const head = document.createElement("div"); head.className = "rule-head";
      const title = document.createElement("strong"); title.textContent = rule.id + " · " + rule.title;
      const level = document.createElement("span"); level.textContent = rule.severity === "warning" ? "需复核" : "线索";
      head.append(title, level);
      const evidence = document.createElement("p"); evidence.textContent = "证据：" + rule.evidence + (rule.offset === null ? "" : "；偏移 " + offset(rule.offset));
      item.append(head, evidence); box.append(item);
    }
  }

  function render(result) {
    currentResult = result; resultPanel.hidden = false;
    drawSummary(result); drawHashes(result.hashes); drawLanguage(result.language, result.pe); drawPE(result.pe);
    drawStrings(result.strings || []); drawIocs(result.iocs || []); drawRules(result.rules || []);
    $("#import-filter").value = ""; $("#string-filter").value = "";
  }

  function start(file) {
    stopWorker(); runId++; currentResult = null; currentFile = file || null; resultPanel.hidden = true;
    if (!file) return;
    if (file.size > MAX_FILE_SIZE) { setStatus("文件超过 128 MiB 上限；未读取文件。", "error"); return; }
    if (!file.size) { setStatus("文件为空。", "error"); return; }
    const thisRun = runId;
    try { worker = new Worker("worker.js?v=20261019-1"); }
    catch (error) { setStatus("无法启动本地分析 Worker；请通过 launch.bat / launch.command 启动本机页面服务后重试：" + error.message, "error"); return; }
    cancelButton.disabled = false; progressWrap.hidden = false; progress.value = 0;
    setStatus("正在分析 " + file.name + "。文件不会上传或执行。");
    worker.onmessage = event => {
      const message = event.data || {};
      if (message.id !== thisRun) return;
      if (message.type === "progress") { progress.value = message.value; progressLabel.textContent = message.label || ""; }
      if (message.type === "result") { stopWorker(true); progress.value = 100; progressLabel.textContent = "分析完成"; render(message.result); setStatus("静态分析完成。结果仅来自文件中可见的静态数据。", "success"); }
      if (message.type === "error") { stopWorker(); setStatus("分析未完成：" + message.error, "error"); }
    };
    worker.onerror = event => { stopWorker(); setStatus("分析 Worker 出错：" + (event.message || "未知错误"), "error"); };
    worker.postMessage({ id: thisRun, file, rules: customRules });
  }

  fileInput.addEventListener("change", () => start(fileInput.files?.[0]));
  for (const type of ["dragenter", "dragover"]) drop.addEventListener(type, event => { event.preventDefault(); drop.classList.add("drag-over"); });
  for (const type of ["dragleave", "drop"]) drop.addEventListener(type, event => { event.preventDefault(); drop.classList.remove("drag-over"); });
  drop.addEventListener("drop", event => { const file = event.dataTransfer?.files?.[0]; if (file) start(file); });
  cancelButton.addEventListener("click", () => { stopWorker(); runId++; resultPanel.hidden = true; setStatus("已取消分析；未生成部分报告。", "warning"); });
  clearButton.addEventListener("click", () => { stopWorker(); runId++; currentResult = null; currentFile = null; fileInput.value = ""; resultPanel.hidden = true; setStatus("结果已清空。"); });
  $("#rules-file").addEventListener("change", async event => {
    const file = event.target.files && event.target.files[0];
    customRules = [];
    if (!file) { $("#rules-file-status").textContent = "当前仅使用内置规则。"; return; }
    if (file.size > 1024 * 1024) { $("#rules-file-status").textContent = "规则文件超过 1 MiB 上限。"; event.target.value = ""; return; }
    try {
      const parsed = JSON.parse(await file.text());
      if (!Array.isArray(parsed.rules)) throw new Error("缺少 rules 数组。");
      customRules = parsed.rules.slice(0, 100).filter(rule => rule && Array.isArray(rule.strings));
      $("#rules-file-status").textContent = "已加载 " + customRules.length + " 条本地规则。" + (currentFile ? "正在使用当前文件重新扫描。" : "选择 EXE 后扫描。");
      if (currentFile) start(currentFile);
    } catch (error) {
      customRules = []; event.target.value = "";
      $("#rules-file-status").textContent = "规则文件无法读取：" + error.message;
    }
  });
  $("#import-filter").addEventListener("input", event => { if (currentResult) drawImports(currentResult.pe.imports || [], event.target.value); });
  $("#string-filter").addEventListener("input", event => { if (currentResult) drawStrings(currentResult.strings || [], event.target.value); });
  $("#export-json").addEventListener("click", () => {
    if (!currentResult) return;
    const blob = new Blob([JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), ...currentResult }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob), link = document.createElement("a");
    link.href = url; link.download = currentResult.file.name.replace(/[^\w.-]+/g, "_") + ".analysis.json";
    document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
})();
