(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const input = $('apk-file');
  const dropZone = $('drop-zone');
  const statusBox = $('status');
  const results = $('results');
  const overviewChip = $('overview-chip');
  const overview = $('overview');
  const securityNotes = $('security-notes');
  const fileInfo = $('file-info');
  const hashList = $('hash-list');
  const signatureChip = $('signature-chip');
  const signatureSummary = $('signature-summary');
  const signatureSchemes = $('signature-schemes');
  const signerList = $('signer-list');
  const signatureWarnings = $('signature-warnings');
  const manifestChip = $('manifest-chip');
  const appInfo = $('app-info');
  const applicationFlags = $('application-flags');
  const componentCount = $('component-count');
  const componentGroups = $('component-groups');
  const permissions = $('permissions');
  const permissionCount = $('permission-count');
  const permissionToggle = $('permission-toggle');
  const declaredPermissionSection = $('declared-permission-section');
  const declaredPermissions = $('declared-permissions');
  const featureSection = $('feature-section');
  const featureList = $('feature-list');
  const manifestExtras = $('manifest-extras');
  const manifestExtraCount = $('manifest-extra-count');
  const manifestExtrasBody = $('manifest-extras-body');
  const inventoryChip = $('inventory-chip');
  const inventorySummary = $('inventory-summary');
  const inventoryKeyFiles = $('inventory-key-files');
  const inventoryMeta = $('inventory-meta');
  const inventoryDex = $('inventory-dex');
  const inventoryLibs = $('inventory-libs');
  const inventoryAssets = $('inventory-assets');
  const inventoryRaw = $('inventory-raw');
  const inventorySuspicious = $('inventory-suspicious');
  const inventoryOthers = $('inventory-others');
  const stringsChip = $('strings-chip');
  const secretHits = $('secret-hits');
  const networkHits = $('network-hits');
  const resourceStrings = $('resource-strings');
  const jadxStatus = $('jadx-status');
  const jadxVersion = $('jadx-version');
  const jadxUrlResults = $('jadx-url-results');
  const jadxUrlCount = $('jadx-url-count');
  const jadxUrlNote = $('jadx-url-note');
  const jadxUrls = $('jadx-urls');
  const urlsToggle = $('jadx-urls-toggle');
  const codeFindings = $('code-findings');
  const codeFindingsSection = $('code-findings-section');
  const codeFindingItems = $('code-finding-items');
  const codeFindingsToggle = $('code-findings-toggle');
  const codeFindingCount = $('code-finding-count');
  const analysisDuration = $('analysis-duration');
  const exportJsonButton = $('export-json');
  const copySummaryButton = $('copy-summary');
  const exportNote = $('export-note');

  const MAX_FILE = 1024 * 1024 * 1024;
  const state = {
    runId: 0,
    file: null,
    report: null,
    controller: null,
    inspectorDone: false,
    inspectorError: '',
    jadxDone: false,
    jadxError: '',
    jadxFindings: 0,
    jadxUrls: 0,
    progressMessage: '',
    progressPercent: 0
  };

  const permissionCatalog = {
    'INTERNET': ['访问网络', '允许应用建立网络连接并发送或接收数据。'],
    'ACCESS_NETWORK_STATE': ['查看网络状态', '允许应用查询当前网络连接状态。'],
    'ACCESS_WIFI_STATE': ['查看 Wi-Fi 状态', '允许应用查询 Wi-Fi 连接信息。'],
    'CHANGE_WIFI_STATE': ['更改 Wi-Fi 状态', '允许应用请求开启、关闭或配置 Wi-Fi。'],
    'CAMERA': ['使用摄像头', '允许应用访问摄像头拍摄照片或视频。'],
    'RECORD_AUDIO': ['录制音频', '允许应用通过麦克风录制音频。'],
    'ACCESS_FINE_LOCATION': ['获取精确位置', '允许应用获取较精确的设备位置信息。'],
    'ACCESS_COARSE_LOCATION': ['获取大致位置', '允许应用获取基于网络等来源的大致位置。'],
    'ACCESS_BACKGROUND_LOCATION': ['后台获取位置', '允许应用在后台持续访问设备位置。'],
    'READ_CONTACTS': ['读取联系人', '允许应用读取联系人信息。'],
    'WRITE_CONTACTS': ['修改联系人', '允许应用新增或修改联系人信息。'],
    'GET_ACCOUNTS': ['查看账号列表', '允许应用查看设备上配置的账号信息。'],
    'READ_CALENDAR': ['读取日历', '允许应用读取日历活动和日程。'],
    'WRITE_CALENDAR': ['修改日历', '允许应用新增或修改日历活动和日程。'],
    'READ_PHONE_STATE': ['读取电话状态', '允许应用读取设备电话状态及部分设备标识信息。'],
    'READ_PHONE_NUMBERS': ['读取电话号码', '允许应用读取设备或 SIM 卡关联的电话号码（系统和运营商支持时）。'],
    'CALL_PHONE': ['直接拨打电话', '允许应用发起电话呼叫，无需先打开拨号确认界面。'],
    'READ_CALL_LOG': ['读取通话记录', '允许应用读取通话记录。'],
    'WRITE_CALL_LOG': ['修改通话记录', '允许应用写入或修改通话记录。'],
    'SEND_SMS': ['发送短信', '允许应用发送短信，可能产生通信费用。'],
    'RECEIVE_SMS': ['接收短信', '允许应用接收短信。'],
    'READ_SMS': ['读取短信', '允许应用读取设备中的短信。'],
    'RECEIVE_MMS': ['接收彩信', '允许应用接收彩信。'],
    'POST_NOTIFICATIONS': ['发送通知', '允许应用向用户显示通知（Android 13 及以上需运行时授权）。'],
    'READ_EXTERNAL_STORAGE': ['读取共享存储', '允许应用读取共享存储中的文件；实际范围受 Android 版本影响。'],
    'WRITE_EXTERNAL_STORAGE': ['写入共享存储', '允许应用写入共享存储；新版本 Android 对此权限有范围限制。'],
    'MANAGE_EXTERNAL_STORAGE': ['管理所有文件', '允许应用广泛访问共享存储中的文件，属于特殊访问权限。'],
    'READ_MEDIA_IMAGES': ['读取图片', '允许应用读取共享存储中的图片。'],
    'READ_MEDIA_VIDEO': ['读取视频', '允许应用读取共享存储中的视频。'],
    'READ_MEDIA_AUDIO': ['读取音频', '允许应用读取共享存储中的音频文件。'],
    'READ_MEDIA_VISUAL_USER_SELECTED': ['读取用户选择的媒体', '允许应用访问用户在系统照片选择器中选定的图片或视频。'],
    'BLUETOOTH': ['使用蓝牙', '允许应用连接已配对的蓝牙设备（旧版蓝牙权限）。'],
    'BLUETOOTH_ADMIN': ['管理蓝牙连接', '允许应用发现和配对蓝牙设备（旧版蓝牙权限）。'],
    'BLUETOOTH_CONNECT': ['连接蓝牙设备', '允许应用连接已配对的蓝牙设备并访问其信息。'],
    'BLUETOOTH_SCAN': ['搜索蓝牙设备', '允许应用搜索附近的蓝牙设备；可能用于推断位置。'],
    'BLUETOOTH_ADVERTISE': ['广播蓝牙信号', '允许应用向附近设备广播自身信息。'],
    'NFC': ['使用 NFC', '允许应用通过近场通信与附近设备或标签交互。'],
    'VIBRATE': ['控制振动', '允许应用控制设备振动。'],
    'WAKE_LOCK': ['保持设备唤醒', '允许应用阻止设备进入休眠状态。'],
    'RECEIVE_BOOT_COMPLETED': ['开机后启动任务', '允许应用接收设备启动完成事件，以便安排后台任务。'],
    'FOREGROUND_SERVICE': ['运行前台服务', '允许应用运行带有持续通知的前台服务。'],
    'SYSTEM_ALERT_WINDOW': ['显示在其他应用上层', '允许应用创建覆盖其他应用的窗口，需用户在系统设置中授权。'],
    'REQUEST_INSTALL_PACKAGES': ['请求安装应用', '允许应用请求安装 APK；系统通常还要求用户确认并单独授权。'],
    'QUERY_ALL_PACKAGES': ['查询设备上的应用', '允许应用查询设备上广泛安装的应用列表。'],
    'PACKAGE_USAGE_STATS': ['查看应用使用情况', '允许应用读取应用使用统计，需用户在系统设置中授权。'],
    'USE_BIOMETRIC': ['使用生物识别', '允许应用请求系统生物识别认证。'],
    'USE_FINGERPRINT': ['使用指纹识别', '旧版指纹识别权限；新系统通常使用 USE_BIOMETRIC。'],
    'ACTIVITY_RECOGNITION': ['识别身体活动', '允许应用识别步行、骑行等身体活动状态。'],
    'BODY_SENSORS': ['读取身体传感器', '允许应用读取心率等身体传感器数据。'],
    'BODY_SENSORS_BACKGROUND': ['后台读取身体传感器', '允许应用在后台读取身体传感器数据。'],
    'SCHEDULE_EXACT_ALARM': ['设置精确闹钟', '允许应用安排精确触发的闹钟或定时任务，可能需用户授权。'],
    'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS': ['请求忽略电池优化', '允许应用请求加入电池优化例外名单。'],
    'CHANGE_NETWORK_STATE': ['更改网络连接', '允许应用请求切换网络连接状态。'],
    'FLASHLIGHT': ['使用闪光灯', '允许应用访问设备闪光灯。'],
    'KILL_BACKGROUND_PROCESSES': ['结束后台进程', '允许应用请求结束其他应用的后台进程。'],
    'BIND_ACCESSIBILITY_SERVICE': ['提供无障碍服务', '系统绑定权限；应用声明该权限表示可提供无障碍服务，需用户在设置中启用。'],
    'WRITE_SETTINGS': ['修改系统设置', '允许应用请求修改部分系统设置，通常需用户单独授权。']
  };
  function permissionDescription(name) {
    const shortName = String(name).split('.').pop();
    const known = permissionCatalog[shortName];
    if (known) return known;
    return [
      shortName.replaceAll('_', ' ').toLowerCase().replace(/\b\w/g, letter => letter.toUpperCase()),
      String(name).startsWith('android.permission.')
        ? 'Android 系统权限；具体保护范围取决于系统版本和权限级别。'
        : '应用或厂商定义的自定义权限；具体用途需结合应用代码或权限声明者确认。'
    ];
  }

  /* ------------------------------ 基础 UI ------------------------------ */

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  function clear(node) { if (node) node.replaceChildren(); }
  function empty(container, message) {
    container.append(el('p', 'apk-empty', message));
  }
  function chip(text, variant) {
    const node = el('span', 'apk-badge' + (variant ? ' is-' + variant : ''), text);
    return node;
  }
  function formatBytes(value) {
    if (!Number.isFinite(value)) return '—';
    const units = ['B', 'KiB', 'MiB', 'GiB'];
    let index = 0, size = value;
    while (size >= 1024 && index < units.length - 1) { size /= 1024; index++; }
    return (index === 0 ? String(size) : size.toFixed(size >= 100 ? 0 : size >= 10 ? 1 : 2)) + ' ' + units[index];
  }
  function formatElapsed(milliseconds) {
    const seconds = Math.max(0, Math.round(milliseconds / 1000));
    return seconds < 60 ? seconds + ' 秒' : Math.floor(seconds / 60) + ' 分 ' + (seconds % 60) + ' 秒';
  }
  function textOr(value, fallback) {
    return value === null || value === undefined || value === '' ? (fallback || '未声明') : String(value);
  }
  function addInfo(container, label, value, mono) {
    const item = el('div', 'apk-info-item');
    item.append(el('span', null, label));
    const strong = el('strong', mono ? 'apk-kv-inline' : null, textOr(value));
    item.append(strong);
    container.append(item);
  }
  function addField(container, label, value, mono) {
    const field = el('div', 'apk-field');
    field.append(el('dt', null, label));
    field.append(el('dd', mono ? 'mono' : null, textOr(value)));
    container.append(field);
  }
  function addFieldGrid(container, rows) {
    const grid = el('dl', 'apk-field-grid');
    for (const [label, value, mono] of rows) addField(grid, label, value, mono);
    container.append(grid);
  }
  function makeTable(headers, rows, options = {}) {
    const wrap = el('div', 'apk-table-wrap');
    const table = el('table', 'apk-table');
    const head = el('thead');
    const headRow = el('tr');
    for (const header of headers) headRow.append(el('th', null, header));
    head.append(headRow);
    table.append(head);
    const body = el('tbody');
    const monoColumns = new Set(options.mono || []);
    for (const row of rows) {
      const tr = el('tr');
      row.forEach((cell, index) => {
        const td = el('td', monoColumns.has(index) ? 'apk-mono' : null);
        if (cell instanceof Node) td.append(cell);
        else td.textContent = textOr(cell, '—');
        tr.append(td);
      });
      body.append(tr);
    }
    table.append(body);
    wrap.append(table);
    return wrap;
  }
  function makeBadgeList(items) {
    const wrap = el('div', 'apk-component-meta');
    for (const item of items) if (item) wrap.append(item);
    return wrap;
  }
  function addSubsection(container, title, chipText) {
    const section = el('div', 'apk-subsection');
    const heading = el('h3');
    heading.append(document.createTextNode(title));
    if (chipText !== undefined) heading.append(chip(chipText));
    section.append(heading);
    container.append(section);
    return section;
  }
  function addDetails(container, summaryText, contentBuilder) {
    const details = el('details', 'apk-details');
    const summary = el('summary', null, summaryText);
    details.append(summary);
    let built = false;
    details.addEventListener('toggle', () => {
      if (!details.open || built) return;
      built = true;
      const content = contentBuilder();
      if (content) details.append(content);
    });
    container.append(details);
    return details;
  }
  async function copyText(text, button) {
    const original = button.textContent;
    let copied = false;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        copied = true;
      }
    } catch {
      copied = false;
    }
    if (!copied) {
      try {
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.top = '-1000px';
        area.style.opacity = '0';
        document.body.append(area);
        area.select();
        copied = document.execCommand('copy');
        area.remove();
      } catch {
        copied = false;
      }
    }
    button.textContent = copied ? '已复制' : '复制失败';
    window.setTimeout(() => { button.textContent = original; }, 1600);
  }
  function addHashRow(container, label, value) {
    const row = el('div', 'apk-hash-row');
    row.append(el('span', null, label));
    row.append(el('code', null, value || '未计算'));
    if (value) {
      const button = el('button', 'apk-copy', '复制');
      button.type = 'button';
      button.addEventListener('click', () => copyText(value, button));
      row.append(button);
    }
    container.append(row);
  }
  function bindExpandButton(button, hasMore, update) {
    if (!button) return;
    button.hidden = !hasMore;
    button.classList.remove('is-expanded');
    button.setAttribute('aria-expanded', 'false');
    button.setAttribute('aria-label', button.dataset.collapsedLabel || '显示更多内容');
    button.onclick = null;
    if (!hasMore) return;
    let expanded = false;
    button.onclick = () => {
      expanded = !expanded;
      update(expanded);
      button.classList.toggle('is-expanded', expanded);
      button.setAttribute('aria-expanded', String(expanded));
      button.setAttribute('aria-label', expanded
        ? (button.dataset.expandedLabel || '收起更多内容')
        : (button.dataset.collapsedLabel || '显示更多内容'));
    };
  }
  function renderExpandableItems(container, items, limit, button) {
    container.replaceChildren();
    for (const item of items.slice(0, limit)) container.append(item);
    const extraItems = items.slice(limit);
    if (!extraItems.length) {
      bindExpandButton(button, false, () => {});
      return;
    }
    const extra = el('div', 'apk-extra-content');
    extra.hidden = true;
    for (const item of extraItems) extra.append(item);
    container.append(extra);
    bindExpandButton(button, true, expanded => { extra.hidden = !expanded; });
  }
  function showStatus(message, kind = '') {
    statusBox.hidden = false;
    statusBox.className = 'status' + (kind ? ' ' + kind : '');
    statusBox.textContent = message;
  }
  function showLoadingStatus(element, message) {
    element.className = 'status is-loading';
    const spinner = el('span', 'analysis-spinner');
    spinner.setAttribute('aria-hidden', 'true');
    element.replaceChildren(spinner, document.createTextNode(message));
  }

  /* ------------------------------ 概览与文件 ------------------------------ */

  function renderOverview(report) {
    overview.replaceChildren();
    const manifest = report.manifest;
    const signature = report.signature || {};
    const schemes = schemeList(signature);
    const certificate = (signature.certificates || [])[0];
    const zip = report.zip || {};
    const stats = report.statistics || {};
    const items = [
      {
        label: '文件', value: report.file.name,
        small: formatBytes(report.file.size) + ' · ' + (zip.parsedEntries || 0) + ' 个 ZIP 条目'
      },
      {
        label: '应用', value: manifest ? (manifest.appLabel?.text || manifest.package) : '未找到 Manifest',
        small: manifest ? manifest.package + ' · ' + textOr(manifest.versionName, '版本名未声明') + '（' + textOr(manifest.versionCode) + '）' : '可能不是 Android 应用包'
      },
      {
        label: '签名', value: schemes.length ? schemes.join(' + ') : '未发现签名方案',
        small: certificate ? ('证书：' + (certificate.subject || '未知主题')) + (signature.debugCertificate ? ' · 调试证书' : '') : '未读取到签名证书'
      },
      {
        label: 'SDK', value: manifest ? ('min ' + textOr(manifest.minSdk) + ' → target ' + textOr(manifest.targetSdk)) : '—',
        small: manifest ? ('compileSdk ' + textOr(manifest.compileSdkVersion) + (manifest.compileSdkVersionCodename ? '（' + manifest.compileSdkVersionCodename + '）' : '')) : '—'
      },
      {
        label: '组件', value: String(stats.components ?? '0'),
        small: manifest ? ('Activity ' + manifest.componentCount.activities + ' · Service ' + manifest.componentCount.services + ' · Receiver ' + manifest.componentCount.receivers + ' · Provider ' + manifest.componentCount.providers) : '—'
      },
      {
        label: '权限', value: String(stats.permissions ?? '0'),
        small: manifest ? ('自定义权限 ' + manifest.declaredPermissions.length + ' 项 · 入口 ' + (manifest.launchers.length || 0) + ' 个') : '—'
      },
      {
        label: '内容', value: (stats.dexFiles || 0) + ' DEX · ' + (stats.nativeLibs || 0) + ' SO · ' + (stats.assets || 0) + ' assets',
        small: '解压后 ' + formatBytes(zip.totalUncompressed || 0) + ' · ' + (zip.compressionMethods || []).map(item => item.name).join(' / ')
      },
      {
        label: '线索', value: (stats.secretHits || 0) + ' 条敏感字符串 · ' + (stats.urls || 0) + ' 个网址',
        small: (report.notes || []).length ? (report.notes.length + ' 条安全提示 · ' + (report.warnings || []).length + ' 条解析警告') : ((report.warnings || []).length + ' 条解析警告')
      }
    ];
    for (const item of items) {
      const card = el('div', 'apk-overview-item');
      card.append(el('span', null, item.label));
      card.append(el('strong', null, item.value));
      if (item.small) card.append(el('small', null, item.small));
      overview.append(card);
    }
    overviewChip.textContent = '静态检查用时 ' + formatElapsed(report.elapsed || 0);
    renderNotes(report);
  }

  function renderNotes(report) {
    securityNotes.replaceChildren();
    const notes = report.notes || [];
    for (const note of notes) {
      const card = el('div', 'apk-note');
      card.dataset.severity = note.severity || 'info';
      card.append(el('strong', null, note.title));
      card.append(el('p', null, note.detail));
      securityNotes.append(card);
    }
    const warnings = report.warnings || [];
    if (warnings.length) {
      const box = el('div', 'apk-warnings');
      box.append(el('strong', null, '解析警告（' + warnings.length + '）'));
      const list = el('ul');
      for (const warning of warnings.slice(0, 40)) list.append(el('li', null, warning));
      box.append(list);
      securityNotes.append(box);
    }
    if (!notes.length && !warnings.length) empty(securityNotes, '没有自动生成安全提示；仍请逐项核对签名、组件与敏感字符串。');
  }

  function renderFileInfo(report) {
    fileInfo.replaceChildren();
    const zip = report.zip || {};
    addInfo(fileInfo, '文件名称', report.file.name);
    addInfo(fileInfo, '文件大小', report.file.size + ' 字节（' + formatBytes(report.file.size) + '）');
    addInfo(fileInfo, '浏览器文件时间', report.file.lastModified ? new Date(report.file.lastModified).toISOString() : '浏览器未提供');
    addInfo(fileInfo, 'ZIP 条目数', zip.entryCount + (zip.parsedEntries !== zip.entryCount ? '（已解析 ' + zip.parsedEntries + '）' : ''));
    addInfo(fileInfo, '解压 / 压缩后大小', formatBytes(zip.totalUncompressed) + ' / ' + formatBytes(zip.totalCompressed));
    addInfo(fileInfo, 'ZIP 时间戳范围', (zip.timestamps?.first || '—') + ' ~ ' + (zip.timestamps?.last || '—'), true);
    addInfo(fileInfo, 'ZIP 注释', zip.comment ? zip.comment : '无（0 字节）');
    addInfo(fileInfo, 'ZIP64 / 加密条目', (zip.zip64 ? 'ZIP64' : '普通 ZIP') + ' / ' + ((zip.encryptedEntries || []).length || 0) + ' 个');
    addInfo(fileInfo, '重名条目', (zip.duplicateNames || []).length ? zip.duplicateNames.join('、') : '无');
    addInfo(fileInfo, '中央目录偏移', zip.centralDirectoryOffset, true);
    addInfo(fileInfo, 'EOCD 偏移', zip.eocdOffset, true);
    addInfo(fileInfo, 'APK Signing Block', report.signature?.apkSigningBlock?.present ? formatBytes(report.signature.apkSigningBlock.size) : '不存在');
    addInfo(fileInfo, '压缩方法', (zip.compressionMethods || []).map(item => item.name + ' × ' + item.count).join('；') || '—');

    hashList.replaceChildren();
    const hashes = report.hashes || {};
    if (hashes.error) {
      empty(hashList, '整包摘要计算失败：' + hashes.error);
    } else {
      addHashRow(hashList, 'MD5', hashes.md5);
      addHashRow(hashList, 'SHA-1', hashes.sha1);
      addHashRow(hashList, 'SHA-256', hashes.sha256);
      const meta = el('p', 'hint');
      meta.textContent = '处理 ' + formatBytes(hashes.bytes || 0) + '，用时 ' + ((hashes.milliseconds || 0) / 1000).toFixed(2) + ' 秒。';
      hashList.append(meta);
    }
  }

  /* ------------------------------ 签名 ------------------------------ */

  function schemeList(signature) {
    const list = [];
    if (signature?.schemes?.v1?.present) list.push('v1 JAR');
    if (signature?.schemes?.v2?.present) list.push('v2');
    if (signature?.schemes?.v3?.present) list.push('v3');
    if (signature?.schemes?.v3_1?.present) list.push('v3.1');
    if (signature?.schemes?.sourceStamp?.present) list.push('SourceStamp');
    return list;
  }
  function renderSignature(report) {
    const signature = report.signature || {};
    const schemes = signature.schemes || {};
    signatureSummary.replaceChildren();
    const chips = [
      ['v1 JAR', schemes.v1?.present],
      ['v2', schemes.v2?.present],
      ['v3', schemes.v3?.present],
      ['v3.1', schemes.v3_1?.present],
      ['SourceStamp', schemes.sourceStamp?.present]
    ];
    for (const [label, present] of chips) {
      signatureSummary.append(chip(label, present ? 'accent' : 'muted'));
    }
    if (signature.apkSigningBlock?.present) signatureSummary.append(chip('签名块 ' + formatBytes(signature.apkSigningBlock.size), 'muted'));
    if (signature.debugCertificate) signatureSummary.append(chip('调试证书', 'exported'));
    if (signature.schemeMismatch) signatureSummary.append(chip('v2/v3 证书不一致', 'exported'));
    signatureChip.textContent = schemeList(signature).length ? schemeList(signature).join(' · ') : '未发现签名';
    signatureSchemes.replaceChildren();

    if (schemes.v1?.present) {
      const card = el('div', 'apk-scheme');
      card.append(el('strong', null, 'v1 · JAR 签名'));
      const manifestFile = schemes.v1.manifest;
      card.append(el('p', null, '签名文件 ' + (schemes.v1.signatureFiles || []).filter(file => file.blockType !== 'SF').length + ' 个' +
        (manifestFile ? ' · MANIFEST.MF 条目 ' + manifestFile.entries : '') +
        (manifestFile?.headers?.['Created-By'] ? ' · Created-By ' + manifestFile.headers['Created-By'] : '') +
        ' · 仅读取签名文件，未校验其有效性'));
      if (manifestFile) {
        addDetails(card, '查看 MANIFEST.MF 与 .SF 文件', () => {
          const rows = (schemes.v1.signatureFiles || []).map(file => [
            file.path,
            file.blockType,
            file.size,
            file.sha256 ? file.sha256.slice(0, 32) + '…' : '—',
            (file.digestAlgorithms || []).join('；') || '—',
            (file.signerInfos || []).map(info => (info.digestAlgorithmName || info.digestAlgorithm || '?') + ' / ' + (info.signatureAlgorithmName || info.signatureAlgorithm || '?')).join('；') || '—'
          ]);
          return makeTable(['文件', '类型', '大小', 'SHA-256', '摘要算法', '签名算法'], rows, { mono: [0, 3] });
        });
      }
      const apkSignedClaims = (schemes.v1.signatureFiles || [])
        .map(file => file.sfHeaders?.['X-Android-APK-Signed'])
        .filter(Boolean);
      if (apkSignedClaims.length) card.append(el('p', null, 'X-Android-APK-Signed 声明：' + [...new Set(apkSignedClaims)].join('；')));
      signatureSchemes.append(card);
    }
    if (schemes.v2?.present) {
      const card = el('div', 'apk-scheme');
      card.append(el('strong', null, 'v2 · APK Signature Scheme'));
      const signers = schemes.v2.signers || [];
      const algorithms = [...new Set(signers.flatMap(signer => [...(signer.digestAlgorithms || []), ...(signer.signatureAlgorithms || [])]))];
      card.append(el('p', null, signers.length + ' 个签名者 · ' + (algorithms.join(' / ') || '算法未识别')));
      const attrs = signers.flatMap(signer => signer.attributes || []);
      if (attrs.length) card.append(el('p', null, '附加属性：' + attrs.map(attr => attr.name + (attr.schemes ? '（' + attr.schemes.join(',') + '）' : '')).join('；')));
      signatureSchemes.append(card);
    }
    if (schemes.v3?.present || schemes.v3_1?.present) {
      const card = el('div', 'apk-scheme');
      const target = schemes.v3?.present ? schemes.v3 : schemes.v3_1;
      const label = schemes.v3?.present ? 'v3' : 'v3.1';
      card.append(el('strong', null, label + ' · APK Signature Scheme'));
      const signers = target.signers || [];
      const algorithms = [...new Set(signers.flatMap(signer => [...(signer.digestAlgorithms || []), ...(signer.signatureAlgorithms || [])]))];
      const ranges = signers.map(signer => (signer.minSdk ?? '?') + '–' + (signer.maxSdk === 2147483647 ? '∞' : (signer.maxSdk ?? '?'))).join('、');
      card.append(el('p', null, signers.length + ' 个签名者 · 适用 SDK ' + (ranges || '未声明') + ' · ' + (algorithms.join(' / ') || '算法未识别')));
      const rotation = signers.some(signer => (signer.attributes || []).some(attr => attr.id === 0x3ba06f8c));
      if (rotation) card.append(el('p', null, '包含签名轮换证明属性（未展开历史证书谱系）。'));
      signatureSchemes.append(card);
    }
    const blockPairs = signature.apkSigningBlock?.pairs || [];
    if (signature.apkSigningBlock?.present && blockPairs.length) {
      addDetails(signatureSchemes, 'APK Signing Block 条目（' + blockPairs.length + '）', () => makeTable(
        ['ID', '方案', '值大小'],
        blockPairs.map(pair => [pair.idHex, pair.scheme || '未知', formatBytes(pair.size)]),
        { mono: [0] }
      ));
    }

    signerList.replaceChildren();
    const certificates = signature.certificates || [];
    if (!certificates.length) {
      empty(signerList, signature.error ? ('签名解析失败：' + signature.error) : '没有读取到签名证书；APK 可能未签名，或使用了不支持的自定义签名方案。');
    }
    certificates.forEach((cert, index) => {
      const card = el('article', 'apk-signer');
      const header = el('header');
      header.append(el('strong', null, '证书 ' + (index + 1) + ' · ' + (cert.subject || '未知主题')));
      for (const scheme of cert.schemes || []) header.append(chip(scheme, 'accent'));
      if (cert.debugLike) header.append(chip('调试证书', 'exported'));
      if (cert.selfSigned) header.append(chip('自签名', 'muted'));
      card.append(header);
      addFieldGrid(card, [
        ['主题（Subject）', cert.subject],
        ['颁发者（Issuer）', cert.issuer],
        ['序列号', cert.serial, true],
        ['版本', cert.version],
        ['签名算法', cert.signatureAlgorithm],
        ['公钥', cert.publicKey],
        ['有效期起始', cert.notBefore + (cert.notBeforeRaw ? ' · 原始值 ' + cert.notBeforeRaw : '')],
        ['有效期截止', cert.notAfter + (cert.notAfterRaw ? ' · 原始值 ' + cert.notAfterRaw : '')],
        ['有效期状态', cert.validityState],
        ['Basic Constraints', cert.ca === null ? '扩展不存在' : (cert.ca ? 'CA: TRUE' : 'CA: FALSE')],
        ['Key Usage', (cert.keyUsage || []).join('、') || '未声明'],
        ['SHA-256 指纹', cert.fingerprintSha256, true],
        ['SHA-1 指纹', cert.fingerprintSha1, true],
        ['MD5 指纹', cert.fingerprintMd5, true],
        ['公钥 SHA-256', cert.publicKeySha256, true],
        ['公钥 SHA-1', cert.publicKeySha1, true],
        ['DER 长度', cert.derLength + ' 字节']
      ]);
      signerList.append(card);
    });

    const warnings = signature.warnings || [];
    signatureWarnings.hidden = !warnings.length;
    signatureWarnings.replaceChildren();
    if (warnings.length) {
      signatureWarnings.append(el('strong', null, '签名解析警告（' + warnings.length + '）'));
      const list = el('ul');
      for (const warning of warnings) list.append(el('li', null, warning));
      signatureWarnings.append(list);
    }
  }

  /* ------------------------------ Manifest ------------------------------ */

  const INSTALL_LOCATIONS = { 0: 'auto（由系统决定）', 1: 'internalOnly（仅内部存储）', 2: 'preferExternal（优先外部存储）' };
  function renderManifest(report) {
    const manifest = report.manifest;
    const appPanel = appInfo.closest('section');
    if (!manifest) {
      appPanel.hidden = true;
      componentGroups.closest('section').hidden = true;
      permissions.closest('section').hidden = true;
      manifestExtras.hidden = true;
      return;
    }
    appPanel.hidden = false;
    componentGroups.closest('section').hidden = false;
    permissions.closest('section').hidden = false;
    manifestExtras.hidden = false;
    manifestChip.textContent = 'AndroidManifest.xml · ' + (report.manifestFile?.size || 0) + ' 字节';
    appInfo.replaceChildren();
    const label = manifest.appLabel;
    addInfo(appInfo, '应用名称', label ? label.text : '未解析');
    addInfo(appInfo, '包名', manifest.package);
    addInfo(appInfo, '版本名称', manifest.versionName);
    addInfo(appInfo, '版本号', manifest.versionCode === null ? null : manifest.versionCode + (manifest.versionCodeMajor ? '（major ' + manifest.versionCodeMajor + '）' : ''));
    addInfo(appInfo, '最低兼容 API（minSdkVersion）', manifest.minSdk);
    addInfo(appInfo, '目标 API（targetSdkVersion）', manifest.targetSdk);
    addInfo(appInfo, '最高 API（maxSdkVersion）', manifest.maxSdk);
    addInfo(appInfo, '编译 API（compileSdkVersion）', manifest.compileSdkVersion === null ? null : manifest.compileSdkVersion + (manifest.compileSdkVersionCodename ? '（' + manifest.compileSdkVersionCodename + '）' : ''));
    addInfo(appInfo, '构建平台版本', manifest.platformBuildVersionName ? manifest.platformBuildVersionName + '（' + manifest.platformBuildVersionCode + '）' : null);
    addInfo(appInfo, '安装位置', manifest.installLocation === null ? null : (INSTALL_LOCATIONS[manifest.installLocation] || String(manifest.installLocation)));
    addInfo(appInfo, '应用入口类', manifest.application?.className);
    addInfo(appInfo, '图标资源', manifest.appIcon?.text);
    if (manifest.appIcon?.file) {
      addInfo(appInfo, '图标文件大小', formatBytes(manifest.appIcon.file.size));
      addInfo(appInfo, '图标文件 SHA-256', manifest.appIcon.file.sha256, true);
    }
    addInfo(appInfo, '主 Activity', manifest.launchers.length ? manifest.launchers.join('\n') : '未发现 LAUNCHER 入口');
    addInfo(appInfo, '共享用户 ID', manifest.sharedUserId);
    addInfo(appInfo, 'Manifest 命名空间', (report.manifestDocument?.namespaces || []).map(item => item.prefix + '=' + item.uri).join('；'));

    applicationFlags.replaceChildren();
    const app = manifest.application || {};
    const booleanLabels = {
      debuggable: '可调试', allowBackup: '允许备份', usesCleartextTraffic: '允许明文流量', extractNativeLibs: '解压原生库',
      requestLegacyExternalStorage: '遗留存储模式', preserveLegacyExternalStorage: '保留遗留存储', testOnly: '仅测试',
      hardwareAccelerated: '硬件加速', largeHeap: '大堆内存', persistent: '常驻进程', enabled: '启用组件',
      allowTaskReparenting: '允许任务重定父', directBootAware: '直接启动感知', defaultToDeviceProtectedStorage: '默认设备加密存储',
      hasCode: '包含代码', killAfterRestore: '恢复后结束', restoreAnyVersion: '允许恢复任意版本', supportsRtl: '支持 RTL',
      resizeableActivity: '可调整窗口', supportsPictureInPicture: '支持画中画', allowAudioPlaybackCapture: '允许音频捕获',
      enableOnBackInvokedCallback: '启用预测性返回', allowNativeHeapPointerTagging: '原生堆指针标记', usesNonSdkApi: '使用非 SDK 接口',
      requestRawExternalStorageAccess: '原始外部存储访问'
    };
    let declared = 0, undeclared = 0;
    for (const [field, labelText] of Object.entries(booleanLabels)) {
      const value = app[field];
      if (value === null || value === undefined) { undeclared++; continue; }
      declared++;
      const tag = el('span', 'apk-tag ' + (value ? 'is-on' : 'is-off'));
      tag.append(el('b', null, labelText));
      tag.append(document.createTextNode(value ? '开启' : '关闭'));
      applicationFlags.append(tag);
    }
    if (!declared) empty(applicationFlags, 'Manifest 未显式声明可识别的布尔属性。');
    if (undeclared) applicationFlags.append(el('span', 'apk-tag is-unknown', undeclared + ' 项布尔属性未声明'));
    const textFields = [
      ['theme', '主题'], ['description', '描述'], ['appComponentFactory', '组件工厂'],
      ['backupAgent', '备份代理'], ['manageSpaceActivity', '空间管理 Activity'],
      ['networkSecurityConfig', '网络安全配置'], ['dataExtractionRules', '数据提取规则'],
      ['fullBackupContent', '完整备份规则'], ['classLoader', '类加载器'], ['localeConfig', '语言配置'],
      ['process', '进程名']
    ];
    for (const [field, labelText] of textFields) {
      if (!app[field]) continue;
      const tag = el('span', 'apk-tag');
      tag.append(el('b', null, labelText));
      tag.append(document.createTextNode(app[field]));
      applicationFlags.append(tag);
    }
    const extraKeys = Object.keys(app.attributes || {});
    if (extraKeys.length) {
      addDetails(applicationFlags, '其他 application 属性（' + extraKeys.length + '）', () => {
        const rows = extraKeys.map(key => [key, app.attributes[key]]);
        return makeTable(['属性', '值'], rows, { mono: [0] });
      });
    }
    const extras = [
      manifest.protectedBroadcasts?.length ? ['protected-broadcast', manifest.protectedBroadcasts.join('、')] : null
    ].filter(Boolean);
    if (extras.length) addDetails(applicationFlags, '其他清单声明', () => makeTable(['项目', '值'], extras));
  }

  /* ------------------------------ 组件 ------------------------------ */

  function riskBadge(component) {
    if (!component.exported) return chip('未导出', 'muted');
    if (component.risk === 'exported-with-permission') return chip('导出 · 有权限', 'protected');
    return chip('导出 · 无权限', 'exported');
  }
  function componentCard(component) {
    const card = el('article', 'apk-component');
    const header = el('div', 'apk-component-header');
    header.append(el('span', 'apk-component-name', component.name || component.shortName || '（未命名）'));
    header.append(riskBadge(component));
    if (component.launcher) header.append(chip('LAUNCHER', 'accent'));
    if (component.type === 'activity-alias') header.append(chip('activity-alias', 'muted'));
    if (component.enabled === false) header.append(chip('已禁用', 'exported'));
    card.append(header);
    const meta = [];
    if (component.type === 'provider' && component.authorities) meta.push(chip('authorities: ' + component.authorities));
    if (component.permission) meta.push(chip('permission: ' + component.permission));
    if (component.readPermission) meta.push(chip('readPermission: ' + component.readPermission));
    if (component.writePermission) meta.push(chip('writePermission: ' + component.writePermission));
    if (component.launchMode) meta.push(chip('launchMode: ' + component.launchMode));
    if (component.screenOrientation && component.screenOrientation !== 'unspecified') meta.push(chip('orientation: ' + component.screenOrientation));
    if (component.taskAffinity) meta.push(chip('taskAffinity: ' + component.taskAffinity));
    if (component.process) meta.push(chip('process: ' + component.process));
    if (component.directBootAware) meta.push(chip('directBootAware'));
    if (component.targetActivity) meta.push(chip('target: ' + component.targetActivity));
    if (component.grantUriPermissions) meta.push(chip('grantUriPermissions'));
    if (meta.length) {
      const metaWrap = el('div', 'apk-component-meta');
      for (const item of meta) metaWrap.append(item);
      card.append(metaWrap);
    }
    if (component.label) card.append(el('p', 'apk-component-line', 'label：' + component.label));
    if (component.targetSdk31Note) card.append(el('p', 'apk-component-line', '⚠ ' + component.targetSdk31Note));
    if (component.exported && component.exportedDeclared === null) card.append(el('p', 'apk-component-line', '导出状态：' + component.exportReason));
    if (!component.intentFilters.length) return card;
    for (const filter of component.intentFilters) {
      const line = el('ul', 'apk-component-filters');
      const parts = [];
      if (filter.actions.length) parts.push('action: ' + filter.actions.join(', '));
      if (filter.categories.length) parts.push('category: ' + filter.categories.join(', '));
      if (filter.data.length) parts.push('data: ' + filter.data.map(item => Object.entries(item).map(([key, value]) => key + '=' + value).join('&')).join(' | '));
      if (filter.autoVerify !== null) parts.push('autoVerify: ' + filter.autoVerify);
      if (filter.priority !== null) parts.push('priority: ' + filter.priority);
      line.append(el('li', null, parts.join('；')));
      card.append(line);
    }
    return card;
  }
  function renderComponents(report) {
    componentGroups.replaceChildren();
    const manifest = report.manifest;
    if (!manifest) return;
    const groups = [
      ['Activity', [...manifest.activities, ...manifest.activityAliases]],
      ['Service', manifest.services],
      ['Receiver', manifest.receivers],
      ['Provider', manifest.providers]
    ];
    const total = groups.reduce((sum, [, items]) => sum + items.length, 0);
    componentCount.textContent = total + ' 个组件';
    let shown = false;
    for (const [name, items] of groups) {
      if (!items.length) continue;
      shown = true;
      const group = el('div', 'apk-component-group');
      const heading = el('h3');
      heading.append(document.createTextNode(name));
      heading.append(chip(String(items.length)));
      group.append(heading);
      const list = el('div');
      const cards = items.map(componentCard);
      for (const card of cards.slice(0, 10)) list.append(card);
      if (cards.length > 10) {
        const extra = el('div', 'apk-extra-content');
        extra.hidden = true;
        for (const card of cards.slice(10)) extra.append(card);
        list.append(extra);
        const toggleWrap = el('div');
        const toggle = el('button', 'apk-copy', '显示全部 ' + cards.length + ' 个' + name);
        toggle.type = 'button';
        toggle.addEventListener('click', () => {
          const open = extra.hidden;
          extra.hidden = !open;
          toggle.textContent = open ? '收起' : '显示全部 ' + cards.length + ' 个' + name;
        });
        toggleWrap.append(toggle);
        list.append(toggleWrap);
      }
      group.append(list);
      componentGroups.append(group);
    }
    if (!shown) empty(componentGroups, 'Manifest 没有声明 Activity、Service、Receiver 或 Provider。');
  }

  /* ------------------------------ 权限 ------------------------------ */

  function renderPermissions(report) {
    const manifest = report.manifest;
    permissions.replaceChildren();
    const rows = manifest?.usesPermissions || [];
    permissionCount.textContent = rows.length + ' 项';
    const items = rows.map(permission => {
      const row = el('div', 'apk-permission');
      const [label, explanation] = permissionDescription(permission.name);
      const heading = el('div', 'apk-permission-title');
      heading.append(el('strong', null, label));
      heading.append(el('code', null, permission.name));
      if (permission.sdk23) heading.append(chip('sdk-23', 'muted'));
      if (permission.maxSdkVersion !== null) heading.append(chip('maxSdk ' + permission.maxSdkVersion, 'muted'));
      if (!String(permission.name).startsWith('android.permission.')) heading.append(chip('自定义', 'accent'));
      row.append(heading);
      row.append(el('p', null, explanation));
      return row;
    });
    if (!items.length) {
      empty(permissions, 'Manifest 未声明 uses-permission 权限。');
      bindExpandButton(permissionToggle, false, () => {});
    } else {
      renderExpandableItems(permissions, items, 6, permissionToggle);
    }

    declaredPermissionSection.hidden = !manifest?.declaredPermissions?.length;
    declaredPermissions.replaceChildren();
    if (manifest?.declaredPermissions?.length) {
      const tableRows = manifest.declaredPermissions.map(item => [
        item.name,
        item.label,
        item.protectionLevel?.text || '未声明',
        item.permissionGroup,
        item.backgroundPermission,
        item.description
      ]);
      declaredPermissions.append(makeTable(['权限名称', '标签', '保护级别', '权限组', '后台权限', '说明'], tableRows, { mono: [0] }));
    }

    const features = manifest?.features || [];
    const libraries = [...(manifest?.libraries || []), ...(manifest?.nativeLibraries || []).map(item => ({ ...item, native: true }))];
    featureSection.hidden = !features.length && !libraries.length;
    featureList.replaceChildren();
    if (features.length) {
      featureList.append(el('h4', null, 'uses-feature'));
      featureList.append(makeTable(['功能', '必需', '版本', 'OpenGL ES'], features.map(item => [
        item.name || '（仅声明 GLES）',
        item.required === null ? '默认 true' : String(item.required),
        item.version,
        item.glEsVersion
      ])));
    }
    if (libraries.length) {
      featureList.append(el('h4', null, 'uses-library / uses-native-library'));
      featureList.append(makeTable(['库', '必需', '版本'], libraries.map(item => [
        item.name,
        item.required === null ? '默认 true' : String(item.required),
        item.version
      ])));
    }
  }

  /* ------------------------------ 清单其他 ------------------------------ */

  function renderManifestExtras(report) {
    const manifest = report.manifest;
    manifestExtrasBody.replaceChildren();
    if (!manifest) return;
    let count = 0;
    const metaData = manifest.metaData || [];
    if (metaData.length) {
      count += metaData.length;
      const section = addSubsection(manifestExtrasBody, 'meta-data', String(metaData.length));
      section.append(makeTable(['名称', '值', '资源引用'], metaData.map(item => [item.name, item.value, item.resourceReference || item.resource]), { mono: [0] }));
    }
    const queries = manifest.queries || { packages: [], providers: [], intents: [] };
    const queryRows = [
      ...queries.packages.map(name => ['package', name]),
      ...queries.providers.map(name => ['provider', name]),
      ...queries.intents.map(actions => ['intent', actions.join(', ')])
    ];
    if (queryRows.length) {
      count += queryRows.length;
      const section = addSubsection(manifestExtrasBody, 'queries（可见性声明）', String(queryRows.length));
      section.append(makeTable(['类型', '目标'], queryRows, { mono: [1] }));
    }
    if (manifest.supportsScreens) {
      count++;
      const section = addSubsection(manifestExtrasBody, 'supports-screens');
      section.append(makeTable(['属性', '值'], Object.entries(manifest.supportsScreens).map(([key, value]) => [key, String(value)])));
    }
    if (manifest.supportsGlTextures.length) {
      count += manifest.supportsGlTextures.length;
      const section = addSubsection(manifestExtrasBody, 'supports-gl-texture');
      section.append(makeTable(['纹理格式'], manifest.supportsGlTextures.map(name => [name]), { mono: [0] }));
    }
    if (manifest.instrumentations.length) {
      count += manifest.instrumentations.length;
      const section = addSubsection(manifestExtrasBody, 'instrumentation', String(manifest.instrumentations.length));
      section.append(makeTable(['名称', '目标包', '功能测试'], manifest.instrumentations.map(item => [item.name, item.targetPackage, String(item.functionalTest)]), { mono: [0] }));
    }
    if (manifest.usesConfiguration) {
      count++;
      const section = addSubsection(manifestExtrasBody, 'uses-configuration');
      section.append(makeTable(['属性', '值'], Object.entries(manifest.usesConfiguration).map(([key, value]) => [key, value])));
    }
    if (manifest.sdkExtensions?.length) {
      count += manifest.sdkExtensions.length;
      const section = addSubsection(manifestExtrasBody, 'SDK 扩展');
      section.append(makeTable(['SDK', '最低扩展版本'], manifest.sdkExtensions.map(item => [item.sdk, item.minExtension]), { mono: [0] }));
    }
    if (manifest.permissionGroups.length) {
      count += manifest.permissionGroups.length;
      const section = addSubsection(manifestExtrasBody, '权限组 / 权限树', String(manifest.permissionGroups.length));
      section.append(makeTable(['类型', '名称', '标签'], manifest.permissionGroups.map(item => [item.type, item.name, item.label]), { mono: [1] }));
    }
    if (manifest.rawXml) {
      const section = addSubsection(manifestExtrasBody, '解码后的 AndroidManifest.xml');
      addDetails(section, '显示 XML 文本（' + formatBytes(manifest.rawXml.length) + '）', () => {
        const pre = el('pre', 'apk-preview', manifest.rawXml);
        return pre;
      });
    }
    manifestExtraCount.textContent = count + ' 项';
  }

  /* ------------------------------ 内容清单 ------------------------------ */

  function renderInventory(report) {
    const inventory = report.inventory || {};
    const counts = inventory.counts || {};
    inventorySummary.replaceChildren();
    const groups = inventory.topLevel || [];
    inventoryChip.textContent = (report.zip?.parsedEntries || 0) + ' 个条目';
    for (const group of groups) {
      const item = el('div', 'apk-inventory-item');
      item.append(el('span', null, group.name));
      item.append(el('strong', null, group.count + ' 个'));
      item.append(el('small', null, formatBytes(group.size)));
      inventorySummary.append(item);
    }
    if (!groups.length) empty(inventorySummary, '没有可显示的条目统计。');

    inventoryKeyFiles.replaceChildren();
    const keyFiles = inventory.keyFiles || [];
    if (keyFiles.length) {
      addSubsection(inventoryKeyFiles, '关键文件摘要（SHA-256）', String(keyFiles.length));
      inventoryKeyFiles.append(makeTable(['文件', '大小', 'SHA-256'], keyFiles.map(file => [file.name, formatBytes(file.size), file.sha256 || '未计算']), { mono: [0, 2] }));
    }

    inventoryMeta.replaceChildren();
    const metaInf = inventory.metaInf || [];
    if (metaInf.length) {
      addSubsection(inventoryMeta, 'META-INF 文件', String(counts.metaInf || metaInf.length));
      inventoryMeta.append(makeTable(['路径', '大小', '压缩方法'], metaInf.map(item => [item.name, formatBytes(item.size), item.method === 0 ? 'stored' : 'deflate (' + item.method + ')']), { mono: [0] }));
    }
    const metaVersions = inventory.metaVersions || [];
    if (metaVersions.length) {
      addDetails(inventoryMeta, '依赖/构建版本标记（' + metaVersions.length + '）', () => makeTable(
        ['文件', '值'],
        metaVersions.map(item => [item.name, item.value]),
        { mono: [0, 1] }
      ));
    }

    inventoryDex.replaceChildren();
    const dex = report.dex || [];
    if (dex.length) {
      addSubsection(inventoryDex, 'DEX 字节码', String(dex.length));
      inventoryDex.append(makeTable(['文件', '版本', '大小', '类', '方法', '字符串', '校验'], dex.map(item => [
        item.name,
        item.version || '—',
        formatBytes(item.size),
        item.classes ?? '—',
        item.methods ?? '—',
        item.stringsScanned ?? '—',
        item.checksumValid === null ? '—' : (item.checksumValid && item.sha1Valid ? '校验和与 SHA-1 一致' : '校验和不一致')
      ]), { mono: [0] }));
      if (dex.some(item => item.scanSkipped)) inventoryDex.append(el('p', 'hint', '部分 DEX 因超过扫描上限未读取字符串，已在上方警告中说明。'));
    }

    inventoryLibs.replaceChildren();
    const libs = inventory.nativeLibs || [];
    if (libs.length) {
      addSubsection(inventoryLibs, '原生库（.so）' + (counts.nativeLibs > libs.length ? '（显示 ' + libs.length + ' / 共 ' + counts.nativeLibs + '）' : ''), String(libs.length));
      inventoryLibs.append(makeTable(['路径', 'ABI', '架构', '大小', 'SHA-256'], libs.map(item => [
        item.name,
        item.abi,
        item.elf ? (item.elf.machine + ' · ' + item.elf.bits + ' 位 · ' + item.elf.endian) : '—',
        formatBytes(item.size),
        item.sha256 || '未计算'
      ]), { mono: [0] }));
    }

    inventoryAssets.replaceChildren();
    const assets = inventory.assets || [];
    if (assets.length) {
      addSubsection(inventoryAssets, 'assets 清单' + (counts.assets > assets.length ? '（显示 ' + assets.length + ' / 共 ' + counts.assets + '）' : ''), String(assets.length));
      const rows = assets.map(item => {
        const findings = [];
        if (item.findings?.length) findings.push(chip(item.findings.join(' / '), 'exported'));
        if (item.note) findings.push(chip('截断', 'muted'));
        if (item.error) findings.push(chip('读取失败', 'exported'));
        const line = el('div', 'apk-component-meta');
        for (const badge of findings) line.append(badge);
        return [
          item.name,
          formatBytes(item.size),
          item.kind || '—',
          item.sha256 || '未计算',
          line
        ];
      });
      const table = makeTable(['路径', '大小', '类型', 'SHA-256', '线索'], rows, { mono: [0, 3] });
      inventoryAssets.append(table);
      for (const item of assets.filter(asset => asset.preview)) {
        addDetails(inventoryAssets, '预览 ' + item.name, () => el('pre', 'apk-preview', item.preview));
      }
    }

    inventoryRaw.replaceChildren();
    const raw = inventory.raw || [];
    if (raw.length) {
      addSubsection(inventoryRaw, 'res/raw 文件' + (counts.raw > raw.length ? '（显示 ' + raw.length + ' / 共 ' + counts.raw + '）' : ''), String(raw.length));
      inventoryRaw.append(makeTable(['路径', '大小', '类型', 'SHA-256'], raw.map(item => [item.name, formatBytes(item.size), item.kind || '—', item.sha256 || '未计算']), { mono: [0, 3] }));
      for (const item of raw.filter(asset => asset.preview)) {
        addDetails(inventoryRaw, '预览 ' + item.name, () => el('pre', 'apk-preview', item.preview));
      }
    }

    inventorySuspicious.replaceChildren();
    const suspicious = inventory.suspicious || [];
    if (suspicious.length) {
      addSubsection(inventorySuspicious, '需要留意的条目', String(suspicious.length));
      inventorySuspicious.append(makeTable(['路径', '大小', '原因'], suspicious.map(item => [
        item.name,
        formatBytes(item.size),
        item.reasons.join('；')
      ]), { mono: [0] }));
    }

    inventoryOthers.replaceChildren();
    const others = inventory.others || [];
    if (others.length) {
      addSubsection(inventoryOthers, '其他根目录文件', String(others.length));
      inventoryOthers.append(makeTable(['路径', '大小'], others.map(item => [item.name, formatBytes(item.size)]), { mono: [0] }));
    }
    if (!libs.length && !assets.length && !raw.length && !suspicious.length) {
      const section = addSubsection(inventoryAssets, '内容提示');
      section.append(el('p', 'hint', '没有 assets、res/raw 或原生库条目。'));
    }
  }

  /* ------------------------------ 字符串与线索 ------------------------------ */

  function renderStrings(report) {
    const strings = report.strings || {};
    const secrets = strings.secrets || [];
    const urls = strings.urls || [];
    const ips = strings.ips || [];
    const emails = strings.emails || [];
    const paths = strings.paths || [];
    stringsChip.textContent = (secrets.length + urls.length + ips.length + emails.length + paths.length) + ' 条线索';
    secretHits.replaceChildren();
    if (secrets.length) {
      addSubsection(secretHits, '敏感字符串命中', String(secrets.length));
      secretHits.append(makeTable(['类型', '匹配内容', '来源'], secrets.map(item => [
        item.label,
        item.value,
        item.source
      ]), { mono: [1, 2] }));
    } else {
      empty(secretHits, '未命中 Flag、密钥、口令或令牌形式的字符串。未命中不代表不存在：运行时拼接、加密或网络下发的内容无法静态发现。');
    }

    networkHits.replaceChildren();
    if (urls.length || ips.length || emails.length || paths.length) {
      const section = addSubsection(networkHits, '网络与路径线索');
      if (urls.length) {
        section.append(el('h4', null, '静态网址（' + urls.length + '）'));
        section.append(makeTable(['网址', '来源'], urls.slice(0, 100).map(item => [item.value, item.source]), { mono: [0, 1] }));
        if (urls.length > 100) section.append(el('p', 'hint', '仅显示前 100 个网址，完整列表在 JSON 报告中。'));
      }
      if (ips.length) {
        section.append(el('h4', null, 'IP 地址（' + ips.length + '）'));
        section.append(makeTable(['IP', '类型', '来源'], ips.map(item => [item.value, item.private ? '私有/保留' : '公网', item.source]), { mono: [0] }));
      }
      if (emails.length) {
        section.append(el('h4', null, '邮箱地址（' + emails.length + '）'));
        section.append(makeTable(['邮箱', '来源'], emails.map(item => [item.value, item.source]), { mono: [0, 1] }));
      }
      if (paths.length) {
        section.append(el('h4', null, '文件路径线索（' + paths.length + '）'));
        section.append(makeTable(['路径', '来源'], paths.map(item => [item.value, item.source]), { mono: [0, 1] }));
      }
    } else {
      empty(networkHits, '没有从 Manifest、资源字符串、assets 或 DEX 字符串中提取到网址、IP、邮箱或存储路径。');
    }

    resourceStrings.replaceChildren();
    const resources = report.resources;
    if (resources) {
      const section = addSubsection(resourceStrings, '资源字符串（resources.arsc）', resources.totalStrings + ' 条');
      section.append(el('p', 'hint', '共收集 ' + resources.collected + ' 条字符串（按语言/配置去重，超出上限会截断）；语言配置：' + (resources.locales || []).slice(0, 12).map(item => item.name + '(' + item.count + ')').join('、') + (resources.locales.length > 12 ? ' 等' : '') + '。'));
      const interesting = (resources.items || []).filter(item => isInterestingResource(item.value));
      if (interesting.length) {
        section.append(el('h4', null, '可能相关的资源字符串（' + interesting.length + '）'));
        const table = makeTable(['名称', '配置', '值'], interesting.slice(0, 200).map(item => [item.name, item.config, item.value]), { mono: [0, 2] });
        section.append(table);
        if (interesting.length > 200) section.append(el('p', 'hint', '仅显示前 200 条可能相关的字符串，完整列表在 JSON 报告中。'));
      } else {
        section.append(el('p', 'hint', '没有资源字符串命中 Flag、密钥、URL 等关键词。'));
      }
      addDetails(section, '显示全部资源字符串（' + resources.collected + '）', () => {
        const rows = (resources.items || []).slice(0, 1000).map(item => [item.name, item.config, item.value]);
        const wrap = el('div');
        wrap.append(makeTable(['名称', '配置', '值'], rows, { mono: [0, 2] }));
        if (resources.items.length > 1000) wrap.append(el('p', 'hint', '仅显示前 1000 条，完整列表在 JSON 报告中。'));
        return wrap;
      });
    } else {
      empty(resourceStrings, '没有找到或无法解析 resources.arsc；资源字符串线索不可用。');
    }
    const dexCount = strings.dexStringsScanned || 0;
    resourceStrings.append(el('p', 'hint', 'DEX 字符串池共扫描 ' + dexCount + ' 条字符串；超过上限的 DEX 不会继续扫描。'));
  }
  function isInterestingResource(value) {
    if (!value) return false;
    return /\bflag\b|ctf|api[_-]?key|secret|token|password|passwd|BEGIN .*KEY/i.test(value) || /https?:\/\//i.test(value);
  }

  /* ------------------------------ JADX ------------------------------ */

  async function loadJadxVersion() {
    if (!jadxVersion) return;
    try {
      const response = await fetch('../api/apk/version', { cache: 'no-store' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || ('JADX 版本接口返回 HTTP ' + response.status));
      const version = String(data.version || '').trim();
      if (!version) throw new Error('JADX 未返回版本信息。');
      jadxVersion.textContent = 'JADX ' + version;
      jadxVersion.title = '本机 JADX CLI 版本：' + version;
    } catch (error) {
      jadxVersion.textContent = 'JADX 版本不可用';
      jadxVersion.title = error?.message || '无法读取本机 JADX 版本';
    }
  }
  void loadJadxVersion();

  function createArrowToggle(collapsedLabel, expandedLabel) {
    const button = el('button', 'apk-expand apk-evidence-toggle');
    button.type = 'button';
    button.dataset.collapsedLabel = collapsedLabel;
    button.dataset.expandedLabel = expandedLabel;
    button.setAttribute('aria-label', collapsedLabel);
    button.setAttribute('aria-expanded', 'false');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'm6 9 6 6 6-6');
    svg.append(path);
    button.append(svg);
    return button;
  }
  function renderCodeFindings(findings) {
    const items = Array.isArray(findings) ? findings : [];
    codeFindingCount.textContent = items.length + ' 类';
    const cards = items.map(finding => {
      const card = el('article', 'code-finding');
      card.append(el('strong', null, finding.title + '（' + finding.count + ' 处线索）'));
      card.append(el('p', null, finding.description));
      const evidenceItems = (finding.evidence || []).map(item => {
        const entry = el('li');
        entry.append(el('span', 'code-location', (item.file || '') + (item.line ? ':' + item.line : '')));
        entry.append(el('code', null, item.snippet || item.api || ''));
        return entry;
      });
      const list = el('ul');
      for (const item of evidenceItems.slice(0, 2)) list.append(item);
      card.append(list);
      if (evidenceItems.length > 2) {
        const extra = el('ul', 'apk-evidence-extra');
        extra.hidden = true;
        for (const item of evidenceItems.slice(2)) extra.append(item);
        const toggle = createArrowToggle('显示更多代码证据', '收起更多代码证据');
        card.append(extra, toggle);
        bindExpandButton(toggle, true, expanded => { extra.hidden = !expanded; });
      }
      return card;
    });
    if (!cards.length) {
      codeFindingItems.replaceChildren();
      codeFindingItems.append(el('p', 'hint', '没有识别到常见能力/API 特征。'));
      bindExpandButton(codeFindingsToggle, false, () => {});
    } else {
      renderExpandableItems(codeFindingItems, cards, 3, codeFindingsToggle);
    }
    codeFindings.hidden = false;
    codeFindingsSection.hidden = false;
  }
  function renderJadxUrls(rows) {
    const items = Array.isArray(rows) ? rows : [];
    jadxUrlCount.textContent = items.length + ' 个';
    jadxUrlNote.textContent = items.length
      ? '网址来自反编译代码或资源中的明文字符串；运行时拼接、加密或网络下发的网址可能无法静态发现。'
      : '没有发现明文静态网址；运行时拼接、加密或网络下发的网址无法通过此方式发现。';
    jadxUrls.replaceChildren();
    const rowItems = items.map(item => {
      const row = el('tr');
      const urlCell = el('td');
      urlCell.append(el('code', null, item.url || ''));
      const sourceCell = el('td', null, (item.file || '') + (item.line ? ':' + item.line : ''));
      row.append(urlCell, sourceCell);
      return row;
    });
    for (let i = 0; i < rowItems.length; i++) {
      rowItems[i].hidden = i >= 5;
      jadxUrls.append(rowItems[i]);
    }
    bindExpandButton(urlsToggle, rowItems.length > 5, expanded => {
      for (let i = 5; i < rowItems.length; i++) rowItems[i].hidden = !expanded;
    });
    jadxUrlResults.hidden = false;
  }

  async function runJadxAnalysis(file, runId, signal) {
    const startedAt = Date.now();
    showLoadingStatus(jadxStatus, '正在调用本机 JADX，解析 APK 结构与代码（已用时 0 秒）');
    jadxStatus.setAttribute('aria-live', 'off');
    const progressTimer = window.setInterval(() => {
      if (runId !== state.runId) { window.clearInterval(progressTimer); return; }
      const elapsed = formatElapsed(Date.now() - startedAt);
      showLoadingStatus(jadxStatus, '正在调用本机 JADX，解析 APK 结构与代码（已用时 ' + elapsed + '）');
      analysisDuration.textContent = 'JADX 解析用时：' + elapsed;
    }, 1000);
    analysisDuration.textContent = 'JADX 解析用时：0 秒';
    jadxUrlResults.hidden = true;
    jadxUrls.replaceChildren();
    try {
      const response = await fetch('../api/apk/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/vnd.android.package-archive' },
        body: file,
        signal
      });
      const data = await response.json();
      if (runId !== state.runId) { window.clearInterval(progressTimer); return; }
      if (!response.ok) throw new Error(data.error || ('JADX 服务返回 HTTP ' + response.status));
      if (data.tool !== 'jadx' || !data.metadata || !data.metadata.package) {
        throw new Error('JADX 未返回有效的 APK 结构信息。');
      }
      window.clearInterval(progressTimer);
      const elapsed = formatElapsed(Date.now() - startedAt);
      analysisDuration.textContent = 'JADX 解析用时：' + elapsed;
      jadxStatus.setAttribute('aria-live', 'polite');
      renderCodeFindings(data.codeFindings || []);
      renderJadxUrls(data.urls || []);
      const findings = (data.codeFindings || []).length;
      state.jadxFindings = findings;
      state.jadxUrls = (data.urls || []).length;
      state.jadxDone = true;
      state.jadxError = '';
      if (data.analysisComplete === false) {
        const warning = data.warning || '部分反编译未完成，代码和网址结果可能不完整。';
        jadxStatus.className = 'status warning';
        jadxStatus.textContent = 'JADX 部分完成：' + warning;
      } else {
        jadxStatus.className = 'status success';
        jadxStatus.textContent = 'JADX 分析完成：' + findings + ' 类代码特征、' + (data.urls || []).length + ' 个静态网址。';
      }
    } catch (error) {
      if (runId !== state.runId) { window.clearInterval(progressTimer); return; }
      window.clearInterval(progressTimer);
      if (error.name === 'AbortError') return;
      const elapsed = formatElapsed(Date.now() - startedAt);
      analysisDuration.textContent = 'JADX 解析用时：' + elapsed;
      jadxStatus.setAttribute('aria-live', 'polite');
      const detail = error instanceof TypeError
        ? '无法连接本机 JADX 分析接口。请通过 launch.command（macOS）或 launch.bat（Windows）启动网站。'
        : error?.message || 'JADX 分析失败。';
      jadxStatus.className = 'status warning';
      jadxStatus.textContent = detail;
      state.jadxDone = true;
      state.jadxError = detail;
    } finally {
      if (runId === state.runId) updateStatus();
    }
  }

  /* ------------------------------ 状态与流程 ------------------------------ */

  function updateStatus() {
    if (!state.file) return;
    if (!state.inspectorDone) {
      if (state.progressMessage) showLoadingStatus(statusBox, state.progressMessage + '（' + state.progressPercent + '%）');
      return;
    }
    const report = state.report;
    const parts = [];
    parts.push('静态检查完成：' + report.file.name + '（' + formatBytes(report.file.size) + '，' + (report.zip?.parsedEntries || 0) + ' 个条目，用时 ' + formatElapsed(report.elapsed || 0) + '）。');
    const schemes = schemeList(report.signature || {});
    parts.push(schemes.length ? '签名 ' + schemes.join(' + ') + '。' : '未发现签名方案。');
    parts.push('组件 ' + (report.statistics?.components || 0) + ' 个 · 权限 ' + (report.statistics?.permissions || 0) + ' 项 · 敏感字符串 ' + (report.statistics?.secretHits || 0) + ' 条。');
    if (!state.jadxDone) {
      parts.push('JADX 代码分析进行中…');
    } else if (state.jadxError) {
      parts.push('JADX 未完成：' + state.jadxError);
    } else {
      parts.push('JADX 已补充 ' + state.jadxFindings + ' 类代码特征、' + state.jadxUrls + ' 个网址。');
    }
    const kind = (report.warnings || []).length ? 'warning' : 'success';
    showStatus(parts.join(' '), kind);
  }
  function resetSections() {
    overviewChip.textContent = '';
    signatureChip.textContent = '';
    manifestChip.textContent = '';
    inventoryChip.textContent = '';
    stringsChip.textContent = '';
    componentCount.textContent = '';
    permissionCount.textContent = '';
    manifestExtraCount.textContent = '';
    for (const node of [overview, securityNotes, fileInfo, hashList, signatureSummary, signatureSchemes, signerList,
      appInfo, applicationFlags, componentGroups, permissions, declaredPermissions, featureList, manifestExtrasBody,
      inventorySummary, inventoryKeyFiles, inventoryMeta, inventoryDex, inventoryLibs, inventoryAssets, inventoryRaw,
      inventorySuspicious, inventoryOthers, secretHits, networkHits, resourceStrings, codeFindingItems, jadxUrls]) {
      clear(node);
    }
    signatureWarnings.hidden = true;
    codeFindings.hidden = true;
    codeFindingsSection.hidden = true;
    jadxUrlResults.hidden = true;
    permissionToggle.hidden = true;
    manifestExtras.open = false;
  }
  function parseApk(file) {
    state.runId++;
    const runId = state.runId;
    if (state.controller) state.controller.abort();
    state.file = null;
    state.report = null;
    state.inspectorDone = false;
    state.inspectorError = '';
    state.jadxDone = false;
    state.jadxError = '';
    state.progressMessage = '';
    state.progressPercent = 0;
    results.hidden = true;
    exportJsonButton.disabled = true;
    copySummaryButton.disabled = true;
    if (!file) return;
    if (file.size > MAX_FILE) return showStatus('文件超过 1 GB 限制。', 'error');
    if (!file.name.toLowerCase().endsWith('.apk')) return showStatus('请选择 .apk 文件。', 'error');

    state.file = file;
    state.controller = new AbortController();
    results.hidden = false;
    resetSections();
    showLoadingStatus(statusBox, '正在读取 APK 结构…（0%）');
    jadxStatus.className = 'status';
    jadxStatus.textContent = '等待分析';
    analysisDuration.textContent = 'JADX 解析用时：—';
    jadxVersion.textContent = jadxVersion.textContent || 'JADX 版本读取中';

    void runJadxAnalysis(file, runId, state.controller.signal);
    void runInspector(file, runId, state.controller.signal);
  }
  async function runInspector(file, runId, signal) {
    try {
      const report = await ApkInspect.inspect(file, {
        signal,
        onProgress: progress => {
          if (runId !== state.runId) return;
          state.progressMessage = progress.message;
          state.progressPercent = progress.percent;
          showLoadingStatus(statusBox, progress.message + '（' + progress.percent + '%）');
        }
      });
      if (runId !== state.runId) return;
      state.report = report;
      state.inspectorDone = true;
      renderAll(report);
      exportJsonButton.disabled = false;
      copySummaryButton.disabled = false;
    } catch (error) {
      if (runId !== state.runId) return;
      if (error?.name === 'AbortError') return;
      state.inspectorError = error?.message || 'APK 检查失败。';
      results.hidden = true;
      showStatus('APK 检查失败：' + state.inspectorError, 'error');
    }
  }
  function renderAll(report) {
    const sections = [
      ['概览', () => renderOverview(report)],
      ['文件与完整性', () => renderFileInfo(report)],
      ['签名', () => renderSignature(report)],
      ['应用信息', () => renderManifest(report)],
      ['组件', () => renderComponents(report)],
      ['权限', () => renderPermissions(report)],
      ['清单其他声明', () => renderManifestExtras(report)],
      ['内容清单', () => renderInventory(report)],
      ['字符串线索', () => renderStrings(report)]
    ];
    for (const [name, render] of sections) {
      try {
        render();
      } catch (error) {
        console.error('APK 页面渲染失败：' + name, error);
      }
    }
    updateStatus();
  }

  /* ------------------------------ 导出 ------------------------------ */

  function summaryText() {
    const report = state.report;
    if (!report) return '';
    const lines = [
      'SimplerForensics APK 检查摘要',
      '文件：' + report.file.name + '（' + report.file.size + ' 字节）',
      'MD5：' + (report.hashes?.md5 || '未计算'),
      'SHA-256：' + (report.hashes?.sha256 || '未计算'),
      '包名：' + (report.manifest?.package || '未找到'),
      '版本：' + (report.manifest?.versionName || '—') + '（' + (report.manifest?.versionCode ?? '—') + '）',
      'SDK：min ' + (report.manifest?.minSdk ?? '—') + ' / target ' + (report.manifest?.targetSdk ?? '—'),
      '签名：' + (schemeList(report.signature || {}).join(' + ') || '未发现'),
      '证书：' + ((report.signature?.certificates || []).map(cert => cert.subject).join('；') || '未读取'),
      '组件：' + (report.statistics?.components || 0) + ' 个；权限：' + (report.statistics?.permissions || 0) + ' 项',
      '敏感字符串：' + (report.statistics?.secretHits || 0) + ' 条；网址：' + (report.statistics?.urls || 0) + ' 个',
      '生成时间：' + new Date().toISOString()
    ];
    return lines.join('\n');
  }
  exportJsonButton.addEventListener('click', () => {
    if (!state.report) return;
    const payload = {
      ...state.report,
      exportNote: '本报告由 SimplerForensics 在本机生成；签名有效性与线索真实性需人工复核。'
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    const base = (state.report.file.name || 'apk').replace(/\.apk$/i, '');
    anchor.href = url;
    anchor.download = base + '_apk-report_' + new Date().toISOString().replace(/[:.]/g, '-') + '.json';
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 2000);
    exportNote.textContent = '报告已生成并下载（' + formatBytes(blob.size) + '）。';
  });
  copySummaryButton.addEventListener('click', () => copyText(summaryText(), copySummaryButton));

  /* ------------------------------ 事件绑定 ------------------------------ */

  input.addEventListener('change', () => parseApk(input.files?.[0]));
  dropZone.addEventListener('click', event => { if (event.target !== input) input.click(); });
  dropZone.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); input.click(); } });
  for (const event of ['dragenter', 'dragover']) dropZone.addEventListener(event, eventObject => { eventObject.preventDefault(); dropZone.classList.add('dragover'); });
  for (const event of ['dragleave', 'drop']) dropZone.addEventListener(event, eventObject => { eventObject.preventDefault(); dropZone.classList.remove('dragover'); });
  dropZone.addEventListener('drop', event => { const file = event.dataTransfer?.files?.[0]; if (file) parseApk(file); });
})();
