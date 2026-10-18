const input = document.querySelector('#apk-file');
const dropZone = document.querySelector('#drop-zone');
const statusBox = document.querySelector('#status');
const results = document.querySelector('#results');
const appInfo = document.querySelector('#app-info');
const permissions = document.querySelector('#permissions');
const permissionCount = document.querySelector('#permission-count');
const jadxStatus = document.querySelector('#jadx-status');
const jadxVersion = document.querySelector('#jadx-version');
const codeFindings = document.querySelector('#code-findings');
const codeFindingsSection = document.querySelector('#code-findings-section');
const codeFindingItems = document.querySelector('#code-finding-items');
const codeFindingsToggle = document.querySelector('#code-findings-toggle');
const permissionToggle = document.querySelector('#permission-toggle');
const codeFindingCount = document.querySelector('#code-finding-count');
const urlsToggle = document.querySelector('#jadx-urls-toggle');
const analysisDuration = document.querySelector('#analysis-duration');
const jadxUrlResults = document.querySelector('#jadx-url-results');
const jadxUrlCount = document.querySelector('#jadx-url-count');
const jadxUrlNote = document.querySelector('#jadx-url-note');
const jadxUrls = document.querySelector('#jadx-urls');
const MAX_FILE = 1024 * 1024 * 1024;
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
let analysisRun = 0;

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

function permissionDescription(permission) {
  const shortName = permission.split('.').pop();
  return permissionCatalog[shortName] || [
    shortName.replaceAll('_', ' ').toLowerCase().replace(/\b\w/g, letter => letter.toUpperCase()),
    permission.startsWith('android.permission.')
      ? 'Android 系统权限；具体保护范围取决于系统版本和权限级别。'
      : '应用或厂商定义的自定义权限；具体用途需结合应用代码或权限声明者确认。'
  ];
}

function showStatus(message, kind = '') {
  statusBox.hidden = false;
  statusBox.className = `status ${kind}`;
  statusBox.textContent = message;
}

function showLoadingStatus(element, message) {
  element.className = 'status is-loading';
  const spinner = document.createElement('span');
  spinner.className = 'analysis-spinner';
  spinner.setAttribute('aria-hidden', 'true');
  element.replaceChildren(spinner, document.createTextNode(message));
}

function addInfo(label, value) {
  const item = document.createElement('div'); item.className = 'apk-info-item';
  const key = document.createElement('span'); key.textContent = label;
  const val = document.createElement('strong'); val.textContent = value || '未声明';
  item.append(key, val); appInfo.append(item);
}

function bindExpandButton(button, hasMore, update) {
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
  const extra = document.createElement('div');
  extra.className = 'apk-extra-content';
  for (const item of extraItems) extra.append(item);
  extra.hidden = true;
  container.append(extra);
  bindExpandButton(button, true, expanded => { extra.hidden = !expanded; });
}

function renderMetadata(metadata) {
  appInfo.replaceChildren();
  addInfo('应用名称', metadata.appName || metadata.appLabel || metadata.package);
  addInfo('包名', metadata.package);
  addInfo('版本名称', metadata.versionName);
  addInfo('版本号', metadata.versionCode);
  addInfo('主程序入口', (metadata.launchers || []).join('\n'));
  addInfo('最低兼容 Android API 级别（minSdkVersion）', metadata.minSdk);
  addInfo('目标 Android API 级别（targetSdkVersion）', metadata.targetSdk);

  const rows = Array.isArray(metadata.permissions) ? metadata.permissions : [];
  permissionCount.textContent = rows.length + ' 项';
  const permissionItems = rows.map(permission => {
    const row = document.createElement('div'); row.className = 'apk-permission';
    const [label, explanation] = permissionDescription(permission);
    const heading = document.createElement('div'); heading.className = 'apk-permission-title';
    const name = document.createElement('strong'); name.textContent = label;
    const code = document.createElement('code'); code.textContent = permission;
    const detail = document.createElement('p'); detail.textContent = explanation;
    heading.append(name, code); row.append(heading, detail); return row;
  });
  if (!permissionItems.length) {
    const empty = document.createElement('p');
    empty.className = 'hint';
    empty.textContent = '未声明 uses-permission 权限。';
    permissionItems.push(empty);
  }
  renderExpandableItems(permissions, permissionItems, 4, permissionToggle);
}

function createArrowToggle(collapsedLabel, expandedLabel) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'apk-expand apk-evidence-toggle';
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
    const card = document.createElement('article'); card.className = 'code-finding';
    const title = document.createElement('strong'); title.textContent = finding.title + '（' + finding.count + ' 处线索）';
    const description = document.createElement('p'); description.textContent = finding.description;
    const evidenceItems = (finding.evidence || []).map(item => {
      const entry = document.createElement('li');
      const location = document.createElement('span'); location.className = 'code-location';
      location.textContent = (item.file || '') + (item.line ? ':' + item.line : '');
      const snippet = document.createElement('code'); snippet.textContent = item.snippet || item.api || '';
      entry.append(location, snippet);
      return entry;
    });
    const list = document.createElement('ul');
    for (const item of evidenceItems.slice(0, 2)) list.append(item);
    card.append(title, description, list);
    if (evidenceItems.length > 2) {
      const extra = document.createElement('ul');
      extra.className = 'apk-evidence-extra';
      extra.hidden = true;
      for (const item of evidenceItems.slice(2)) extra.append(item);
      const toggle = createArrowToggle('显示更多代码证据', '收起更多代码证据');
      card.append(extra, toggle);
      bindExpandButton(toggle, true, expanded => { extra.hidden = !expanded; });
    }
    return card;
  });
  if (!cards.length) {
    const empty = document.createElement('p');
    empty.className = 'hint';
    empty.textContent = '没有识别到常见能力/API 特征。';
    cards.push(empty);
  }
  renderExpandableItems(codeFindingItems, cards, 3, codeFindingsToggle);
  codeFindings.hidden = false;
  codeFindingsSection.hidden = false;
}

function renderUrls(data) {
  const rows = Array.isArray(data.urls) ? data.urls : [];
  jadxUrlCount.textContent = rows.length + ' 个';
  jadxUrlNote.textContent = rows.length
    ? '网址来自反编译代码或资源中的明文字符串；运行时拼接、加密或网络下发的网址可能无法静态发现。'
    : '没有发现明文静态网址；运行时拼接、加密或网络下发的网址无法通过此方式发现。';
  jadxUrls.replaceChildren();
  const rowItems = rows.map(item => {
    const row = document.createElement('tr');
    const urlCell = document.createElement('td');
    const url = document.createElement('code'); url.textContent = item.url || '';
    urlCell.append(url);
    const sourceCell = document.createElement('td');
    sourceCell.textContent = (item.file || '') + (item.line ? ':' + item.line : '');
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

async function parseApk(file) {
  analysisRun++;
  results.hidden = true;
  if (!file) return;
  if (file.size > MAX_FILE) return showStatus('文件超过 1 GB 限制。', 'error');
  if (!file.name.toLowerCase().endsWith('.apk')) return showStatus('请选择 .apk 文件。', 'error');

  results.hidden = false;
  appInfo.replaceChildren();
  permissions.replaceChildren();
  codeFindings.replaceChildren();
  codeFindingItems.replaceChildren();
  codeFindings.hidden = true;
  codeFindingsSection.hidden = true;
  codeFindingsToggle.hidden = true;
  urlsToggle.hidden = true;
  jadxUrlResults.hidden = true;
  permissionToggle.hidden = true;
  permissionCount.textContent = '分析中';
  analysisDuration.textContent = '解析用时：0 秒';
  jadxUrls.replaceChildren();
  void runJadxAnalysis(file);
}

function formatElapsed(milliseconds) {
  const seconds = Math.floor(milliseconds / 1000);
  return seconds < 60 ? seconds + ' 秒' : Math.floor(seconds / 60) + ' 分 ' + (seconds % 60) + ' 秒';
}

async function runJadxAnalysis(file) {
  const runId = ++analysisRun;
  const loadingMessage = '正在使用 JADX 分析 ' + file.name + '，请稍候…';
  statusBox.hidden = false;
  showLoadingStatus(statusBox, loadingMessage);
  const progressStartedAt = Date.now();
  const progressMessage = '正在调用本机 JADX，解析 APK 结构与代码';
  showLoadingStatus(jadxStatus, progressMessage + '（已用时 0 秒）');
  jadxStatus.setAttribute('aria-live', 'off');
  const progressText = jadxStatus.lastChild;
  const progressTimer = window.setInterval(() => {
    if (runId !== analysisRun) { window.clearInterval(progressTimer); return; }
    const elapsed = formatElapsed(Date.now() - progressStartedAt);
    progressText.textContent = progressMessage + '（已用时 ' + elapsed + '）';
    analysisDuration.textContent = '解析用时：' + elapsed;
  }, 1000);
  jadxUrlResults.hidden = true;
  jadxUrls.replaceChildren();

  try {
    const response = await fetch('../api/apk/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/vnd.android.package-archive' },
      body: file
    });
    const data = await response.json();
    if (runId !== analysisRun) { window.clearInterval(progressTimer); return; }
    if (!response.ok) throw new Error(data.error || ('JADX 服务返回 HTTP ' + response.status));
    if (data.tool !== 'jadx' || !data.metadata || !data.metadata.package) {
      throw new Error('JADX 未返回有效的 APK 结构信息，无法填充应用信息。');
    }

    window.clearInterval(progressTimer);
    const elapsed = formatElapsed(Date.now() - progressStartedAt);
    analysisDuration.textContent = '解析用时：' + elapsed;
    jadxStatus.setAttribute('aria-live', 'polite');
    renderMetadata(data.metadata);
    renderCodeFindings(data.codeFindings);
    renderUrls(data);
    const summary = [
      '包名 ' + data.metadata.package,
      (data.metadata.permissions?.length ?? 0) + ' 项权限',
      data.metadata.launchers?.length ? '入口 ' + data.metadata.launchers.join(', ') : ''
    ].filter(Boolean).join(' · ');
    const sizeLabel = file.name + '（' + (file.size / 1024 / 1024).toFixed(1) + ' MB）';
    if (data.analysisComplete === false) {
      const warning = data.warning || '部分反编译未完成，代码和网址结果可能不完整。';
      jadxStatus.className = 'status warning';
      jadxStatus.textContent = 'Manifest 结构已解析；' + warning;
      showStatus('结构解析完成：' + sizeLabel + '。解析用时 ' + elapsed + '。' + (summary ? ' ' + summary + '。' : '') + ' ' + warning, 'warning');
    } else {
      const message = 'JADX 分析完成：' + sizeLabel + '。解析用时 ' + elapsed + '。' + (summary ? ' ' + summary + '。' : '');
      jadxStatus.className = 'status success';
      jadxStatus.textContent = 'JADX 分析完成，应用信息已更新。解析用时 ' + elapsed + '。';
      showStatus(message, 'success');
    }
  } catch (error) {
    if (runId !== analysisRun) { window.clearInterval(progressTimer); return; }
    window.clearInterval(progressTimer);
    const elapsed = formatElapsed(Date.now() - progressStartedAt);
    analysisDuration.textContent = '解析用时：' + elapsed;
    jadxStatus.setAttribute('aria-live', 'polite');
    const detail = error instanceof TypeError
      ? '无法连接本机 JADX 分析接口。请通过 launch.command（macOS）或 launch.bat（Windows）启动网站。'
      : error?.message || 'JADX 分析失败。';
    jadxStatus.className = 'status warning';
    jadxStatus.textContent = detail + ' 解析用时 ' + elapsed + '。';
    permissionCount.textContent = '分析失败';
    showStatus('JADX 未能完成分析：' + detail + ' 解析用时 ' + elapsed + '。', 'error');
  }
}

input.addEventListener('change', () => parseApk(input.files?.[0]));
dropZone.addEventListener('click', event => { if (event.target !== input) input.click(); });
dropZone.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); input.click(); } });
for (const event of ['dragenter', 'dragover']) dropZone.addEventListener(event, eventObject => { eventObject.preventDefault(); dropZone.classList.add('dragover'); });
for (const event of ['dragleave', 'drop']) dropZone.addEventListener(event, eventObject => { eventObject.preventDefault(); dropZone.classList.remove('dragover'); });
dropZone.addEventListener('drop', event => { const file = event.dataTransfer?.files?.[0]; if (file) parseApk(file); });
