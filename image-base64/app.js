const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];

const MAX_IMAGE_BYTES = 32 * 1024 * 1024;
const MAX_BASE64_CHARS = 48 * 1024 * 1024;
const WRAP_WIDTH = 76;
const EXTENSION_MIME = {
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  png: 'image/png',
  gif: 'image/gif',
  webp: 'image/webp',
  bmp: 'image/bmp',
  ico: 'image/x-icon',
  tif: 'image/tiff',
  tiff: 'image/tiff',
  svg: 'image/svg+xml',
  avif: 'image/avif',
  heic: 'image/heic',
  heif: 'image/heic'
};
const MIME_ALIASES = {
  'image/jpg': 'image/jpeg',
  'image/pjpeg': 'image/jpeg',
  'image/x-png': 'image/png',
  'image/tif': 'image/tiff',
  'image/vnd.microsoft.icon': 'image/x-icon',
  'image/heif': 'image/heic'
};

const encodeDrop = $('#encode-drop');
const encodeFileInput = $('#encode-file');
const encodeStatus = $('#encode-status');
const encodeOutput = $('#encode-output');
const includePrefix = $('#include-prefix');
const wrapLines = $('#wrap-lines');
const encodeResult = $('#encode-result');
const encodePreview = $('#encode-preview');
const encodePreviewNote = $('#encode-preview-note');
const encodeInfo = $('#encode-info');
const copyEncodeButton = $('#copy-encode');
const downloadEncodeButton = $('#download-encode');
const decodeInput = $('#decode-input');
const decodeFileInput = $('#decode-file');
const decodeStatus = $('#decode-status');
const decodeButton = $('#decode');
const decodeLayout = $('#decode-layout');
const decodeResult = $('#decode-result');
const decodePreview = $('#decode-preview');
const decodePreviewNote = $('#decode-preview-note');
const decodeInfo = $('#decode-info');
const downloadDecodeButton = $('#download-decode');
const copyDecodeButton = $('#copy-decode');

let encodeRequestId = 0;
let encodeBase64 = '';
let encodePrefix = '';
let encodeObjectUrl = null;
let encodeFile = null;

let decodeRequestId = 0;
let decodeBase64 = '';
let decodeBytes = null;
let decodeDetected = null;
let decodeObjectUrl = null;
let decodeSourceName = '';

const formatNumber = value => new Intl.NumberFormat('zh-CN').format(Number(value) || 0);

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  if (bytes < 1024) return `${formatNumber(bytes)} B`;
  const units = ['KiB', 'MiB', 'GiB'];
  let size = bytes / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }
  return `${size.toLocaleString('zh-CN', { maximumFractionDigits: size >= 10 ? 1 : 2 })} ${units[unit]}`;
}

function setStatus(element, message, kind = '') {
  element.classList.remove('success', 'warning', 'error');
  if (kind) element.classList.add(kind);
  element.textContent = message;
}

function appendInfo(container, label, value) {
  const item = document.createElement('div');
  item.className = 'b64-info-item';
  const term = document.createElement('span');
  term.textContent = label;
  const detail = document.createElement('strong');
  detail.textContent = value || '—';
  item.append(term, detail);
  container.append(item);
}

function bytesToAscii(bytes, start, length) {
  let text = '';
  const end = Math.min(bytes.length, start + length);
  for (let index = start; index < end; index++) text += String.fromCharCode(bytes[index]);
  return text;
}

function hasSignature(bytes, signature) {
  return bytes.length >= signature.length && signature.every((byte, index) => bytes[index] === byte);
}

function detectImageType(bytes) {
  if (!bytes || !bytes.length) return null;
  if (hasSignature(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    return { mime: 'image/png', label: 'PNG', extension: 'png' };
  }
  if (hasSignature(bytes, [0xff, 0xd8, 0xff])) {
    return { mime: 'image/jpeg', label: 'JPEG', extension: 'jpg' };
  }
  const firstSix = bytesToAscii(bytes, 0, 6);
  if (firstSix === 'GIF87a' || firstSix === 'GIF89a') {
    return { mime: 'image/gif', label: 'GIF', extension: 'gif' };
  }
  if (bytes.length >= 12 && bytesToAscii(bytes, 0, 4) === 'RIFF' && bytesToAscii(bytes, 8, 4) === 'WEBP') {
    return { mime: 'image/webp', label: 'WebP', extension: 'webp' };
  }
  if (hasSignature(bytes, [0x42, 0x4d]) && bytes.length >= 14) {
    return { mime: 'image/bmp', label: 'BMP', extension: 'bmp' };
  }
  if (hasSignature(bytes, [0x00, 0x00, 0x01, 0x00])) {
    return { mime: 'image/x-icon', label: 'ICO', extension: 'ico' };
  }
  if (hasSignature(bytes, [0x49, 0x49, 0x2a, 0x00]) || hasSignature(bytes, [0x4d, 0x4d, 0x00, 0x2a])) {
    return { mime: 'image/tiff', label: 'TIFF', extension: 'tif' };
  }
  if (bytes.length >= 12 && bytesToAscii(bytes, 4, 4) === 'ftyp') {
    const brand = bytesToAscii(bytes, 8, 4).toLowerCase();
    if (brand === 'avif' || brand === 'avis') {
      return { mime: 'image/avif', label: 'AVIF', extension: 'avif' };
    }
    if (['heic', 'heix', 'hevc', 'hevx', 'heim', 'heis', 'mif1', 'msf1'].includes(brand)) {
      return { mime: 'image/heic', label: 'HEIC / HEIF', extension: 'heic' };
    }
  }
  const head = new TextDecoder('utf-8', { fatal: false })
    .decode(bytes.subarray(0, Math.min(bytes.length, 4096)))
    .replace(/^\uFEFF/, '')
    .trimStart();
  if (/^(?:<\?xml[\s\S]*?\?>\s*)?(?:<!doctype\s+svg[^>]*>\s*)?(?:<!--[\s\S]*?-->\s*)*<svg[\s>]/i.test(head)) {
    return { mime: 'image/svg+xml', label: 'SVG', extension: 'svg' };
  }
  return null;
}

function extensionOf(name) {
  const match = /\.([^.\\/]+)$/.exec(String(name || ''));
  return match ? match[1].toLowerCase() : '';
}

function canonicalMime(mime) {
  const value = String(mime || '').toLowerCase();
  return MIME_ALIASES[value] || value;
}

function formatDimensions(dimensions) {
  if (!dimensions) return '浏览器未能读取';
  if (!dimensions.width && !dimensions.height) return '未提供固有像素尺寸（矢量图常见）';
  return `${formatNumber(dimensions.width)} × ${formatNumber(dimensions.height)} px`;
}

function safeStem(name) {
  const stem = String(name || '')
    .replace(/\.[^.]+$/, '')
    .replace(/[\\/:*?"<>|\u0000-\u001F]/g, '_')
    .trim();
  return (stem || 'image').slice(0, 100);
}

function timestampForName() {
  const now = new Date();
  const pad = value => String(value).padStart(2, '0');
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

function readAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '');
    reader.onerror = () => reject(reader.error || new Error('读取文件失败。'));
    reader.onabort = () => reject(new Error('读取已取消。'));
    reader.readAsDataURL(file);
  });
}

function readTextFile(file) {
  if (typeof file.text === 'function') return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '');
    reader.onerror = () => reject(reader.error || new Error('读取文本文件失败。'));
    reader.readAsText(file);
  });
}

function getImageDimensions(url) {
  return new Promise(resolve => {
    const image = new Image();
    image.decoding = 'async';
    image.onload = () => resolve({ width: image.naturalWidth || 0, height: image.naturalHeight || 0 });
    image.onerror = () => resolve(null);
    image.src = url;
  });
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = 'none';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  return filename;
}

async function copyText(text, statusElement, successMessage) {
  if (!text) {
    setStatus(statusElement, '没有可复制的内容。', 'warning');
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    setStatus(statusElement, successMessage, 'success');
    return;
  } catch { /* Fall back to a temporary textarea below. */ }
  const helper = document.createElement('textarea');
  helper.value = text;
  helper.setAttribute('readonly', '');
  helper.style.position = 'fixed';
  helper.style.top = '-1000px';
  helper.style.opacity = '0';
  document.body.append(helper);
  helper.select();
  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch {
    copied = false;
  }
  helper.remove();
  if (copied) {
    setStatus(statusElement, successMessage, 'success');
  } else {
    setStatus(statusElement, '浏览器未允许访问剪贴板。请手动选择输出文本并复制。', 'warning');
  }
}

function wrapBase64(text) {
  let wrapped = '';
  for (let index = 0; index < text.length; index += WRAP_WIDTH) {
    wrapped += `${index ? '\n' : ''}${text.slice(index, index + WRAP_WIDTH)}`;
  }
  return wrapped;
}

function renderEncodeOutput() {
  if (!encodeBase64) return;
  const body = wrapLines.checked ? wrapBase64(encodeBase64) : encodeBase64;
  encodeOutput.value = includePrefix.checked ? `${encodePrefix}${body}` : body;
}

function resetEncodeResult() {
  encodeFile = null;
  encodeBase64 = '';
  encodePrefix = '';
  encodeOutput.value = '';
  if (encodeObjectUrl) {
    URL.revokeObjectURL(encodeObjectUrl);
    encodeObjectUrl = null;
  }
  encodePreview.hidden = true;
  encodePreview.removeAttribute('src');
  encodePreview.alt = '';
  encodePreviewNote.hidden = true;
  encodePreviewNote.textContent = '';
  encodeInfo.replaceChildren();
  encodeResult.hidden = true;
  copyEncodeButton.disabled = true;
  downloadEncodeButton.disabled = true;
}

function renderEncodeInfo(file, detected, declaredMime, resolvedMime, base64, dimensions) {
  encodeInfo.replaceChildren();
  appendInfo(encodeInfo, '文件', file.name);
  appendInfo(encodeInfo, '文件大小', formatBytes(file.size));
  appendInfo(encodeInfo, '声明类型', declaredMime || '未提供');
  appendInfo(encodeInfo, '检测格式', detected ? `${detected.label}（${detected.mime}）` : `未识别（使用 ${resolvedMime}）`);
  appendInfo(encodeInfo, '像素尺寸', formatDimensions(dimensions));
  appendInfo(encodeInfo, 'Base64 字符', `${formatNumber(base64.length)} 字符`);
  appendInfo(encodeInfo, 'Data URL 字符', `${formatNumber(base64.length + `data:${resolvedMime};base64,`.length)} 字符`);
  appendInfo(encodeInfo, '相对文件大小', file.size ? `${(base64.length / file.size * 100).toFixed(1)}%` : '—');
}

async function handleEncodeFile(file, extraNote = '') {
  const request = ++encodeRequestId;
  resetEncodeResult();
  if (!file) return;
  if (!file.size) {
    setStatus(encodeStatus, '这个文件为空，无法生成 Base64。', 'error');
    return;
  }
  if (file.size > MAX_IMAGE_BYTES) {
    setStatus(encodeStatus, `文件大小为 ${formatBytes(file.size)}，超过 ${formatBytes(MAX_IMAGE_BYTES)} 的单张图片上限。请先缩小图片或压缩后重试。`, 'error');
    return;
  }

  setStatus(encodeStatus, `正在读取 ${file.name} 并生成 Base64…`);
  try {
    const head = new Uint8Array(await file.slice(0, Math.min(file.size, 4096)).arrayBuffer());
    if (request !== encodeRequestId) return;

    const detected = detectImageType(head);
    const declaredMime = (file.type || '').toLowerCase();
    const extensionMime = EXTENSION_MIME[extensionOf(file.name)] || '';
    if (!detected && !declaredMime.startsWith('image/') && !extensionMime) {
      throw new Error('文件头不是常见图片格式，文件类型也不是 image/*。请选择图片文件。');
    }
    const resolvedMime = detected?.mime || (declaredMime.startsWith('image/') ? canonicalMime(declaredMime) : canonicalMime(extensionMime)) || 'application/octet-stream';
    const dataUrl = await readAsDataURL(file);
    if (request !== encodeRequestId) return;

    const comma = dataUrl.indexOf(',');
    if (comma < 0) throw new Error('浏览器未能生成 Base64 数据。');
    const base64 = dataUrl.slice(comma + 1);
    if (!base64) throw new Error('浏览器生成的 Base64 为空。');
    if (base64.length > MAX_BASE64_CHARS) {
      throw new Error(`Base64 输出超过 ${formatNumber(MAX_BASE64_CHARS)} 字符上限。`);
    }

    const previewUrl = URL.createObjectURL(file);
    const dimensions = await getImageDimensions(previewUrl);
    if (request !== encodeRequestId) {
      URL.revokeObjectURL(previewUrl);
      return;
    }

    encodeFile = file;
    encodeBase64 = base64;
    encodePrefix = `data:${resolvedMime};base64,`;
    encodeObjectUrl = previewUrl;

    encodePreview.src = previewUrl;
    encodePreview.alt = `${file.name} 的图片预览`;
    encodePreview.hidden = !dimensions;
    if (!dimensions) {
      encodePreviewNote.hidden = false;
      encodePreviewNote.textContent = '浏览器无法预览此图片格式，但 Base64 文本仍可复制或下载。';
    } else if (!dimensions.width && !dimensions.height) {
      encodePreviewNote.hidden = false;
      encodePreviewNote.textContent = '浏览器没有提供固有像素尺寸，矢量图的实际显示尺寸可能由 viewBox 或外部样式决定。';
    } else {
      encodePreviewNote.hidden = true;
      encodePreviewNote.textContent = '';
    }

    renderEncodeInfo(file, detected, declaredMime, resolvedMime, base64, dimensions);
    renderEncodeOutput();
    encodeResult.hidden = false;
    copyEncodeButton.disabled = false;
    downloadEncodeButton.disabled = false;

    const notes = [];
    let kind = 'success';
    if (detected && declaredMime && detected.mime !== canonicalMime(declaredMime)) {
      notes.push(`文件声明类型为 ${declaredMime}，文件头检测为 ${detected.label}（${detected.mime}）。Data URL 前缀使用检测到的类型。`);
      kind = 'warning';
    } else if (!detected) {
      notes.push(`未能从文件头识别格式，已按${declaredMime ? '声明类型' : '扩展名'}使用 ${resolvedMime}；预览和后续解析可能失败。`);
      kind = 'warning';
    }
    if (!dimensions) {
      notes.push('浏览器无法加载此图片预览；Base64 文本仍按原始文件字节生成。');
      if (kind === 'success') kind = 'warning';
    }
    if (extraNote) notes.push(extraNote);
    const outputKind = includePrefix.checked ? 'Data URL' : 'Base64';
    setStatus(encodeStatus, [`已生成 ${file.name} 的 ${outputKind}（${formatNumber(base64.length)} 个 Base64 字符）。`, ...notes].join('\n'), kind);
  } catch (error) {
    if (request !== encodeRequestId) return;
    resetEncodeResult();
    setStatus(encodeStatus, `无法转换此文件：${error.message || '未知错误'}`, 'error');
  }
}

function handleEncodeFiles(fileList) {
  const files = [...(fileList || [])];
  if (!files.length) return;
  const note = files.length > 1 ? `一次只处理一张图片，已选择第一张：${files[0].name}。` : '';
  handleEncodeFile(files[0], note);
}

function parseBase64Input(raw) {
  let text = String(raw).trim();
  if (!text) throw new Error('请输入 Base64 或 Data URL。');

  let declaredMime = '';
  let isDataUrl = false;
  if (/^data:/i.test(text)) {
    const comma = text.indexOf(',');
    if (comma < 0) throw new Error('Data URL 缺少“,”分隔符。');
    const metadata = text.slice(5, comma);
    const parts = metadata.split(';').map(part => part.trim());
    declaredMime = (parts.shift() || '').toLowerCase();
    if (!parts.some(part => part.toLowerCase() === 'base64')) {
      throw new Error('当前只支持 base64 形式的 Data URL；这个 Data URL 不是 Base64 编码。');
    }
    text = text.slice(comma + 1);
    isDataUrl = true;
  }

  const hadWhitespace = /\s/.test(text);
  let payload = text.replace(/\s+/g, '');
  if (!payload) throw new Error('没有找到 Base64 数据。');
  if (payload.length > MAX_BASE64_CHARS) {
    throw new Error(`Base64 文本超过 ${formatNumber(MAX_BASE64_CHARS)} 字符上限。`);
  }

  let urlSafe = false;
  if (/[-_]/.test(payload)) {
    urlSafe = true;
    payload = payload.replace(/-/g, '+').replace(/_/g, '/');
  }

  const invalid = payload.match(/[^A-Za-z0-9+/=]/);
  if (invalid) {
    const index = payload.indexOf(invalid[0]);
    throw new Error(`Base64 包含无效字符“${invalid[0]}”（有效字符第 ${index + 1} 个）。`);
  }

  const paddingMatch = payload.match(/=+$/);
  const padding = paddingMatch ? paddingMatch[0].length : 0;
  const dataPart = payload.slice(0, payload.length - padding);
  if (dataPart.includes('=')) throw new Error('“=”只能出现在 Base64 末尾。');
  if (padding > 2) throw new Error('Base64 末尾的“=”不能超过两个。');
  if (!dataPart) throw new Error('没有找到有效的 Base64 数据。');

  const remainder = dataPart.length % 4;
  if (remainder === 1) throw new Error('Base64 数据长度无效（模 4 余 1）。');
  const expectedPadding = remainder === 0 ? 0 : 4 - remainder;
  if (padding && padding !== expectedPadding) throw new Error('Base64 填充长度与数据长度不匹配。');
  const base64 = dataPart + '='.repeat(expectedPadding);
  const estimatedBytes = Math.floor(base64.length / 4) * 3 - expectedPadding;
  if (estimatedBytes > MAX_IMAGE_BYTES) {
    throw new Error(`解码后的图片约 ${formatBytes(estimatedBytes)}，超过 ${formatBytes(MAX_IMAGE_BYTES)} 上限。`);
  }

  let binary;
  try {
    binary = atob(base64);
  } catch {
    throw new Error('Base64 解码失败，请检查字符和填充是否正确。');
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return { bytes, base64, declaredMime, isDataUrl, urlSafe, hadWhitespace };
}

function renderDecodeInfo(parsed, detected, dimensions) {
  decodeInfo.replaceChildren();
  appendInfo(decodeInfo, '检测格式', `${detected.label}（${detected.mime}）`);
  appendInfo(decodeInfo, '图片大小', formatBytes(parsed.bytes.length));
  appendInfo(decodeInfo, '像素尺寸', formatDimensions(dimensions));
  appendInfo(decodeInfo, 'Base64 字符', `${formatNumber(parsed.base64.length)} 字符`);
  appendInfo(decodeInfo, '输入形式', `${parsed.isDataUrl ? 'Data URL' : '原始 Base64'}${parsed.hadWhitespace ? '，含空白' : ''}`);
  appendInfo(decodeInfo, 'Data URL 声明', parsed.declaredMime || (parsed.isDataUrl ? '未声明 MIME' : '无（原始 Base64）'));
  appendInfo(decodeInfo, '编码字符集', parsed.urlSafe ? '标准 Base64 + URL-safe 字符' : '标准 Base64');
  appendInfo(decodeInfo, '来源文件', decodeSourceName || '—');
}

function resetDecodeResult() {
  decodeBase64 = '';
  decodeBytes = null;
  decodeDetected = null;
  if (decodeObjectUrl) {
    URL.revokeObjectURL(decodeObjectUrl);
    decodeObjectUrl = null;
  }
  decodeResult.hidden = true;
  decodePreview.hidden = true;
  decodePreview.removeAttribute('src');
  decodePreview.alt = '';
  decodePreviewNote.hidden = true;
  decodePreviewNote.textContent = '';
  decodeInfo.replaceChildren();
  downloadDecodeButton.disabled = true;
  copyDecodeButton.disabled = true;
  decodeLayout.classList.add('is-single');
}

async function decodeBase64ToImage() {
  const raw = decodeInput.value;
  if (!raw.trim()) {
    ++decodeRequestId;
    resetDecodeResult();
    decodeButton.disabled = false;
    setStatus(decodeStatus, '请输入 Base64 或 Data URL。', 'error');
    decodeInput.focus();
    return;
  }
  if (raw.length > MAX_BASE64_CHARS + 4096) {
    ++decodeRequestId;
    resetDecodeResult();
    decodeButton.disabled = false;
    setStatus(decodeStatus, `输入长度为 ${formatNumber(raw.length)} 字符，超过处理上限。请确认内容为单张图片的 Base64。`, 'error');
    return;
  }

  const request = ++decodeRequestId;
  resetDecodeResult();
  decodeButton.disabled = true;
  setStatus(decodeStatus, '正在解析 Base64 并识别图片格式…');
  try {
    await new Promise(resolve => setTimeout(resolve, 0));
    const parsed = parseBase64Input(raw);
    if (request !== decodeRequestId) return;

    const detected = detectImageType(parsed.bytes);
    if (!detected) {
      throw new Error('解码成功，但字节内容不是可识别的图片格式。请确认输入的是图片的 Base64，而不是普通文本或其他文件。');
    }

    const blob = new Blob([parsed.bytes], { type: detected.mime });
    const previewUrl = URL.createObjectURL(blob);
    const dimensions = await getImageDimensions(previewUrl);
    if (request !== decodeRequestId) {
      URL.revokeObjectURL(previewUrl);
      return;
    }

    decodeBase64 = parsed.base64;
    decodeBytes = parsed.bytes;
    decodeDetected = detected;
    decodeObjectUrl = previewUrl;

    decodePreview.src = previewUrl;
    decodePreview.alt = `${detected.label} 图片预览`;
    decodePreview.hidden = !dimensions;
    if (!dimensions) {
      decodePreviewNote.hidden = false;
      decodePreviewNote.textContent = '浏览器无法预览此图片格式，但原始图片字节可以下载。';
    } else if (!dimensions.width && !dimensions.height) {
      decodePreviewNote.hidden = false;
      decodePreviewNote.textContent = '浏览器没有提供固有像素尺寸，矢量图的实际显示尺寸可能由 viewBox 或外部样式决定。';
    } else {
      decodePreviewNote.hidden = true;
      decodePreviewNote.textContent = '';
    }

    renderDecodeInfo(parsed, detected, dimensions);
    decodeResult.hidden = false;
    decodeLayout.classList.remove('is-single');
    downloadDecodeButton.disabled = false;
    copyDecodeButton.disabled = false;

    const notes = [];
    let kind = 'success';
    if (parsed.declaredMime && canonicalMime(parsed.declaredMime) !== detected.mime) {
      notes.push(`Data URL 声明类型为 ${parsed.declaredMime}，文件头实际检测为 ${detected.label}（${detected.mime}）；预览和下载按实际格式处理。`);
      kind = 'warning';
    }
    if (parsed.urlSafe) notes.push('输入包含 URL-safe 字符“-”或“_”，已按标准 Base64 解码。');
    if (parsed.hadWhitespace) notes.push('已忽略输入中的空白字符和换行。');
    if (!dimensions) {
      notes.push('浏览器无法加载此图片预览；原始图片字节仍可下载。');
      if (kind === 'success') kind = 'warning';
    }
    setStatus(decodeStatus, [`已还原 ${detected.label} 图片，${formatBytes(parsed.bytes.length)}。`, ...notes].join('\n'), kind);
  } catch (error) {
    if (request !== decodeRequestId) return;
    resetDecodeResult();
    setStatus(decodeStatus, `解析失败：${error.message || '未知错误'}`, 'error');
  } finally {
    if (request === decodeRequestId) decodeButton.disabled = false;
  }
}

async function loadDecodeTextFile(file) {
  if (!file) return;
  const maxTextBytes = MAX_BASE64_CHARS + 4096;
  ++decodeRequestId;
  resetDecodeResult();
  decodeButton.disabled = false;
  if ((file.type || '').startsWith('image/') || EXTENSION_MIME[extensionOf(file.name)]) {
    setStatus(decodeStatus, '检测到图片文件。请切换到“图片 → Base64”模式后再选择它；本输入框只接受 Base64 文本文件。', 'warning');
    return;
  }
  if (file.size > maxTextBytes) {
    setStatus(decodeStatus, `文本文件大小为 ${formatBytes(file.size)}，超过 ${formatBytes(maxTextBytes)} 上限。`, 'error');
    return;
  }
  setStatus(decodeStatus, `正在读取 ${file.name}…`);
  try {
    const text = await readTextFile(file);
    if (text.length > maxTextBytes) {
      throw new Error(`文本长度为 ${formatNumber(text.length)} 字符，超过处理上限。`);
    }
    if (!text.trim()) throw new Error('文本文件为空。');
    decodeInput.value = text;
    decodeSourceName = file.name;
    setStatus(decodeStatus, `已载入 ${file.name}（${formatBytes(file.size)}，${formatNumber(text.length)} 字符）。点击“解析为图片”开始解码。`, 'success');
    decodeInput.focus();
  } catch (error) {
    setStatus(decodeStatus, `无法读取文本文件：${error.message || '未知错误'}`, 'error');
  }
}

$$('input[name="image-b64-mode"]').forEach(radio => {
  radio.addEventListener('change', () => {
    const showEncode = radio.value === 'encode';
    $('#encode-view').hidden = !showEncode;
    $('#decode-view').hidden = showEncode;
  });
});

encodeFileInput.addEventListener('change', event => {
  // Copy the FileList before clearing the input; input.files can be a live list.
  const files = [...(event.target.files || [])];
  event.target.value = '';
  handleEncodeFiles(files);
});

encodeDrop.addEventListener('click', event => {
  if (event.target !== encodeFileInput) encodeFileInput.click();
});
encodeDrop.addEventListener('keydown', event => {
  if (event.target === encodeDrop && (event.key === 'Enter' || event.key === ' ')) {
    event.preventDefault();
    encodeFileInput.click();
  }
});
encodeDrop.addEventListener('dragover', event => {
  event.preventDefault();
  encodeDrop.classList.add('dragover');
});
encodeDrop.addEventListener('dragleave', event => {
  if (!encodeDrop.contains(event.relatedTarget)) encodeDrop.classList.remove('dragover');
});
encodeDrop.addEventListener('drop', event => {
  event.preventDefault();
  encodeDrop.classList.remove('dragover');
  handleEncodeFiles(event.dataTransfer?.files);
});

includePrefix.addEventListener('change', renderEncodeOutput);
wrapLines.addEventListener('change', renderEncodeOutput);

copyEncodeButton.addEventListener('click', () => {
  const text = encodeOutput.value;
  const form = includePrefix.checked ? 'Data URL' : 'Base64';
  copyText(text, encodeStatus, `已复制${form}（${formatNumber(text.length)} 字符）。`);
});

downloadEncodeButton.addEventListener('click', () => {
  if (!encodeFile || !encodeOutput.value) return;
  const filename = `${safeStem(encodeFile.name)}-base64.txt`;
  downloadBlob(new Blob([encodeOutput.value], { type: 'text/plain;charset=utf-8' }), filename);
  setStatus(encodeStatus, `已下载 ${filename}。原图未修改。`, 'success');
});

$('#clear-encode').addEventListener('click', () => {
  ++encodeRequestId;
  resetEncodeResult();
  encodeFileInput.value = '';
  setStatus(encodeStatus, '请选择一张图片开始转换。Base64 是编码方式，不是加密。');
});

decodeButton.addEventListener('click', decodeBase64ToImage);

decodeInput.addEventListener('keydown', event => {
  if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    decodeBase64ToImage();
  }
});
decodeInput.addEventListener('input', () => {
  decodeSourceName = '';
  if (decodeButton.disabled || !decodeResult.hidden) {
    ++decodeRequestId;
    resetDecodeResult();
    decodeButton.disabled = false;
    setStatus(decodeStatus, '输入已修改，请重新点击“解析为图片”。', 'warning');
  }
});
decodeInput.addEventListener('dragover', event => {
  if (event.dataTransfer && [...event.dataTransfer.types].includes('Files')) {
    event.preventDefault();
    decodeInput.classList.add('is-dragover');
  }
});
decodeInput.addEventListener('dragleave', () => decodeInput.classList.remove('is-dragover'));
decodeInput.addEventListener('drop', event => {
  const file = event.dataTransfer?.files?.[0];
  if (!file) return;
  event.preventDefault();
  decodeInput.classList.remove('is-dragover');
  loadDecodeTextFile(file);
});

decodeFileInput.addEventListener('change', event => {
  const file = event.target.files[0];
  event.target.value = '';
  loadDecodeTextFile(file);
});

copyDecodeButton.addEventListener('click', () => {
  copyText(decodeBase64, decodeStatus, `已复制规范 Base64（${formatNumber(decodeBase64.length)} 字符，不含 Data URL 前缀和空白）。`);
});

downloadDecodeButton.addEventListener('click', () => {
  if (!decodeBytes || !decodeDetected) return;
  const stem = decodeSourceName ? `${safeStem(decodeSourceName)}-decoded` : 'decoded-image';
  const filename = `${stem}-${timestampForName()}.${decodeDetected.extension}`;
  downloadBlob(new Blob([decodeBytes], { type: decodeDetected.mime }), filename);
  setStatus(decodeStatus, `已下载 ${filename}（${decodeDetected.label}，${formatBytes(decodeBytes.length)}）。`, 'success');
});

$('#clear-decode').addEventListener('click', () => {
  ++decodeRequestId;
  resetDecodeResult();
  decodeButton.disabled = false;
  decodeInput.value = '';
  decodeSourceName = '';
  decodeFileInput.value = '';
  setStatus(decodeStatus, '粘贴 Base64 或 Data URL，或从文本文件载入。');
});

window.addEventListener('dragover', event => {
  const target = event.target instanceof Element ? event.target : null;
  if (event.dataTransfer && [...event.dataTransfer.types].includes('Files') && !target?.closest('#encode-drop, #decode-input')) {
    event.preventDefault();
  }
});
window.addEventListener('drop', event => {
  const target = event.target instanceof Element ? event.target : null;
  if (event.dataTransfer && [...event.dataTransfer.types].includes('Files') && !target?.closest('#encode-drop, #decode-input')) {
    event.preventDefault();
  }
});

resetEncodeResult();
resetDecodeResult();
