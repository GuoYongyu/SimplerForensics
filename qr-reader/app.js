const $ = selector => document.querySelector(selector);
const fileInput = $('#file');
const drop = $('#drop');
const status = $('#status');
const resultLayout = $('#result-layout');
const output = $('#output');
const copyButton = $('#copy');
let previewUrl = null;
let requestId = 0;

function setStatus(message, kind = '') {
  status.className = `status${kind ? ` ${kind}` : ''}`;
  status.textContent = message;
}

function* enhanceContrast(pixels) {
  const { data, width, height } = pixels;
  const gray = new Uint8Array(width * height);
  const histogram = new Uint32Array(256);
  for (let i = 0, p = 0; i < data.length; i += 4, p++) {
    const value = Math.round(data[i] * 0.299 + data[i + 1] * 0.587 + data[i + 2] * 0.114);
    gray[p] = value;
    histogram[value]++;
  }
  const total = gray.length;
  let low = 0, high = 255;
  let seen = 0;
  for (let value = 0; value < 256; value++) { seen += histogram[value]; if (seen >= total * 0.02) { low = value; break; } }
  seen = 0;
  for (let value = 255; value >= 0; value--) { seen += histogram[value]; if (seen >= total * 0.02) { high = value; break; } }
  const range = Math.max(high - low, 1);

  // Otsu's threshold works well on unevenly lit photos after contrast stretching.
  let weighted = 0;
  for (let value = 0; value < 256; value++) weighted += value * histogram[value];
  let backgroundWeight = 0, backgroundSum = 0, bestVariance = -1, threshold = 127;
  for (let value = 0; value < 256; value++) {
    backgroundWeight += histogram[value];
    if (!backgroundWeight) continue;
    const foregroundWeight = total - backgroundWeight;
    if (!foregroundWeight) break;
    backgroundSum += value * histogram[value];
    const difference = backgroundSum / backgroundWeight - (weighted - backgroundSum) / foregroundWeight;
    const variance = backgroundWeight * foregroundWeight * difference * difference;
    if (variance > bestVariance) { bestVariance = variance; threshold = value; }
  }
  threshold = Math.max(0, Math.min(255, Math.round((threshold - low) * 255 / range)));

  const contrastData = new Uint8ClampedArray(data.length);
  const binaryData = new Uint8ClampedArray(data.length);
  for (let p = 0, i = 0; p < gray.length; p++, i += 4) {
    const value = Math.max(0, Math.min(255, Math.round((gray[p] - low) * 255 / range)));
    contrastData[i] = contrastData[i + 1] = contrastData[i + 2] = value;
    contrastData[i + 3] = 255;
    const binary = value > threshold ? 255 : 0;
    binaryData[i] = binaryData[i + 1] = binaryData[i + 2] = binary;
    binaryData[i + 3] = 255;
  }
  yield { data: contrastData, width, height };
  yield { data: binaryData, width, height };
}

function rotatedImageData(canvas, degrees) {
  const sideways = degrees === 90 || degrees === 270;
  const rotated = document.createElement('canvas');
  rotated.width = sideways ? canvas.height : canvas.width;
  rotated.height = sideways ? canvas.width : canvas.height;
  const context = rotated.getContext('2d', { willReadFrequently: true });
  if (!context) return null;
  context.translate(rotated.width / 2, rotated.height / 2);
  context.rotate(degrees * Math.PI / 180);
  context.drawImage(canvas, -canvas.width / 2, -canvas.height / 2);
  return context.getImageData(0, 0, rotated.width, rotated.height);
}

async function decodeQr(image, canvas, pixels) {
  let decoded = jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: 'attemptBoth' });
  if (decoded) return decoded;

  if ('BarcodeDetector' in window) {
    try {
      const detector = new BarcodeDetector({ formats: ['qr_code'] });
      const barcodes = await detector.detect(image);
      if (barcodes.length && barcodes[0].rawValue) return { data: barcodes[0].rawValue };
    } catch { /* Continue with the local decoder fallbacks. */ }
  }

  for (const variant of enhanceContrast(pixels)) {
    decoded = jsQR(variant.data, variant.width, variant.height, { inversionAttempts: 'attemptBoth' });
    if (decoded) return decoded;
  }
  for (const degrees of [90, 180, 270]) {
    const rotated = rotatedImageData(canvas, degrees);
    if (!rotated) continue;
    decoded = jsQR(rotated.data, rotated.width, rotated.height, { inversionAttempts: 'attemptBoth' });
    if (decoded) return decoded;
  }
  return null;
}

function showFile(file) {
  if (!file) return;
  const id = ++requestId;
  output.value = '';
  copyButton.disabled = true;
  resultLayout.hidden = false;

  if (!file.type.startsWith('image/')) {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    previewUrl = null;
    $('#preview').removeAttribute('src');
    $('#image-info').textContent = '';
    setStatus('请选择图片文件。', 'error');
    return;
  }

  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = URL.createObjectURL(file);
  const preview = $('#preview');
  preview.src = previewUrl;
  $('#image-info').textContent = `${file.name} · ${(file.size / 1024).toLocaleString('zh-CN', { maximumFractionDigits: 1 })} KB`;
  setStatus('正在读取图片并查找二维码…');

  const image = new Image();
  image.onload = async () => {
    if (id !== requestId) return;
    try {
      const maxSide = 4096;
      const maxPixels = 24_000_000;
      const scale = Math.min(1, maxSide / Math.max(image.naturalWidth, image.naturalHeight), Math.sqrt(maxPixels / (image.naturalWidth * image.naturalHeight)));
      const width = Math.max(1, Math.round(image.naturalWidth * scale));
      const height = Math.max(1, Math.round(image.naturalHeight * scale));
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const context = canvas.getContext('2d', { willReadFrequently: true });
      if (!context) throw new Error('浏览器无法读取图片像素。');
      context.drawImage(image, 0, 0, width, height);
      const pixels = context.getImageData(0, 0, width, height);
      const decoded = await decodeQr(image, canvas, pixels);
      if (!decoded) {
        setStatus('没有在这张图片中找到可识别的二维码。请尝试更清晰、完整、对比度更高的图片。', 'warning');
        return;
      }
      output.value = decoded.data;
      copyButton.disabled = false;
      const resizeNote = scale < 1 ? `（已缩放至 ${width} × ${height} 像素进行识别）` : '';
      setStatus(`识别成功${resizeNote}`, 'success');
      output.focus();
      output.select();
    } catch (error) {
      setStatus(`识别失败：${error.message || '无法读取图片。'}`, 'error');
    }
  };
  image.onerror = () => {
    if (id === requestId) setStatus('无法打开这张图片。请换一个常见图片格式后重试。', 'error');
  };
  image.src = previewUrl;
}

fileInput.addEventListener('change', event => showFile(event.target.files[0]));
drop.addEventListener('click', event => {
  if (event.target !== fileInput) fileInput.click();
});
drop.addEventListener('dragover', event => {
  event.preventDefault();
  drop.classList.add('dragover');
});
drop.addEventListener('dragleave', event => {
  if (!drop.contains(event.relatedTarget)) drop.classList.remove('dragover');
});
drop.addEventListener('drop', event => {
  event.preventDefault();
  drop.classList.remove('dragover');
  showFile(event.dataTransfer.files[0]);
});
drop.addEventListener('keydown', event => {
  if (event.target === drop && (event.key === 'Enter' || event.key === ' ')) {
    event.preventDefault();
    fileInput.click();
  }
});
$('#copy').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(output.value);
    setStatus('已复制识别内容。', 'success');
  } catch {
    output.focus();
    output.select();
    setStatus('浏览器未允许直接访问剪贴板，识别内容已选中，请按 Ctrl+C 或 ⌘C 复制。', 'warning');
  }
});
$('#clear').addEventListener('click', () => {
  requestId++;
  fileInput.value = '';
  output.value = '';
  copyButton.disabled = true;
  resultLayout.hidden = true;
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;
  $('#preview').removeAttribute('src');
  setStatus('选择一张包含二维码的图片开始识别。');
});
