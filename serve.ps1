$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
$listener = $null
$port = 8765

for ($candidate = 8765; $candidate -le 8785; $candidate++) {
  $tryListener = New-Object System.Net.HttpListener
  $tryListener.Prefixes.Add("http://127.0.0.1:$candidate/")
  try {
    $tryListener.Start()
    $listener = $tryListener
    $port = $candidate
    break
  } catch {
    $tryListener.Close()
  }
}

if ($null -eq $listener) {
  throw '无法在本机启动 HTTP 服务。请关闭占用 8765–8785 端口的程序后重试。'
}

$url = "http://127.0.0.1:$port/index.html"
Write-Host "SimplerForensic is running at $url (local machine only). Press Ctrl+C to stop."
Start-Process $url

$mime = @{
  '.html' = 'text/html; charset=utf-8'
  '.css' = 'text/css; charset=utf-8'
  '.js' = 'text/javascript; charset=utf-8'
  '.json' = 'application/json; charset=utf-8'
  '.txt' = 'text/plain; charset=utf-8'
  '.png' = 'image/png'
  '.jpg' = 'image/jpeg'
  '.jpeg' = 'image/jpeg'
  '.webp' = 'image/webp'
  '.svg' = 'image/svg+xml'
}

function Send-Json($context, [int]$statusCode, $data) {
  $context.Response.StatusCode = $statusCode
  $context.Response.ContentType = 'application/json; charset=utf-8'
  $context.Response.Headers['Cache-Control'] = 'no-store'
  $bytes = [System.Text.Encoding]::UTF8.GetBytes(($data | ConvertTo-Json -Depth 12 -Compress))
  $context.Response.ContentLength64 = $bytes.Length
  $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
  $context.Response.Close()
}

function Invoke-JadxAnalysis($context) {
  $origin = $context.Request.Headers['Origin']
  if ($origin -and $origin -notmatch '^http://(127\.0\.0\.1|localhost)(:\d+)?$') {
    Send-Json $context 403 @{ error = '只允许本机 SimplerForensic 页面调用分析接口。' }
    return
  }
  if ($context.Request.HttpMethod -ne 'POST') {
    $context.Response.Headers['Allow'] = 'POST'
    Send-Json $context 405 @{ error = '此接口只接受 POST 请求。' }
    return
  }
  if ($context.Request.ContentLength64 -le 0) {
    Send-Json $context 400 @{ error = '没有收到 APK 文件。' }
    return
  }
  if ($context.Request.ContentLength64 -gt 1GB) {
    Send-Json $context 413 @{ error = 'APK 超过 1 GB 限制。' }
    return
  }

  $jadx = $env:JADX_BIN
  if ([string]::IsNullOrWhiteSpace($jadx)) { $jadx = Join-Path $PSScriptRoot 'tools\jadx\bin-jadx.cmd' }
  if (-not (Test-Path -LiteralPath $jadx -PathType Leaf)) {
    $found = Get-Command jadx -ErrorAction SilentlyContinue
    if ($null -ne $found) { $jadx = $found.Source }
  }
  if (-not (Test-Path -LiteralPath $jadx -PathType Leaf)) {
    Send-Json $context 503 @{ error = '未找到 JADX 运行包。请运行 scripts\setup-jadx.ps1 下载统一便携包，无需安装 Java。' }
    return
  }

  $work = Join-Path ([System.IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $work -Force | Out-Null
  try {
    $apk = Join-Path $work 'input.apk'
    $output = Join-Path $work 'decoded'
    $stream = [System.IO.File]::Create($apk)
    try { $context.Request.InputStream.CopyTo($stream) } finally { $stream.Dispose() }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/d /s /c call "' + $jadx + '" --log-level ERROR --threads-count 4 --output-dir "' + $output + '" "' + $apk + '"'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(300000)) {
      $process.Kill()
      $process.WaitForExit()
      Send-Json $context 504 @{ error = 'JADX 分析超过 5 分钟，已停止处理。' }
      return
    }
    $manifestPath = Join-Path $output 'resources\AndroidManifest.xml'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
      $detail = ($stderrTask.Result + "`n" + $stdoutTask.Result).Trim()
      $message = "JADX 无法完成 APK 结构解析（退出码 $($process.ExitCode)）。"
      if ($detail) { $message += ' ' + $detail.Substring(0, [Math]::Min(3000, $detail.Length)) }
      Send-Json $context 422 @{ error = $message }
      return
    }

    [xml]$xml = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8
    $rootNode = $xml.DocumentElement
    $androidNs = 'http://schemas.android.com/apk/res/android'
    $attr = { param($node, $name) if ($null -ne $node) { $node.GetAttribute($name, $androidNs) } else { '' } }
    $sdkNode = $rootNode.SelectSingleNode('uses-sdk')
    $appNode = $rootNode.SelectSingleNode('application')
    $appLabel = & $attr $appNode 'label'
    $appName = $appLabel
    if ($appLabel -match '^@string/(.+)$') {
      $resourceName = $Matches[1]
      $valueFiles = Get-ChildItem -LiteralPath (Join-Path $output 'resources\res') -Filter '*.xml' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Directory.Name -like 'values*' }
      foreach ($valueFile in $valueFiles) {
        try {
          [xml]$valuesXml = Get-Content -LiteralPath $valueFile.FullName -Raw -Encoding UTF8
          foreach ($valueNode in $valuesXml.DocumentElement.ChildNodes) {
            $isString = ($valueNode.LocalName -eq 'string') -or ($valueNode.LocalName -eq 'item' -and $valueNode.GetAttribute('type') -eq 'string')
            if ($isString -and $valueNode.GetAttribute('name') -eq $resourceName -and $valueNode.InnerText.Trim()) {
              $appName = $valueNode.InnerText.Trim()
              break
            }
          }
          if ($appName -ne $appLabel) { break }
        } catch { }
      }
    }
    $permissions = @()
    foreach ($node in $rootNode.SelectNodes('/manifest/uses-permission | /manifest/uses-permission-sdk-23')) {
      $name = & $attr $node 'name'
      if ($name) { $permissions += $name }
    }
    $launchers = @()
    foreach ($component in $rootNode.SelectNodes('/manifest/application/activity | /manifest/application/activity-alias')) {
      $actions = @($component.SelectNodes('intent-filter/action') | ForEach-Object { $_.GetAttribute('name', $androidNs) })
      $categories = @($component.SelectNodes('intent-filter/category') | ForEach-Object { $_.GetAttribute('name', $androidNs) })
      if (($actions -contains 'android.intent.action.MAIN') -and ($categories -contains 'android.intent.category.LAUNCHER')) {
        $name = & $attr $component 'name'
        $pkg = $rootNode.GetAttribute('package')
        if ($name.StartsWith('.')) { $name = $pkg + $name } elseif ($name -and -not $name.Contains('.')) { $name = $pkg + '.' + $name }
        if ($name) { $launchers += $name }
      }
    }

    $urls = @()
    $seen = @{}
    $pattern = 'https?://[A-Za-z0-9._~:/?#\[\]@!$&''()*+,;=%-]+'
    $codeRules = @(
      @{ title = '网络通信'; description = '引用 HTTP、Socket、OkHttp、Retrofit 或 WebSocket 等网络通信 API。'; pattern = '\b(HttpURLConnection|HttpsURLConnection|OkHttpClient|Retrofit|WebSocket|Socket|URL)\b|\b(okhttp3|retrofit2)\.' },
      @{ title = '位置与定位'; description = '引用 Android 定位服务或位置更新 API。'; pattern = '\b(LocationManager|FusedLocationProviderClient|requestLocationUpdates|getLastKnownLocation)\b' },
      @{ title = '相机与录音'; description = '引用相机、音频采集或媒体录制 API。'; pattern = '\b(CameraManager|CameraDevice|CameraX|CameraCaptureSession|MediaRecorder|AudioRecord)\b' },
      @{ title = 'WebView 与 JavaScript 桥接'; description = '引用内嵌网页组件或 JavaScript 与原生代码桥接 API。'; pattern = '\b(WebView|addJavascriptInterface|setJavaScriptEnabled|evaluateJavascript)\b' },
      @{ title = '动态加载与反射'; description = '引用动态加载 DEX、类加载器或反射 API。'; pattern = '\b(DexClassLoader|InMemoryDexClassLoader|PathClassLoader|Class\.forName|loadClass)\b' },
      @{ title = '进程与原生代码'; description = '引用启动系统进程或加载原生库的 API。'; pattern = '\b(ProcessBuilder|Runtime\.getRuntime\(\)\.exec|System\.loadLibrary|System\.load)\b' },
      @{ title = '加密与摘要'; description = '引用加密、密钥库或消息摘要 API。'; pattern = '\b(Cipher\.getInstance|MessageDigest\.getInstance|KeyStore\.getInstance|Mac\.getInstance)\b' },
      @{ title = '设备标识与电话信息'; description = '引用 Android ID、电话管理器或设备序列号相关 API。'; pattern = '\b(ANDROID_ID|TelephonyManager|Build\.SERIAL|getImei|getDeviceId)\b' },
      @{ title = '无障碍与屏幕覆盖'; description = '引用无障碍服务或覆盖其他应用窗口的相关 API。'; pattern = '\b(AccessibilityService|TYPE_APPLICATION_OVERLAY|SYSTEM_ALERT_WINDOW)\b' },
      @{ title = '剪贴板'; description = '引用读取或写入系统剪贴板的 API。'; pattern = '\b(ClipboardManager|ClipData\.newPlainText|getPrimaryClip)\b' },
      @{ title = '文件读写'; description = '引用文件、流或共享存储访问 API。'; pattern = '\b(FileInputStream|FileOutputStream|RandomAccessFile|getExternalFilesDir|MediaStore)\b' }
    )
    $codeFindingStates = @{}
    foreach ($rule in $codeRules) {
      $codeFindingStates[$rule.title] = @{
        title = $rule.title
        description = $rule.description
        count = 0
        evidence = [System.Collections.Generic.List[object]]::new()
      }
    }
    $sourceFiles = Get-ChildItem -LiteralPath $output -Recurse -File | Where-Object { $_.Extension -in '.java', '.kt', '.xml', '.json' } | Select-Object -First 25000
    foreach ($source in $sourceFiles) {
      if ($source.Length -gt 12MB) { continue }
      $relative = $source.FullName.Substring($output.Length).TrimStart('\')
      $lineNo = 0
      foreach ($line in [System.IO.File]::ReadLines($source.FullName)) {
        $lineNo++
        $normalized = $line.Replace('\/', '/')
        foreach ($match in [regex]::Matches($normalized, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
          $url = $match.Value.TrimEnd([char[]]@('.', ',', ';', ')', ']', '}', '"', "'"))
          if (-not $seen.ContainsKey($url)) {
            $seen[$url] = $true
            $urls += @{ url = $url; file = $relative; line = $lineNo }
            if ($urls.Count -ge 10000) { break }
          }
        }
        foreach ($rule in $codeRules) {
          $match = [regex]::Match($normalized, $rule.pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
          if (-not $match.Success) { continue }
          $state = $codeFindingStates[$rule.title]
          $state.count++
          if ($state.evidence.Count -lt 30) {
            $snippet = $normalized.Trim()
            if ($snippet.Length -gt 240) { $snippet = $snippet.Substring(0, 240) }
            [void]$state.evidence.Add(@{ api = $match.Value; file = $relative; line = $lineNo; snippet = $snippet })
          }
        }
        if ($urls.Count -ge 10000) { break }
      }
      if ($urls.Count -ge 10000) { break }
    }
    $codeFindingResults = @($codeRules | ForEach-Object { $codeFindingStates[$_.title] } | Where-Object { $_.count -gt 0 })
    Send-Json $context 200 @{
      tool = 'jadx'
      metadata = @{
        package = $rootNode.GetAttribute('package')
        versionName = (& $attr $rootNode 'versionName')
        versionCode = (& $attr $rootNode 'versionCode')
        minSdk = (& $attr $sdkNode 'minSdkVersion')
        targetSdk = (& $attr $sdkNode 'targetSdkVersion')
        appLabel = $appLabel
        appName = $appName
        permissions = @($permissions | Select-Object -Unique)
        launchers = @($launchers | Select-Object -Unique)
      }
      urls = $urls
      urlCount = $urls.Count
      codeFindings = $codeFindingResults
      sourcesScanned = $true
      jadxExitCode = $process.ExitCode
      analysisComplete = ($process.ExitCode -eq 0)
      warning = if ($process.ExitCode -eq 0) { $null } else { "JADX 已生成 Manifest，但反编译进程退出码为 $($process.ExitCode)；代码和网址结果可能不完整。" }
    }
  } catch {
    Send-Json $context 500 @{ error = "本地 JADX 分析失败：$($_.Exception.Message)" }
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
}

try {
  while ($listener.IsListening) {
    $context = $listener.GetContext()
    try {
      $relative = [Uri]::UnescapeDataString($context.Request.Url.AbsolutePath.TrimStart('/'))
      if ($relative -eq 'api/apk/analyze') {
        Invoke-JadxAnalysis $context
        continue
      }
      if ([string]::IsNullOrWhiteSpace($relative)) { $relative = 'index.html' }
      $file = [System.IO.Path]::GetFullPath((Join-Path $root $relative))
      if (-not $file.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        $context.Response.StatusCode = 403
        $bytes = [System.Text.Encoding]::UTF8.GetBytes('Forbidden')
      } elseif (-not [System.IO.File]::Exists($file)) {
        $context.Response.StatusCode = 404
        $bytes = [System.Text.Encoding]::UTF8.GetBytes('Not found')
      } else {
        $context.Response.StatusCode = 200
        $extension = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
        if ($mime.ContainsKey($extension)) { $context.Response.ContentType = $mime[$extension] }
        else { $context.Response.ContentType = 'application/octet-stream' }
        $bytes = [System.IO.File]::ReadAllBytes($file)
      }
      $context.Response.ContentLength64 = $bytes.Length
      if ($context.Request.HttpMethod -ne 'HEAD') {
        $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
      }
      $context.Response.Close()
    } catch {
      try { $context.Response.StatusCode = 500; $context.Response.Close() } catch {}
    }
  }
} finally {
  $listener.Stop()
  $listener.Close()
}
