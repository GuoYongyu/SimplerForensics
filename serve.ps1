$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
Add-Type -Path (Join-Path $PSScriptRoot 'scripts/ApkSourceScanner.cs')
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
Write-Host "SimplerForensics is running at $url (local machine only). Press Ctrl+C to stop."
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

function Resolve-JadxCommand {
  $candidates = @()
  if (-not [string]::IsNullOrWhiteSpace($env:JADX_BIN)) { $candidates += $env:JADX_BIN }
  $candidates += (Join-Path $PSScriptRoot 'tools/jadx/bin-jadx.cmd')
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
  }
  $found = Get-Command jadx -ErrorAction SilentlyContinue
  if ($null -ne $found -and -not [string]::IsNullOrWhiteSpace($found.Source)) { return $found.Source }
  return $null
}

function New-JadxProcessStartInfo([string]$jadx, [string]$jadxArguments) {
  $commandProcessor = $env:ComSpec
  if ([string]::IsNullOrWhiteSpace($commandProcessor)) { $commandProcessor = Join-Path $env:SystemRoot 'System32/cmd.exe' }
  if (-not (Test-Path -LiteralPath $commandProcessor -PathType Leaf)) { throw '无法找到 Windows 命令处理器 cmd.exe。' }
  $quote = [string][char]34
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $commandProcessor
  $jadxCommand = $quote + $jadx + $quote + ' ' + $jadxArguments
  # /s /c requires an outer quote pair so cmd.exe preserves quoted paths with spaces.
  $psi.Arguments = '/d /s /c ' + $quote + $jadxCommand + $quote
  $psi.WorkingDirectory = $PSScriptRoot
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  return $psi
}

function Invoke-JadxVersion($context) {
  if ($context.Request.HttpMethod -ne 'GET') {
    $context.Response.Headers['Allow'] = 'GET'
    Send-Json $context 405 @{ error = '此接口只接受 GET 请求。' }
    return
  }
  $jadx = Resolve-JadxCommand
  if (-not $jadx) { Send-Json $context 503 @{ error = '未找到 JADX 运行包。' }; return }
  try {
    $process = [System.Diagnostics.Process]::Start((New-JadxProcessStartInfo $jadx '--version'))
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(30000)) {
      $process.Kill()
      $process.WaitForExit()
      Send-Json $context 504 @{ error = '读取 JADX 版本超时。' }
      return
    }
    $version = ($stdoutTask.Result + [Environment]::NewLine + $stderrTask.Result).Trim()
    if ($process.ExitCode -ne 0 -or -not $version) { Send-Json $context 503 @{ error = '无法读取 JADX 版本。' }; return }
    Send-Json $context 200 @{ tool = 'jadx'; version = $version }
  } catch {
    Send-Json $context 500 @{ error = ('读取 JADX 版本失败：' + $_.Exception.Message) }
  }
}
function Invoke-JadxAnalysis($context) {
  $origin = $context.Request.Headers['Origin']
  if ($origin -and $origin -notmatch '^http://(127\.0\.0\.1|localhost)(:\d+)?$') {
    Send-Json $context 403 @{ error = '只允许本机 SimplerForensics 页面调用分析接口。' }
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

  $jadx = Resolve-JadxCommand
  if (-not $jadx) {
    Send-Json $context 503 @{ error = '未找到 JADX 运行包。请运行 scripts/setup-jadx.ps1 下载统一便携包，无需安装 Java。' }
    return
  }
  $work = Join-Path ([System.IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $work -Force | Out-Null
  try {
    $apk = Join-Path $work 'input.apk'
    $output = Join-Path $work 'decoded'
    $stream = [System.IO.File]::Create($apk)
    try { $context.Request.InputStream.CopyTo($stream) } finally { $stream.Dispose() }
    $threadCount = [Math]::Min([Math]::Max([Environment]::ProcessorCount, 1), 8)
    $quote = [string][char]34
    $jadxArguments = '--log-level ERROR --threads-count ' + $threadCount + ' --decompilation-mode simple --output-dir ' + $quote + $output + $quote + ' ' + $quote + $apk + $quote
    $psi = New-JadxProcessStartInfo $jadx $jadxArguments
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

    $scanResult = [ApkSourceScanner]::Scan($output)
    $urls = $scanResult.Urls
    $codeFindingResults = $scanResult.CodeFindings
    $jadxWarning = $null
    if ($process.ExitCode -ne 0) {
      $jadxWarning = 'JADX 已生成 Manifest，但反编译进程退出码为 ' + $process.ExitCode + '；代码和网址结果可能不完整。'
      $log = $stderrTask.Result + [Environment]::NewLine + $stdoutTask.Result
      $diagnostics = @($log -split '\r?\n' | Where-Object { $_ -match '^\s*ERROR\s*-' } | Select-Object -First 8)
      $detail = ($diagnostics -join '；').Trim()
      if ($detail) { $jadxWarning += ' 诊断信息：' + $detail }
    }
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
      urls = $scanResult.Urls
      urlCount = $scanResult.UrlCount
      codeFindings = $codeFindingResults
      sourcesScanned = $true
      jadxExitCode = $process.ExitCode
      analysisComplete = ($process.ExitCode -eq 0)
      warning = $jadxWarning
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
      if ($relative -eq 'api/apk/version') {
        Invoke-JadxVersion $context
        continue
      }
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
