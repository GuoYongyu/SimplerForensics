$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$tools = Join-Path $root 'tools\jadx'
$version = '1.5.6'
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
$jadxZip = Join-Path $temp "jadx-$version.zip"
$jadxUrl = "https://github.com/skylot/jadx/releases/download/v$version/jadx-$version.zip"
$runtimes = @(
  @{ Key = 'mac-arm64'; Os = 'mac'; Arch = 'aarch64'; Format = 'tar.gz' },
  @{ Key = 'mac-x64'; Os = 'mac'; Arch = 'x64'; Format = 'tar.gz' },
  @{ Key = 'linux-arm64'; Os = 'linux'; Arch = 'aarch64'; Format = 'tar.gz' },
  @{ Key = 'linux-x64'; Os = 'linux'; Arch = 'x64'; Format = 'tar.gz' },
  @{ Key = 'windows-x64'; Os = 'windows'; Arch = 'x64'; Format = 'zip' }
)

try {
  $jadxExtract = Join-Path $temp 'jadx'
  $runtimeRoot = Join-Path $temp 'runtimes'
  New-Item -ItemType Directory -Path $temp, $jadxExtract, $runtimeRoot -Force | Out-Null
  Write-Host "Downloading shared JADX $version CLI..."
  Invoke-WebRequest -Uri $jadxUrl -OutFile $jadxZip
  Expand-Archive -Path $jadxZip -DestinationPath $jadxExtract -Force
  $jadxScript = Get-ChildItem -Path $jadxExtract -Filter 'jadx.bat' -File -Recurse | Select-Object -First 1
  if ($null -eq $jadxScript) { throw 'The JADX archive did not contain bin\jadx.bat.' }
  $jadxRoot = $jadxScript.Directory.Parent.FullName

  foreach ($runtime in $runtimes) {
    $archiveName = "$($runtime.Key).$($runtime.Format)"
    $archive = Join-Path $temp $archiveName
    $extractTo = Join-Path $temp "extract-$($runtime.Key)"
    $url = "https://api.adoptium.net/v3/binary/latest/17/ga/$($runtime.Os)/$($runtime.Arch)/jre/hotspot/normal/eclipse?project=jdk"
    Write-Host "Downloading portable JRE 17: $($runtime.Key)..."
    Invoke-WebRequest -Uri $url -OutFile $archive
    New-Item -ItemType Directory -Path $extractTo -Force | Out-Null
    if ($runtime.Format -eq 'zip') {
      Expand-Archive -Path $archive -DestinationPath $extractTo -Force
    } else {
      & tar.exe -xzf $archive -C $extractTo
      if ($LASTEXITCODE -ne 0) { throw "Unable to extract $archiveName." }
    }
    $java = Get-ChildItem -Path $extractTo -Filter 'java.exe' -File -Recurse | Select-Object -First 1
    if ($null -eq $java) { throw "JRE package $($runtime.Key) did not contain java.exe." }
    $runtimeHome = $java.Directory.Parent.FullName
    $normalized = Join-Path $runtimeRoot $runtime.Key
    New-Item -ItemType Directory -Path $normalized -Force | Out-Null
    Copy-Item -Path (Join-Path $runtimeHome '*') -Destination $normalized -Recurse -Force
  }

  if (Test-Path $tools) { Remove-Item -Path $tools -Recurse -Force }
  New-Item -ItemType Directory -Path (Join-Path $tools 'app'), (Join-Path $tools 'runtime') -Force | Out-Null
  Copy-Item -Path (Join-Path $jadxRoot '*') -Destination (Join-Path $tools 'app') -Recurse -Force
  Copy-Item -Path (Join-Path $runtimeRoot '*') -Destination (Join-Path $tools 'runtime') -Recurse -Force
  @'
@echo off
set "TOOLS_DIR=%~dp0"
set "JAVA_HOME=%TOOLS_DIR%runtime\windows-x64"
set "PATH=%JAVA_HOME%\bin;%PATH%"
call "%TOOLS_DIR%app\bin\jadx.bat" %*
'@ | Set-Content -Path (Join-Path $tools 'bin-jadx.cmd') -Encoding ASCII
  Write-Host "Unified portable runtime package installed in $tools"
  Write-Host 'Includes macOS Intel/Apple Silicon, Linux x64/ARM64, and Windows x64. Java does not need to be installed on target computers.'
  & (Join-Path $tools 'bin-jadx.cmd') --version
  $bundle = Join-Path $root 'jadx-portable-bundle.zip'
  if (Test-Path $bundle) { Remove-Item -Path $bundle -Force }
  Compress-Archive -Path $tools -DestinationPath $bundle -CompressionLevel Optimal
  Write-Host "Portable transfer bundle: $bundle"
} finally {
  Remove-Item -Path $temp -Recurse -Force -ErrorAction SilentlyContinue
}
