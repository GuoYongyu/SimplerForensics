#!/bin/sh
set -eu

APP_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TOOLS_DIR="$APP_DIR/tools/jadx"
VERSION="1.5.6"

if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
  echo "需要系统自带的 curl、unzip 和 tar。" >&2
  exit 1
fi
if ! command -v zip >/dev/null 2>&1; then
  echo "需要 zip 命令来生成可复制的统一便携包。" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM
mkdir -p "$TMP_DIR/jadx" "$TMP_DIR/runtimes"
JADX_URL="https://github.com/skylot/jadx/releases/download/v${VERSION}/jadx-${VERSION}.zip"
echo "正在下载统一 JADX ${VERSION} CLI（只下载一次）…"
curl --fail --location --retry 3 "$JADX_URL" -o "$TMP_DIR/jadx.zip"
unzip -q "$TMP_DIR/jadx.zip" -d "$TMP_DIR/jadx"
JADX_SCRIPT="$(find "$TMP_DIR/jadx" -type f -path '*/bin/jadx' -print -quit)"
if [ -z "$JADX_SCRIPT" ]; then echo "未找到 JADX CLI 启动脚本。" >&2; exit 1; fi
JADX_ROOT="$(dirname "$(dirname "$JADX_SCRIPT")")"

download_jre() {
  key="$1"; os="$2"; arch="$3"; format="$4"
  archive="$TMP_DIR/${key}.${format}"
  url="https://api.adoptium.net/v3/binary/latest/17/ga/${os}/${arch}/jre/hotspot/normal/eclipse?project=jdk"
  curl --fail --location --retry 5 --retry-all-errors --retry-delay 2 --silent --show-error "$url" -o "$archive" >"$TMP_DIR/${key}.download.log" 2>&1
}

install_jre() {
  key="$1"; format="$2"
  archive="$TMP_DIR/${key}.${format}"
  echo "正在准备独立 JRE 17：${key}…"
  destination="$TMP_DIR/runtimes/$key"
  mkdir -p "$destination"
  if [ "$format" = zip ]; then unzip -q "$archive" -d "$destination"; else tar -xzf "$archive" -C "$destination"; fi
  java_bin="$(find "$destination" \( -path '*/bin/java' -o -path '*/bin/java.exe' \) -print -quit)"
  if [ -z "$java_bin" ]; then echo "未能在 ${key} 运行时包中找到 java。" >&2; exit 1; fi
  java_home="$(dirname "$(dirname "$java_bin")")"
  normalized="$TMP_DIR/runtime-$key"
  mkdir -p "$normalized"
  cp -R "$java_home"/. "$normalized/"
  rm -rf "$destination"
  mv "$normalized" "$TMP_DIR/runtimes/$key"
}

# Fetch platform runtimes concurrently; expand and normalize them after all downloads finish.
download_jre mac-arm64 mac aarch64 tar.gz & p1=$!
download_jre mac-x64 mac x64 tar.gz & p2=$!
download_jre linux-arm64 linux aarch64 tar.gz & p3=$!
download_jre linux-x64 linux x64 tar.gz & p4=$!
download_jre windows-x64 windows x64 zip & p5=$!
wait "$p1" || { cat "$TMP_DIR/mac-arm64.download.log" >&2; exit 1; }
wait "$p2" || { cat "$TMP_DIR/mac-x64.download.log" >&2; exit 1; }
wait "$p3" || { cat "$TMP_DIR/linux-arm64.download.log" >&2; exit 1; }
wait "$p4" || { cat "$TMP_DIR/linux-x64.download.log" >&2; exit 1; }
wait "$p5" || { cat "$TMP_DIR/windows-x64.download.log" >&2; exit 1; }
install_jre mac-arm64 tar.gz
install_jre mac-x64 tar.gz
install_jre linux-arm64 tar.gz
install_jre linux-x64 tar.gz
install_jre windows-x64 zip

rm -rf "$TOOLS_DIR"
mkdir -p "$TOOLS_DIR/app" "$TOOLS_DIR/runtime"
cp -R "$JADX_ROOT"/. "$TOOLS_DIR/app/"
cp -R "$TMP_DIR/runtimes"/. "$TOOLS_DIR/runtime/"
cat > "$TOOLS_DIR/bin-jadx" <<'EOF'
#!/bin/sh
TOOLS_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS:$ARCH" in
  darwin:arm64|darwin:aarch64) RUNTIME="mac-arm64" ;;
  darwin:x86_64|darwin:amd64) RUNTIME="mac-x64" ;;
  linux:arm64|linux:aarch64) RUNTIME="linux-arm64" ;;
  linux:x86_64|linux:amd64) RUNTIME="linux-x64" ;;
  *) echo "当前平台没有预装 JADX 运行时：$OS/$ARCH" >&2; exit 1 ;;
esac
export JAVA_HOME="$TOOLS_DIR/runtime/$RUNTIME"
export PATH="$JAVA_HOME/bin:$PATH"
exec "$TOOLS_DIR/app/bin/jadx" "$@"
EOF
cat > "$TOOLS_DIR/bin-jadx.cmd" <<'EOF'
@echo off
set "TOOLS_DIR=%~dp0"
set "JAVA_HOME=%TOOLS_DIR%runtime\windows-x64"
set "PATH=%JAVA_HOME%\bin;%PATH%"
call "%TOOLS_DIR%app\bin\jadx.bat" %*
EOF
chmod +x "$TOOLS_DIR/bin-jadx" "$TOOLS_DIR/app/bin/jadx"
echo "统一运行包已安装到 ${TOOLS_DIR}。"
echo "包含 macOS Intel/Apple Silicon、Linux x64/ARM64 和 Windows x64；目标电脑无需预装 Java。"
"$TOOLS_DIR/bin-jadx" --version
(cd "$APP_DIR/tools" && zip -qr "$APP_DIR/jadx-portable-bundle.zip" jadx)
echo "可迁移压缩包：$APP_DIR/jadx-portable-bundle.zip"
