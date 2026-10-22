require 'webrick'
require 'json'
require 'open3'
require 'tmpdir'
require 'tempfile'
require 'timeout'
require 'find'
require 'rexml/document'

ROOT = File.expand_path(__dir__)
MAX_APK_SIZE = 1024 * 1024 * 1024
ANALYSIS_TIMEOUT = 300
URL_PATTERN = %r{https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+}i
CODE_RULES = [
  { title: '网络通信', description: '引用 HTTP、Socket、OkHttp、Retrofit 或 WebSocket 等网络通信 API。', pattern: /\b(?:HttpURLConnection|HttpsURLConnection|OkHttpClient|Retrofit|WebSocket|Socket|URL)\b|\b(?:okhttp3|retrofit2)\./i },
  { title: '位置与定位', description: '引用 Android 定位服务或位置更新 API。', pattern: /\b(?:LocationManager|FusedLocationProviderClient|requestLocationUpdates|getLastKnownLocation)\b/i },
  { title: '相机与录音', description: '引用相机、音频录制或媒体录制 API。', pattern: /\b(?:CameraManager|CameraDevice|CameraX|CameraCaptureSession|MediaRecorder|AudioRecord)\b/i },
  { title: '麦克风与音频输入', description: '引用音频采集 API；是否录音还取决于调用路径和运行时授权。', pattern: /\b(?:AudioRecord|VOICE_RECOGNITION|MICROPHONE)\b/i },
  { title: 'WebView 与 JavaScript 桥接', description: '引用内嵌网页组件或 JavaScript 与原生代码桥接 API。', pattern: /\b(?:WebView|addJavascriptInterface|setJavaScriptEnabled|evaluateJavascript)\b/i },
  { title: '动态加载与反射', description: '引用动态加载 DEX、类加载器或反射 API。', pattern: /\b(?:DexClassLoader|InMemoryDexClassLoader|PathClassLoader|Class\.forName|loadClass)\b/i },
  { title: '进程与原生代码', description: '引用启动系统进程或加载原生库的 API。', pattern: /\b(?:ProcessBuilder|Runtime\.getRuntime\(\)\.exec|System\.loadLibrary|System\.load)\b/i },
  { title: '加密与摘要', description: '引用加密、密钥库或消息摘要 API。', pattern: /\b(?:Cipher\.getInstance|MessageDigest\.getInstance|KeyStore\.getInstance|Mac\.getInstance)\b/i },
  { title: '设备标识与电话信息', description: '引用 Android ID、电话管理器或设备序列号相关 API。', pattern: /\b(?:ANDROID_ID|TelephonyManager|Build\.SERIAL|getImei|getDeviceId)\b/i },
  { title: '无障碍与屏幕覆盖', description: '引用无障碍服务或覆盖其他应用窗口的相关 API。', pattern: /\b(?:AccessibilityService|TYPE_APPLICATION_OVERLAY|SYSTEM_ALERT_WINDOW)\b/i },
  { title: '剪贴板', description: '引用读取或写入系统剪贴板的 API。', pattern: /\b(?:ClipboardManager|ClipData\.newPlainText|getPrimaryClip)\b/i },
  { title: '文件读写', description: '引用文件、流或共享存储访问 API。', pattern: /\b(?:FileInputStream|FileOutputStream|RandomAccessFile|getExternalFilesDir|MediaStore)\b/i }
].freeze

def response_json(response, code, data)
  response.status = code
  response['Content-Type'] = 'application/json; charset=utf-8'
  response['Cache-Control'] = 'no-store'
  response.body = JSON.generate(data)
end

def find_jadx
  configured = ENV['JADX_BIN']
  candidates = [configured, File.join(ROOT, 'tools', 'jadx', 'bin-jadx'), File.join(ROOT, 'tools', 'jadx', 'bin', 'jadx'), 'jadx'].compact
  candidates.each do |candidate|
    if candidate.include?(File::SEPARATOR)
      return candidate if File.file?(candidate) && File.executable?(candidate)
    else
      ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |dir|
        path = File.join(dir, candidate)
        return path if File.file?(path) && File.executable?(path)
      end
    end
  end
  nil
end

def launcher_names(root)
  package = root.attributes['package'].to_s
  found = []
  root.elements.each('application/*') do |component|
    next unless %w[activity activity-alias].include?(component.name)
    is_main = false
    is_launcher = false
    component.elements.each('intent-filter/action') do |action|
      is_main ||= action.attributes['android:name'] == 'android.intent.action.MAIN'
    end
    component.elements.each('intent-filter/category') do |category|
      is_launcher ||= category.attributes['android:name'] == 'android.intent.category.LAUNCHER'
    end
    next unless is_main && is_launcher
    name = component.attributes['android:name'].to_s
    name = "#{package}#{name}" if name.start_with?('.')
    name = "#{package}.#{name}" if !name.empty? && !name.include?('.')
    found << name unless name.empty?
  end
  found.uniq
end

def resolve_app_name(output_dir, label)
  match = /\A@string\/([A-Za-z0-9_.]+)\z/.match(label.to_s)
  return label.to_s unless match
  resource_name = match[1]
  Dir.glob(File.join(output_dir, 'resources', 'res', 'values*', '*.xml')).each do |path|
    begin
      document = REXML::Document.new(File.read(path, encoding: 'UTF-8'))
      document.root&.elements&.each do |element|
        is_string = element.name == 'string' || (element.name == 'item' && element.attributes['type'] == 'string')
        next unless is_string && element.attributes['name'] == resource_name
        value = element.text.to_s.strip
        return value unless value.empty?
      end
    rescue REXML::ParseException, EncodingError
      next
    end
  end
  label.to_s
end

def collect_code_analysis(output_dir)
  urls = []
  seen_urls = {}
  findings = CODE_RULES.map { |rule| rule.merge(count: 0, evidence: []) }
  scanned_bytes = 0
  scanned_files = 0
  Find.find(output_dir) do |path|
    next unless File.file?(path) && %w[.java .kt .xml .json].include?(File.extname(path).downcase)
    break if scanned_files >= 25_000 || scanned_bytes >= 200 * 1024 * 1024
    size = File.size(path) rescue 0
    next if size > 12 * 1024 * 1024
    scanned_bytes += size
    scanned_files += 1
    relative = path.delete_prefix(output_dir + File::SEPARATOR)
    File.foreach(path).with_index(1) do |line, line_number|
      normalized = line.gsub('\\/', '/')
      normalized.scan(URL_PATTERN) do |match|
        url = match.sub(/[.,;:)\]}'"]+\z/, '')
        next if url.length < 10 || seen_urls[url]
        seen_urls[url] = true
        urls << { url: url, file: relative, line: line_number }
      end
      findings.each do |finding|
        next unless normalized.match?(finding[:pattern])
        finding[:count] += 1
        if finding[:evidence].length < 30
          finding[:evidence] << {
            api: finding[:pattern].match(normalized)&.to_s,
            file: relative,
            line: line_number,
            snippet: normalized.strip[0, 240]
          }
        end
      end
      break if urls.length >= 10_000
    end
  rescue EncodingError, IOError
    next
  end
  { urls: urls, findings: findings.select { |finding| finding[:count].positive? }.map { |finding| finding.reject { |key, _| key == :pattern } }, scannedFiles: scanned_files }
end

def run_jadx_analysis(request, response)
  origin = request['Origin']
  if origin && origin !~ %r{\Ahttp://(127\.0\.0\.1|localhost)(:\d+)?\z}i
    return response_json(response, 403, error: '只允许本机 SimplerForensics 页面调用分析接口。')
  end
  unless request.request_method == 'POST'
    response['Allow'] = 'POST'
    return response_json(response, 405, error: '此接口只接受 POST 请求。')
  end
  unless request.body && !request.body.empty?
    return response_json(response, 400, error: '没有收到 APK 文件。')
  end
  if request.body.bytesize > MAX_APK_SIZE
    return response_json(response, 413, error: 'APK 超过 1 GB 限制。')
  end

  jadx = find_jadx
  unless jadx
    return response_json(response, 503, error: '未找到 JADX 运行包。请运行 scripts/setup-jadx.sh（macOS/Linux）或 scripts/setup-jadx.ps1（Windows），无需安装 Java。')
  end

  Dir.mktmpdir('simplerforensic-jadx-') do |work_dir|
    apk_path = File.join(work_dir, 'input.apk')
    output_dir = File.join(work_dir, 'decoded')
    File.binwrite(apk_path, request.body)
    log_path = File.join(work_dir, 'jadx.log')
    command = [jadx, '--log-level', 'ERROR', '--threads-count', '4', '--output-dir', output_dir, apk_path]
    pid = Process.spawn(*command, out: log_path, err: [:child, :out])
    begin
      _pid, status = Timeout.timeout(ANALYSIS_TIMEOUT) { Process.wait2(pid) }
    rescue Timeout::Error
      Process.kill('TERM', pid) rescue nil
      sleep 1
      Process.kill('KILL', pid) rescue nil
      Process.wait(pid) rescue nil
      return response_json(response, 504, error: 'JADX 分析超过 5 分钟，已停止处理。')
    end

    manifest_path = File.join(output_dir, 'resources', 'AndroidManifest.xml')
    unless File.file?(manifest_path)
      details = File.file?(log_path) ? File.read(log_path, 4000).to_s.strip : ''
      exit_code = status.exitstatus || "signal #{status.termsig}"
      reason = status.success? ? 'JADX 没有生成解码后的 AndroidManifest.xml。' : "JADX 无法完成 APK 结构解析（退出码 #{exit_code}）。"
      reason += " #{details}" unless details.empty?
      return response_json(response, 422, error: reason)
    end

    document = REXML::Document.new(File.read(manifest_path, encoding: 'UTF-8'))
    root = document.root
    permissions = []
    root.elements.each('uses-permission') { |node| permissions << node.attributes['android:name'] if node.attributes['android:name'] }
    root.elements.each('uses-permission-sdk-23') { |node| permissions << node.attributes['android:name'] if node.attributes['android:name'] }
    app = root.elements['application']
    code_analysis = collect_code_analysis(output_dir)
    response_json(response, 200, {
      tool: 'jadx',
      metadata: {
        package: root.attributes['package'],
        versionName: root.attributes['android:versionName'],
        versionCode: root.attributes['android:versionCode'],
        minSdk: root.elements['uses-sdk']&.attributes&.[]('android:minSdkVersion'),
        targetSdk: root.elements['uses-sdk']&.attributes&.[]('android:targetSdkVersion'),
        appLabel: app&.attributes&.[]('android:label'),
        appName: resolve_app_name(output_dir, app&.attributes&.[]('android:label')),
        permissions: permissions.compact.uniq,
        launchers: launcher_names(root)
      },
      urls: code_analysis[:urls],
      urlCount: code_analysis[:urls].length,
      codeFindings: code_analysis[:findings],
      sourceFilesScanned: code_analysis[:scannedFiles],
      sourcesScanned: true,
      jadxExitCode: status.exitstatus,
      analysisComplete: status.success?,
      warning: status.success? ? nil : "JADX 已生成 Manifest，但反编译进程退出码为 #{status.exitstatus || status.termsig}；代码和网址结果可能不完整。"
    })
  rescue REXML::ParseException => error
    response_json(response, 422, error: "JADX 输出的 Manifest 无法解析：#{error.message}")
  rescue StandardError => error
    response_json(response, 500, error: "本地 JADX 分析失败：#{error.message}")
  end
end

server = WEBrick::HTTPServer.new(
  BindAddress: '127.0.0.1',
  Port: 0,
  DocumentRoot: ROOT,
  AccessLog: [],
  Logger: WEBrick::Log.new($stderr, WEBrick::Log::WARN)
)
server.mount_proc('/api/apk/analyze') { |request, response| run_jadx_analysis(request, response) }

port = server.listeners.first.addr[1]
url = "http://127.0.0.1:#{port}/index.html"
puts "SimplerForensics is running at #{url} (local machine only)."
STDOUT.flush
Thread.new { sleep 0.4; system('open', url) }
Signal.trap('INT') { Thread.new { server.shutdown } }
server.start
