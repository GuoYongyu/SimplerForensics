using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

public sealed class ApkSourceScanResult
{
    public List<Dictionary<string, object>> Urls { get; private set; }
    public List<Dictionary<string, object>> CodeFindings { get; private set; }
    public int UrlCount { get { return Urls.Count; } }

    public ApkSourceScanResult()
    {
        Urls = new List<Dictionary<string, object>>();
        CodeFindings = new List<Dictionary<string, object>>();
    }
}

public static class ApkSourceScanner
{
    private sealed class Rule
    {
        public readonly string Title;
        public readonly string Description;
        public readonly Regex Pattern;
        public readonly string[] Needles;
        public Rule(string title, string description, string pattern, params string[] needles)
        {
            Title = title;
            Description = description;
            Needles = needles;
            Pattern = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
        }
    }

    private sealed class RuleState
    {
        public int Count;
        public readonly object Sync = new object();
        public readonly List<Dictionary<string, object>> Evidence = new List<Dictionary<string, object>>();
    }

    private static readonly Regex UrlPattern = new Regex(
        @"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Rule[] Rules = new Rule[]
    {
        new Rule("网络通信", "引用 HTTP、Socket、OkHttp、Retrofit 或 WebSocket 等网络通信 API。", @"\b(HttpURLConnection|HttpsURLConnection|OkHttpClient|Retrofit|WebSocket|Socket|URL)\b|\b(okhttp3|retrofit2)\.", "HttpURLConnection", "HttpsURLConnection", "OkHttpClient", "Retrofit", "WebSocket", "Socket", "URL", "okhttp3", "retrofit2"),
        new Rule("位置与定位", "引用 Android 定位服务或位置更新 API。", @"\b(LocationManager|FusedLocationProviderClient|requestLocationUpdates|getLastKnownLocation)\b", "LocationManager", "FusedLocationProviderClient", "requestLocationUpdates", "getLastKnownLocation"),
        new Rule("相机与录音", "引用相机、音频采集或媒体录制 API。", @"\b(CameraManager|CameraDevice|CameraX|CameraCaptureSession|MediaRecorder|AudioRecord)\b", "CameraManager", "CameraDevice", "CameraX", "CameraCaptureSession", "MediaRecorder", "AudioRecord"),
        new Rule("WebView 与 JavaScript 桥接", "引用内嵌网页组件或 JavaScript 与原生代码桥接 API。", @"\b(WebView|addJavascriptInterface|setJavaScriptEnabled|evaluateJavascript)\b", "WebView", "addJavascriptInterface", "setJavaScriptEnabled", "evaluateJavascript"),
        new Rule("动态加载与反射", "引用动态加载 DEX、类加载器或反射 API。", @"\b(DexClassLoader|InMemoryDexClassLoader|PathClassLoader|Class\.forName|loadClass)\b", "DexClassLoader", "InMemoryDexClassLoader", "PathClassLoader", "Class.forName", "loadClass"),
        new Rule("进程与原生代码", "引用启动系统进程或加载原生库的 API。", @"\b(ProcessBuilder|Runtime\.getRuntime\(\)\.exec|System\.loadLibrary|System\.load)\b", "ProcessBuilder", "Runtime", "System.loadLibrary", "System.load"),
        new Rule("加密与摘要", "引用加密、密钥库或消息摘要 API。", @"\b(Cipher\.getInstance|MessageDigest\.getInstance|KeyStore\.getInstance|Mac\.getInstance)\b", "Cipher.getInstance", "MessageDigest.getInstance", "KeyStore.getInstance", "Mac.getInstance"),
        new Rule("设备标识与电话信息", "引用 Android ID、电话管理器或设备序列号相关 API。", @"\b(ANDROID_ID|TelephonyManager|Build\.SERIAL|getImei|getDeviceId)\b", "ANDROID_ID", "TelephonyManager", "Build.SERIAL", "getImei", "getDeviceId"),
        new Rule("无障碍与屏幕覆盖", "引用无障碍服务或覆盖其他应用窗口的相关 API。", @"\b(AccessibilityService|TYPE_APPLICATION_OVERLAY|SYSTEM_ALERT_WINDOW)\b", "AccessibilityService", "TYPE_APPLICATION_OVERLAY", "SYSTEM_ALERT_WINDOW"),
        new Rule("剪贴板", "引用读取或写入系统剪贴板的 API。", @"\b(ClipboardManager|ClipData\.newPlainText|getPrimaryClip)\b", "ClipboardManager", "ClipData.newPlainText", "getPrimaryClip"),
        new Rule("文件读写", "引用文件、流或共享存储访问 API。", @"\b(FileInputStream|FileOutputStream|RandomAccessFile|getExternalFilesDir|MediaStore)\b", "FileInputStream", "FileOutputStream", "RandomAccessFile", "getExternalFilesDir", "MediaStore")
    };

    private static bool ContainsNeedle(string line, string[] needles)
    {
        for (int i = 0; i < needles.Length; i++)
            if (line.IndexOf(needles[i], StringComparison.OrdinalIgnoreCase) >= 0) return true;
        return false;
    }

    public static ApkSourceScanResult Scan(string outputDirectory)
    {
        ApkSourceScanResult result = new ApkSourceScanResult();
        HashSet<string> seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        object urlSync = new object();
        RuleState[] states = new RuleState[Rules.Length];
        for (int i = 0; i < states.Length; i++) states[i] = new RuleState();

        List<string> files = new List<string>();
        foreach (string path in Directory.EnumerateFiles(outputDirectory, "*", SearchOption.AllDirectories))
        {
            string extension = Path.GetExtension(path);
            if (!extension.Equals(".java", StringComparison.OrdinalIgnoreCase)
                && !extension.Equals(".kt", StringComparison.OrdinalIgnoreCase)
                && !extension.Equals(".xml", StringComparison.OrdinalIgnoreCase)
                && !extension.Equals(".json", StringComparison.OrdinalIgnoreCase)) continue;
            if (files.Count >= 25000) break;
            try
            {
                if (new FileInfo(path).Length <= 12L * 1024L * 1024L) files.Add(path);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        Parallel.ForEach(files,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Min(Math.Max(Environment.ProcessorCount, 1), 8) },
            path =>
            {
                string relative = path.Substring(outputDirectory.Length)
                    .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                int lineNumber = 0;
                foreach (string sourceLine in File.ReadLines(path))
                {
                    lineNumber++;
                    string line = sourceLine.IndexOf("\\/", StringComparison.Ordinal) >= 0 ? sourceLine.Replace("\\/", "/") : sourceLine;
                    if (line.IndexOf("http", StringComparison.OrdinalIgnoreCase) >= 0) foreach (Match match in UrlPattern.Matches(line))
                    {
                        string url = match.Value.TrimEnd('.', ',', ';', ')', ']', '}', '"', '\'');
                        lock (urlSync)
                        {
                            if (result.Urls.Count >= 10000) break;
                            if (seenUrls.Add(url))
                            {
                                result.Urls.Add(new Dictionary<string, object>
                                {
                                    { "url", url }, { "file", relative }, { "line", lineNumber }
                                });
                            }
                        }
                    }

                    for (int ruleIndex = 0; ruleIndex < Rules.Length; ruleIndex++)
                    {
                        if (!ContainsNeedle(line, Rules[ruleIndex].Needles)) continue;
                        Match match = Rules[ruleIndex].Pattern.Match(line);
                        if (!match.Success) continue;
                        RuleState state = states[ruleIndex];
                        lock (state.Sync)
                        {
                            state.Count++;
                            if (state.Evidence.Count < 30)
                            {
                                string snippet = line.Trim();
                                if (snippet.Length > 240) snippet = snippet.Substring(0, 240);
                                state.Evidence.Add(new Dictionary<string, object>
                                {
                                    { "api", match.Value }, { "file", relative },
                                    { "line", lineNumber }, { "snippet", snippet }
                                });
                            }
                        }
                    }
                }
            });

        for (int i = 0; i < Rules.Length; i++)
        {
            if (states[i].Count == 0) continue;
            Dictionary<string, object> finding = new Dictionary<string, object>
            {
                { "title", Rules[i].Title },
                { "description", Rules[i].Description },
                { "count", states[i].Count },
                { "evidence", states[i].Evidence }
            };
            result.CodeFindings.Add(finding);
        }
        return result;
    }
}