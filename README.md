# LittleTools

离线本地工具合集，使用原生 HTML、CSS 和 JavaScript，无需安装依赖或启动服务器。

## 使用

推荐双击 macOS 的 `launch.command` 或 Windows 的 `launch.bat`。脚本会在 `127.0.0.1` 启动一个仅本机可访问的服务，并打开入口页；不依赖 Python。也可以在 Chrome 或 Edge 中直接打开根目录的 `index.html`，但不同浏览器对 `file://` 子页面导航的限制可能不同。

MD5 字典匹配时，在页面中选择 `md5/dicts` 文件夹，或手动选择 TXT 字典文件。为确保由易到难的顺序，可给字典文件名前加 `00-`、`10-` 等编号。浏览器出于本地文件安全限制，不会静默读取相邻目录。

文件格式速查表内置常见签名，也可添加保存在当前浏览器中的自定义记录。图片尺寸工具支持 JPEG、PNG、WebP，只修改尺寸元数据（PNG 另更新 IHDR 校验值），并下载新副本；原图不会被覆盖。所谓真实尺寸候选是启发式提示，需结合外部线索判断。

文件伪装分析在浏览器本地比对常见文件头与扩展名、扫描内部签名，并检查 PNG/JPEG 结束标记及 RIFF 容器长度线索；可按疑似偏移生成拆分命令。隐写初筛会统计 PNG 解压像素及 PCM WAV 样本的低位分布。命中可能来自正常的嵌套容器或数据，统计结果也不能证明隐写；JPEG 系数及压缩音视频帧需专用工具进一步分析。

APK 元数据解析页先调用本机 JADX 分析 APK。JADX 成功解析并返回 Manifest 信息后，页面才填入应用名称、包名、版本、主入口、Android API 级别和权限声明；权限会附上常见中文说明。代码分析还会标出网络、定位、相机/录音、WebView、动态加载、加密、设备标识、剪贴板、文件访问等 API 特征及源码位置，并列出静态网址。代码特征是静态匹配线索，不等于运行时行为；混淆或动态加载可能造成遗漏。

页面还可调用本机 JADX CLI 解码 Manifest、权限和入口，并在反编译源码及资源中搜索静态网址。JADX 运行和 APK 临时文件均留在本机；网页服务只监听 `127.0.0.1`。统一便携运行包包含一份 JADX 1.5.6 CLI 和独立 Temurin JRE 17，覆盖 macOS Intel/Apple Silicon、Linux x64/ARM64 和 Windows x64。目标电脑不需要预装 Java。

首次准备运行包时，在任一台可联网电脑上运行：

- macOS / Linux：`sh scripts/setup-jadx.sh`
- Windows：`powershell -ExecutionPolicy Bypass -File scripts/setup-jadx.ps1`

下载完成后，安装脚本会生成 `jadx-portable-bundle.zip`。把该压缩包与网站文件一起复制到其他电脑，并解压到项目的 `tools` 目录；本地服务会按操作系统和 CPU 架构选用匹配的 JRE。运行包较大，且被 `.gitignore` 排除；若通过 Git 同步项目，请另外复制便携包，或在目标电脑运行一次安装脚本。JADX 不能保证完整反编译所有 APK，静态分析也无法发现运行时拼接、加密或网络下发的网址。JADX 使用 Apache-2.0 许可证，详见[官方仓库](https://github.com/skylot/jadx)。

如果 macOS 浏览器直接打开 `file://` 页面时显示 `ERR_ACCESS_DENIED`，请改用 `launch.command` 通过本机地址访问。若脚本提示 Ruby/WEBrick 不可用，可在 Chrome 或 Edge 中手动打开入口页。服务绑定在 `127.0.0.1`，不会对局域网或互联网开放。

所有 APK 内容均在本机处理，不会上传到远程服务。JADX 独立运行包仅在首次安装时从官方发行页和 Adoptium 下载；其他页面不加载远程脚本、字体或 API。

二维码识别使用本地打包的 [jsQR 1.4.0](https://github.com/cozmo/jsQR)（Apache-2.0）解码图片，结果只在当前浏览器显示；第三方库许可证见 `assets/vendor/jsQR-LICENSE.txt`。

Linux 指令检索按用途分类收录常用命令，支持按命令名、中文关键词、近似拼写、配置路径和示例搜索，并可复制示例。命令资料离线保存在 `linux/data.js`、`linux/supplement.js` 和 `linux/paths.js`；指令优先链接菜鸟教程，缺少对应页面时链接官方文档或手册页。页面也说明 Linux 关键目录与配置文件的用途和维护方式。菜鸟教程的低频命令经过筛选；《Tutorial.md》中的命令和示例均纳入索引。

市场监管题库与法规检索在 `market-search` 目录中离线运行。题库原始工作簿保存在 `market-search/data/题库.xlsx`，`questions.json` 是可编辑数据源，页面加载的 `questions.js` 可用 `python3 market-search/build-index.py` 重建。题目记录需包含 `question`、`type`、`answer`，也可带 `id`、`options`。法规全文数据包括国家市场监督管理总局数据库的 594 条记录和 1 条国家知识产权局后续规章补充记录，PDF 原文位于 `market-search/data/laws/`，全文检索索引位于 `data/laws-full.json` 和页面加载用的 `data/laws-full.js`。联网更新时运行 `python3 market-search/download-corpus.py`；只重建浏览器索引时运行 `python3 market-search/build-law-index.py`。页面支持导入 TXT、Markdown、CSV、JSON 到当前浏览器本地存储，也可导出为 JSON；此类导入仅在当前浏览器可见，不会自动写入项目文件。正式使用前应核实官方数据库中的现行文本和适用范围。
