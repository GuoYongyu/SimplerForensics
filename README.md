# SimplerForensic

SimplerForensic 是一组可离线使用的本地工具，基于原生 HTML、CSS 和 JavaScript 编写，无需安装项目依赖。大多数工具直接在浏览器中运行；需要 APK 分析时，页面会调用本机的 JADX。

## 工具一览

| 工具 | 用途 |
| --- | --- |
| MD5 | 使用用户选择的字典文件进行本地匹配 |
| 文件签名 | 查询常见文件格式签名，也可保存自定义记录 |
| 十六进制查看器 | 分页查看文件字节、全文件分块搜索并导出选定范围 |
| 文件元数据查看 | 只读解析 JPEG、TIFF、PNG、WebP、PDF 与 WAV 的可读字段 |
| 图片尺寸 | 修改 JPEG、PNG、WebP 的尺寸元数据并下载副本 |
| 文件伪装分析 | 对照扩展名和文件头，扫描内部签名及容器边界线索 |
| EXE 静态分析 | 本地计算多种哈希、解析 PE 结构、推测语言/工具链、提取字符串并扫描内置规则 |
| 隐写初筛 | 统计 PNG 像素和 PCM WAV 样本的低位分布 |
| APK 分析 | 查看 Manifest、权限、入口、代码特征和静态网址 |
| 二维码识别 | 在浏览器中识别图片里的二维码 |
| Linux 指令检索 | 按命令、中文关键词、近似拼写、路径和示例查找命令 |
| 代码指令检索 | 按语言与用途查找编译、运行、构建、测试、容器、Kubernetes 和 TLS 证书命令 |
| Windows 工具 | 使用离线整理的 Windows 相关工具和资料 |
| 市场监管题库与法规检索 | 搜索题库和法规全文，或导入自己的资料 |
| 时间戳、Base64 等 | 处理常见编码与时间戳转换 |

## 启动

推荐双击对应系统的启动脚本：

- macOS：launch.command
- Windows：launch.bat

脚本会启动只监听本机 127.0.0.1 的网页服务并打开入口页，不需要 Python。也可以用 Chrome 或 Edge 直接打开根目录的 index.html；部分浏览器会限制从 file:// 页面打开其他本地页面。若 macOS 浏览器显示 ERR_ACCESS_DENIED，请使用 launch.command。如果启动脚本提示 Ruby/WEBrick 不可用，可尝试直接打开入口页。

## 各工具说明

### MD5 字典匹配

在页面中选择 md5/dicts 文件夹，或手动选择 TXT 字典文件。浏览器因本地文件安全限制，不会在未选择的情况下读取相邻文件。若希望按从易到难的顺序尝试字典，可在文件名前添加 00-、10- 等编号。

### 文件与图片分析

十六进制查看器按需读取文件页，可按十进制或十六进制偏移跳转、分块搜索字节或 UTF-8 文本，并将指定范围导出为派生文件。文件元数据查看依据内容签名支持 JPEG、TIFF、PNG、WebP、PDF 和 WAV；结果显示字段偏移，并提示未支持的编码、压缩对象或解析范围。两者均在浏览器本地运行，保持源文件不变。

文件签名速查表内置常见格式，也支持添加保存在当前浏览器中的自定义记录。图片尺寸工具支持 JPEG、PNG 和 WebP，只修改尺寸元数据（PNG 还会更新 IHDR 校验值），并下载新副本，不会覆盖原图。工具给出的“真实尺寸候选”是启发式提示，应结合其他线索判断。

文件伪装分析会在浏览器本地比对常见文件头与扩展名、分块扫描内部签名，并检查 PNG/JPEG 结束标记和 RIFF 容器长度线索；它也可以根据疑似偏移生成拆分命令。扫描上限为 512 MiB，提供扫描进度与取消操作。

隐写初筛统计 PNG 解压像素和 PCM WAV 样本的低位分布。统计异常可能由正常的嵌套容器或数据造成，不能单独证明文件含有隐写内容。JPEG 系数和压缩音视频帧需要专用工具进一步分析。

新增或改造工具应遵循 [工具设计规范](docs/TOOL_DESIGN_SPEC.md)，特别是证据边界、偏移记录、资源上限、可访问状态反馈和非破坏性处理约定。

### EXE 静态分析

EXE 静态分析页面位于 exe-analysis/。支持本地计算 MD5、SHA-1、SHA-256、SHA-384 和 SHA-512，解析 PE32/PE32+ 头部、节区、导入/导出表和常见结构异常，基于 PE 元数据、运行时标记和可见字符串推测编程语言与工具链，并提取 ASCII/UTF-16LE 字符串、筛选 URL/IP/注册表路径线索、扫描内置静态规则，并可导入本地 JSON 文本规则。文件在浏览器 Web Worker 中处理，不执行样本、不上传文件、不调用在线信誉、扫描或规则服务；报告只有在用户点击导出后才下载为 JSON。

语言和编译器判断、结构提示及规则命中均为静态线索，可能误报或漏报。PE 时间戳不应视为可信编译时间；字符串命中不证明对应行为发生；未命中规则也不代表文件安全。首版单文件上限为 128 MiB，规则扫描使用内置特征和可选本地 JSON 文本规则，不等同于完整 YARA 引擎；规则格式示例见 exe-analysis/rules-example.json。

### APK 分析与 JADX

APK 分析页面调用本机 JADX。成功读取 APK 的 Manifest 后，页面会显示应用名称、包名、版本、主入口、Android API 级别和权限，并提供常见权限的中文说明。代码分析会标出网络、定位、相机或录音、WebView、动态加载、加密、设备标识、剪贴板和文件访问等 API 特征及其源码位置，并搜索静态网址。

这些结果是静态分析线索，不代表应用运行时一定执行了对应行为。混淆、动态加载、运行时拼接或加密，以及从网络下载的内容，都可能导致结果不完整。

项目提供跨平台便携运行包，内含 JADX 1.5.6 CLI 和 Temurin JRE 17，支持 macOS Intel/Apple Silicon、Linux x64/ARM64 和 Windows x64；目标电脑无需预装 Java。首次准备运行包时，在一台可联网的电脑上运行：

- macOS / Linux：sh scripts/setup-jadx.sh
- Windows：powershell -ExecutionPolicy Bypass -File scripts/setup-jadx.ps1

安装脚本从 JADX 官方发行页和 Adoptium 下载文件，并生成 jadx-portable-bundle.zip。将压缩包复制到目标电脑后，解压到项目的 tools 目录；本地服务会根据操作系统和 CPU 架构选择对应的 JRE。压缩包和解压后的 tools/jadx/ 均由 .gitignore 排除。通过 Git 获取项目后，可单独复制运行包，或在目标电脑运行安装脚本重新准备。

### 二维码识别

二维码识别使用本地打包的 [jsQR 1.4.0](https://github.com/cozmo/jsQR) 解码图片。识别结果只显示在当前浏览器中；许可证文本见 assets/vendor/jsQR-LICENSE.txt。

### Linux 指令检索

命令按用途分类，支持按命令名、中文关键词、近似拼写、配置路径和示例搜索，也可复制示例。离线数据位于 linux/data.js、linux/supplement.js 和 linux/paths.js。命令条目优先链接菜鸟教程；没有对应页面时链接官方文档或手册页。页面也介绍 Linux 关键目录与配置文件的用途和维护方式。菜鸟教程中的低频命令经过筛选；《Tutorial.md》中的命令和示例均已纳入索引。

### 市场监管题库与法规检索

相关页面位于 market-search/，可离线检索题库和法规全文。题库原始工作簿（如有）保存在 market-search/data/题库.xlsx；questions.json 是可编辑数据源，页面读取的 questions.js 可通过以下命令重建：

    python3 market-search/build-index.py

题目记录必须包含 question、type 和 answer，也可包含 id、options。法规 PDF 原文位于 market-search/data/laws/；全文索引为 market-search/data/laws-full.json 和页面读取的 market-search/data/laws-full.js。联网更新法规语料运行 python3 market-search/download-corpus.py；只重建浏览器索引运行 python3 market-search/build-law-index.py。当前语料包含国家市场监督管理总局数据库的 594 条记录，以及国家知识产权局的 1 条后续规章补充记录。

页面支持将 TXT、Markdown、CSV 或 JSON 导入当前浏览器的本地存储，并可导出为 JSON。导入的数据仅在当前浏览器可见，不会自动写入项目文件。正式使用法规内容前，请核实官方数据库中的现行文本和适用范围。

## 隐私与联网

网页服务只绑定 127.0.0.1，不会向局域网或互联网开放。APK 文件和 JADX 生成的临时文件均在本机处理，不会上传到远程服务。除首次准备 JADX 便携运行包时从官方发行页和 Adoptium 下载文件外，其他页面不加载远程脚本、字体或 API。

## 开源致谢

感谢 [JADX 项目](https://github.com/skylot/jadx)提供优秀的 Android APK 反编译工具。本项目通过 JADX 进行本机 APK 静态分析；JADX 使用 Apache-2.0 许可证，使用及再分发时请遵守其许可证要求。

二维码识别使用 [jsQR](https://github.com/cozmo/jsQR)，同样采用 Apache-2.0 许可证。其许可证文本随项目保存在 assets/vendor/jsQR-LICENSE.txt。
