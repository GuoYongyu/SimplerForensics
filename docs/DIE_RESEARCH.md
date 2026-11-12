# EXE 逆向与取证常见数据需求调研

本文记录 `die/`（DIE 查壳识别）功能设计前的调研结论，以及这些结论如何映射到页面实际呈现的数据。目标不是罗列所有 PE 字段，而是回答两个问题：

1. CTF 逆向、恶意样本初筛和电子数据取证中，分析人员通常会先从 EXE 里提取什么？
2. 其中哪些可以由纯静态、离线、跨平台的浏览器工具可靠地给出？

## 调研来源

- 腾讯云开发者社区《CTF 竞赛逆向工程题型深入解析与循序渐进指南》（2025-11）：把逆向流程归纳为“文件类型识别 → 基本信息收集 → 静态分析 → 动态调试 → 算法还原 → 获取 Flag”，并明确列出文件格式、CPU 架构、编译器、是否加壳、字符串、导入/导出表、节表等检查项；脱壳流程为“识别壳类型 → 寻找 OEP → 转储内存 → 修复导入表 → 验证”。<https://cloud.tencent.cn/developer/article/2587061>
- 《CTF 逆向工程实战：JustRE 题目解析与技巧》（BJDCTF 2020 JustRE 题解）：使用 PEiD/Exeinfo PE 判断是否加壳，`strings` 找提示，IDA 看导入函数与入口，Resource Hacker 查看资源，x64dbg 在比较指令处下断点。<https://www.wzjinhao.cn/news/76741>
- ENISA《Artifact Analysis Fundamentals Handbook》：面向取证的工件分析基础，强调先固定文件身份（哈希、类型、大小），再做结构化解析、字符串与嵌入对象检查。<https://www.enisa.europa.eu/topics/training-and-exercises/trainings-for-cybersecurity-specialists/online-training-material/documents/artifact-analysis-fundamentals-handbook>
- CCDCOE《Malware Reverse Engineering Handbook》：把 PEiD 一类工具用于识别 cryptor、packer 和 compiler，并介绍 PE 头、节区、导入表等静态检查。<https://ccdcoe.org/uploads/2020/07/Malware-Reverse-Engineering-Handbook-final.pdf>
- Microsoft PE Format 文档：节表、数据目录、资源树、调试目录、TLS 目录、CLR/CLI 头等结构的权威定义。<https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
- Detect It Easy 官方仓库及 `help/PE.md`、`help/Signatures.md`、`db/PE/_init`：DiE-JS 的 PE API、签名语法（`??`/`..`、`$` 相对跳转、`#` 地址、单引号文本等）、`meta()`/`result()` 结果语义，以及 PE 数据库的规则类型。<https://github.com/horsicq/Detect-It-Easy>

## 常见数据需求与页面映射

| 逆向 / 取证需求 | 典型用途 | 本页呈现 | 数据性质与限制 |
| --- | --- | --- | --- |
| 文件身份摘要 | 样本编号、去重、与外部报告比对（页面不联网查询） | MD5、SHA-1、SHA-256、SHA-384、SHA-512 | 直接计算结果；对完整文件字节计算 |
| 格式、架构、子系统 | 判断 PE32/PE32+、x86/x64/ARM64、EXE/DLL/驱动、GUI/CUI | 概览与“取证速览” | 直接读取 Optional Header / File Header |
| 壳、保护器、加密器 | 决定是否先脱壳；识别 UPX、VMProtect、Themida 等 | “DIE 识别结果”，类型为压缩壳/保护器/加密器 | DIE 签名命中；不等于已确认保护或已成功脱壳 |
| 编译器、链接器、工具链 | 推测开发环境、定位库函数、辅助反编译 | “DIE 识别结果”中的编译器/链接器 | DIE 规则 + PE 元数据；可被裁剪或伪造 |
| 节区名称、大小、权限、熵 | 识别异常节、W+X、高熵压缩数据、伪节名 | “节区、熵与入口点” | 直接读取 + 熵计算；高熵也可能是正常资源 |
| 入口点 / OEP / EP 字节 | 动态调试断点、脱壳后定位 OEP、判断 EP 是否异常 | 取证速览、入口点卡片、EP 十六进制 | EP RVA/文件偏移直接读取；OEP 需动态分析，页面只给静态入口点 |
| 导入表 / IAT / 导入哈希 | 判断程序能力、加壳后导入是否异常、匹配样本家族 | “导入与导出” | 静态导入表；不包含运行时解析或延迟导入 |
| 导出表 | DLL 能力、.NET/原生导出、调试符号入口 | “导入与导出” | 只解析标准导出目录 |
| 资源：版本信息 | 作者、产品名、版本、公司、版权等线索 | “资源、版本信息与 Manifest” | 解析 RT_VERSION；字段可被构造 |
| 资源：Manifest | 请求管理员权限、DPI、兼容性、CLR 激活 | Manifest 预览 | 解析 RT_MANIFEST；不执行其中配置 |
| 资源：RCDATA/图标/对话框/字符串表 | CTF 隐藏 Flag、安装器载荷、界面文本 | 资源条目表 + 字符串提取 | 列出资源偏移/大小；不递归解包任意格式 |
| Overlay / 文件尾部附加数据 | 附加 Flag、安装包、签名、二次载荷 | Overlay 卡片、前 64 字节、Overlay 字符串 | 以最后一个节区原始数据末端为界；签名数据也会被算作 Overlay |
| ASCII / UTF-16LE 字符串 | Flag、口令、URL、IP、注册表、路径、PDB | “字符串与 Flag 线索” | 可见字符串提取；不覆盖加密/压缩/运行时拼接内容 |
| Flag 形式字符串 | CTF 直接取 Flag | `flag{...}`、`ctf{...}` 等归类 | 正则启发式；可能误报或漏报 |
| PE 时间戳 | 编译时间线索、样本时间线 | 取证速览 | 秒级 Unix 时间；可伪造，也可能是 0 |
| Rich Header | 推测 MSVC 工具链与构建号 | Rich Header 表 | 解析未加密的 Rich 结构；可伪造 |
| PDB / 调试目录 | 源码路径、构建机器、符号线索 | 取证速览 | CodeView 记录；路径可伪造 |
| TLS 回调 | 入口点之前执行的代码、反调试 | 取证速览 | 只检查 TLS 目录是否存在 |
| Authenticode 签名 | 是否带签名、签名大小/位置 | 取证速览 | 只检查 Security Directory；**不验证**证书链、时间戳、吊销 |
| .NET / CLI | 判断托管程序、CLR 版本、模块、类型/方法规模 | 取证速览；DIE 的 .NET 规则 | 解析 CLI Header、元数据流和部分表；不反编译 IL |
| .NET 类型/方法数量 | 判断混淆、加壳、库规模 | .NET 摘要 | 解析 TypeDef/MethodDef 表计数；不保证所有表都完整 |
| 可疑 API / 字符串线索 | 网络、持久化、加密、调试检测 | 导入表筛选 + 字符串线索 | 静态线索；命中不代表行为发生 |

## 为什么把 DIE 规则放进浏览器，而不是调用 `diec`

Detect It Easy 本身是跨平台桌面程序，并提供命令行版本。但本项目的约束是：

- **完全离线**：不访问在线信誉、规则更新或云端 API。
- **Windows 与 macOS 都能直接使用**：不要求用户安装 DIE、Qt 运行时或配置 `PATH`。
- **不执行样本**：页面只读取字节，不能因为调用外部程序而引入执行链。
- **不增加平台相关二进制**：仓库不需要为每个系统放一份 `diec`。

因此实现选择是：把 DIE 的 **DiE-JS PE 签名库**和浏览器内的 PE 解析器放进 Web Worker，在本地执行规则。它使用 Detect It Easy 官方 `db/PE` 规则，但不是完整 DIE 客户端：

- 规则里的 `meta()`/`result()`、`PE.compareEP()`、`PE.compare()`、`compareOverlay()`、节区/导入/导出/资源/Overlay/.NET 字符串等 API 由本项目实现。
- 依赖原生反汇编、IL 方法体模拟、深度启发式引擎或读取相邻文件的规则会被跳过，并在页面“规则库覆盖与限制”中列出。
- 规则库固定随页面发布，不自动更新；需要更新时重新运行 `scripts/build-die-db.mjs`。

这样做的代价是覆盖范围小于原生 DIE，但换来可审计、可离线、跨平台且不执行样本的实现。

## 签名库概况

- 来源：Detect It Easy `db/PE/*.sg`（MIT 许可证）。
- 规则数：1,034 条（另有 1 条 `__GenericHeuristicAnalysis_By_DosX.7.sg` 未加载，它依赖原生反汇编和流程模拟）。
- 类型分布：library 279、protector 255、packer 124、installer 109、cryptor 61、compiler 51、sfx 41、tool 27、protection 26、game engine 21、joiner 12，其余为其他类型。
- 规则格式：DiE-JS，包含 `meta()` 声明和 `detect()` 函数；部分规则通过 `includeScript()` 复用 `db/` 下的辅助脚本，构建时已展开。
- 结果去重：遵循 DIE 的重复结果阈值（例如 packer 最多 2 条、protector 最多 3 条），并额外按“类型 + 名称 + 版本 + 选项”去重。

## 页面实现边界

- 单文件上限 128 MiB；DIE 扫描时间上限约 25 秒，达到上限会标记“结果可能不完整”。
- 字符串上限 8,000 条；Overlay 单独扫描前 512 KiB，避免尾部 Flag 因总上限被跳过。
- 只解析 PE32/PE32+；ELF、Mach-O、脚本、APK 等不在本页范围。
- 页面通过 Web Worker 和 `fetch` 读取本地签名库，需要经本机启动脚本或静态服务打开；`file://` 直接打开会受浏览器安全限制。
- 不验证数字签名，不解析证书，不访问网络，不执行样本，不写入原文件。
- PE 时间戳、版本资源、Rich Header、PDB、Manifest 都可能被伪造；页面把它们标为线索而不是事实。
- DIE 结果是静态签名匹配，未命中不代表文件安全，也不代表一定没有加壳。

## 测试记录

- 合成 PE：验证 PE 头、节区、入口点、字符串、规则执行与结果语义，见 `test/die-engine.test.cjs`。
- 合成 UPX 入口点：命中 `packer_UPX.2.sg`，返回 `UPX 3.91+ / modified`。
- 真实工具链样本：7-Zip 21.07 的 `7za.exe`（x64，MSVC）命中 `Microsoft Visual C/C++ 14.00` 与 `Microsoft Linker`，并正确读出 RT_VERSION 和 Manifest；esbuild（Go）命中 Go 编译器；rollup 的 napi-rs 原生模块命中 Rust 编译器与 Microsoft Linker。
- .NET 程序集（Newtonsoft.Json 13.0.3）：识别 `.NET Framework 4.5`、`Newton Json`、`Windows Authenticode`，并解析出 CLR 版本、模块名、类型/方法计数。
- Corkami PE 语料：对 228 个构造/畸形 PE（203 个可解析）做解析与规则执行回归，检查截断、异常节表、Overlay、资源树等路径。
- 哈希对照：MD5/SHA-256 与系统工具结果一致。
