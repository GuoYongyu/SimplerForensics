# DIE 查壳识别（浏览器移植）

本目录实现一个纯前端的 Detect It Easy（DiE-JS）PE 签名运行器：

- `engine.js`：PE32/PE32+ 解析、DiE-JS 签名语法与匹配器、PE API 子集、签名执行器和字符串线索分类。
- `worker.js`：在 Web Worker 中加载签名库、执行规则、计算哈希、提取字符串，向页面发送进度和报告。
- `app.js` / `index.html` / `style.css`：页面交互与展示。
- `db/pe-signatures.json`：离线签名库，由 `../scripts/build-die-db.mjs` 从 Detect It Easy 的 `db/PE` 生成。
- `db/DIE-LICENSE.txt`：Detect It Easy 的 MIT 许可证文本。

## 签名库

当前打包 1,034 条 PE 规则，来自 Detect It Easy 4.1.0 的 `db/PE`。`db/PE/_init`、`db/_runtime_helpers` 以及规则通过 `includeScript()` 引用的辅助脚本一并打包；`includeScript()` 在构建结果中展开为普通源码。

未加载的规则：

- `__GenericHeuristicAnalysis_By_DosX.7.sg`：依赖原生反汇编、流程遍历和 PE_Cached 缓存，无法在浏览器中安全复现。

规则执行依赖 `meta()`/`result()` 的语义、`bDetected`/`sName`/`sVersion`/`sOptions` 变量，以及 PE API 子集。遇到未实现的 API（例如 `PE.getDisasmString`、`PE.getNetMethodInfo`）时，该条规则会被跳过并计入页面的“规则异常”，不会返回猜测结果。

重新生成签名库（需要本机 Detect It Easy 仓库，不需要联网）：

```sh
node scripts/build-die-db.mjs /path/to/Detect-It-Easy
```

## 支持的 PE API 子集

- 读写：`readByte`/`readWord`/`readDword`/`readQword`、`read_int*`/`read_uint*`、`getString`、`getSignature`、`readBytes`。
- 比较与搜索：`compare`、`compareEP`、`compareOverlay`、`isSignaturePresent`、`findSignature`、`findSignatures`、`findString`、`findByte/Word/Dword`、节区/Overlay 搜索。
- 签名语法：十六进制、`??`/`..`、`**`、`%%`/`%&`/`!%`/`_%`、单引号文本、`$` 相对跳转、`#` 地址、`+` delta、`#[]` 基址。
- 结构：节区、导入/导出、资源树、版本资源、Manifest、Overlay、Rich Header、调试目录/PDB、TLS、Security Directory、CLI 元数据（版本、模块、类型/方法计数、`#Strings`/`#US`/`#Blob` 搜索）。
- 地址：`VAToOffset`、`RVAToOffset`、`OffsetToVA`、`OffsetToRVA`；`nEP`、`nLastSection`、`PE.section[...]`、`PE.resource[...]` 由官方 `db/PE/_init` 构建。

## 测试

```sh
node test/die-engine.test.cjs
DIE_FIXTURE=/path/to/sample.exe node test/die-engine.test.cjs
```

测试覆盖合成 PE 的解析、签名语法、入口点比较、字符串/线索提取、自定义规则以及完整签名库执行。`DIE_FIXTURE` 为可选的端到端样本检查。

## 限制

- 需通过本机启动脚本或静态服务打开；`file://` 页面无法加载 Web Worker 和签名库 JSON。
- 仅 PE32/PE32+；不解析 ELF、Mach-O、APK。
- 单文件 128 MiB；DIE 扫描时间上限约 25 秒；字符串 8,000 条；Overlay 单独扫描前 512 KiB。
- 不执行样本、不写入原文件、不联网、不验证 Authenticode 签名链。
- 浏览器移植不包含原生反汇编、IL 方法体模拟、深度启发式和跨文件读取；覆盖范围小于原生 DIE。
- 所有结果都是静态线索，未命中不代表文件安全。
