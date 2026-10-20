window.CODE_COMMANDS = [
  {
    "category": "Java / JVM",
    "name": "java -jar",
    "syntax": "java [JVM 选项] -jar app.jar",
    "description": "运行 Java 可执行 JAR；JDK/JRE 版本需与目标字节码兼容。",
    "examples": [
      "java -version",
      "java -jar app.jar"
    ],
    "keywords": "运行 启动 jar JVM 主类",
    "source": "Java SE / JDK 工具",
    "risk": false
  },
  {
    "category": "Java / JVM",
    "name": "javac",
    "syntax": "javac [选项] 源文件.java",
    "description": "编译 Java 源码；-d 指定 class 输出目录，--release 限定目标 API 与字节码版本。",
    "examples": [
      "javac -d out src/Main.java",
      "javac --release 17 -d out src/Main.java"
    ],
    "keywords": "编译 源码 class JDK",
    "source": "Java SE / JDK 工具",
    "risk": false
  },
  {
    "category": "Java / JVM",
    "name": "java classpath",
    "syntax": "java -cp <路径> <主类>",
    "description": "通过类路径指定依赖目录或 JAR；Windows 用分号，Unix 用冒号分隔。",
    "examples": [
      "java -cp \"out;lib/*\" com.example.Main",
      "java -cp \"out:lib/*\" com.example.Main"
    ],
    "keywords": "classpath 类路径 依赖",
    "source": "Java SE / JDK 工具",
    "risk": false
  },
  {
    "category": "Java / JVM",
    "name": "jar",
    "syntax": "jar [--create / --list / --extract] [选项]",
    "description": "创建、查看或解包 JAR；JAR 本质是 ZIP 归档。",
    "examples": [
      "jar --list --file app.jar",
      "jar --extract --file app.jar"
    ],
    "keywords": "打包 查看 解压 zip",
    "source": "Java SE / JDK 工具",
    "risk": false
  },
  {
    "category": "Java / JVM",
    "name": "javadoc",
    "syntax": "javadoc -d <目录> <源文件>",
    "description": "从 Java 源码注释生成 API 文档。",
    "examples": [
      "javadoc -d docs src/com/example/*.java"
    ],
    "keywords": "文档 API 注释",
    "source": "Java SE / JDK 工具",
    "risk": false
  },
  {
    "category": "Java / JVM",
    "name": "jcmd",
    "syntax": "jcmd <PID> <命令>",
    "description": "向本机 JVM 发送诊断命令，可查看线程、堆和启动参数。",
    "examples": [
      "jcmd 1234 VM.version",
      "jcmd 1234 Thread.print"
    ],
    "keywords": "JVM 诊断 线程 堆 PID",
    "source": "Java SE / JDK 工具",
    "risk": false
  },
  {
    "category": "Java / JVM",
    "name": "jstack",
    "syntax": "jstack [-l] <PID>",
    "description": "打印 Java 线程栈，常用于定位死锁或线程阻塞。",
    "examples": [
      "jstack -l 1234 > threads.txt"
    ],
    "keywords": "线程 dump 死锁 堆栈",
    "source": "Java SE / JDK 工具",
    "risk": false
  },
  {
    "category": "Java / JVM",
    "name": "jmap",
    "syntax": "jmap [选项] <PID>",
    "description": "查看堆摘要或导出 heap dump；转储可能含敏感数据。",
    "examples": [
      "jmap -heap 1234",
      "jmap -dump:format=b,file=heap.hprof 1234"
    ],
    "keywords": "heap 堆转储 dump 内存",
    "source": "Java SE / JDK 工具",
    "risk": true
  },
  {
    "category": "Java / JVM",
    "name": "jstat",
    "syntax": "jstat -gc <PID> [间隔] [次数]",
    "description": "按间隔查看 JVM 垃圾回收和内存统计。",
    "examples": [
      "jstat -gc 1234 1000 10"
    ],
    "keywords": "GC 垃圾回收 内存监控",
    "source": "Java SE / JDK 工具",
    "risk": false
  },
  {
    "category": "Java / JVM",
    "name": "keytool",
    "syntax": "keytool -list -v -keystore <文件>",
    "description": "查看 Java keystore 条目、证书主题、颁发者和有效期。",
    "examples": [
      "keytool -list -v -keystore truststore.jks"
    ],
    "keywords": "证书 keystore jks truststore 到期",
    "source": "Java SE / JDK 工具",
    "risk": false
  },
  {
    "category": "Python",
    "name": "python",
    "syntax": "python [选项] <脚本.py>",
    "description": "运行 Python 脚本；Windows 上也常用 py 启动器。",
    "examples": [
      "python --version",
      "python app.py"
    ],
    "keywords": "运行 脚本 版本",
    "source": "Python 文档",
    "risk": false
  },
  {
    "category": "Python",
    "name": "python -m",
    "syntax": "python -m <模块> [参数]",
    "description": "以模块方式执行代码，适用于 pip、venv、http.server 等。",
    "examples": [
      "python -m http.server 8000",
      "python -m pip --version"
    ],
    "keywords": "模块运行 http server pip",
    "source": "Python 文档",
    "risk": false
  },
  {
    "category": "Python",
    "name": "python -c",
    "syntax": "python -c \"<代码>\"",
    "description": "直接执行短代码，适合一次性环境检查。",
    "examples": [
      "python -c \"import sys; print(sys.executable)\""
    ],
    "keywords": "单行 命令行 检查",
    "source": "Python 文档",
    "risk": false
  },
  {
    "category": "Python",
    "name": "py launcher",
    "syntax": "py [-版本] <脚本.py>",
    "description": "Windows Python Launcher，可选择已安装版本。",
    "examples": [
      "py -0p",
      "py -3.12 app.py"
    ],
    "keywords": "Windows 多版本 启动器",
    "source": "Python 文档",
    "risk": false
  },
  {
    "category": "Python",
    "name": "venv",
    "syntax": "python -m venv <目录>",
    "description": "创建隔离虚拟环境；激活命令因操作系统和 shell 而异。",
    "examples": [
      "python -m venv .venv",
      "source .venv/bin/activate",
      ".venv\\Scripts\\Activate.ps1"
    ],
    "keywords": "虚拟环境 环境隔离",
    "source": "Python 文档",
    "risk": false
  },
  {
    "category": "Python",
    "name": "pip install",
    "syntax": "python -m pip install <包>",
    "description": "安装依赖到当前解释器环境；使用 python -m pip 可避免解释器错配。",
    "examples": [
      "python -m pip install requests",
      "python -m pip install -r requirements.txt"
    ],
    "keywords": "安装 依赖 requirements",
    "source": "Python 文档",
    "risk": true
  },
  {
    "category": "Python",
    "name": "pip list / show",
    "syntax": "python -m pip list",
    "description": "查看环境包列表，或用 show 查看包元数据和安装位置。",
    "examples": [
      "python -m pip list",
      "python -m pip show requests"
    ],
    "keywords": "包列表 查看",
    "source": "Python 文档",
    "risk": false
  },
  {
    "category": "Python",
    "name": "pip freeze",
    "syntax": "python -m pip freeze",
    "description": "导出当前环境包版本，可重定向为 requirements.txt。",
    "examples": [
      "python -m pip freeze > requirements.txt"
    ],
    "keywords": "依赖 导出 版本",
    "source": "Python 文档",
    "risk": false
  },
  {
    "category": "Python",
    "name": "compileall",
    "syntax": "python -m compileall <路径>",
    "description": "递归检查 Python 语法并生成 __pycache__ 字节码文件。",
    "examples": [
      "python -m compileall src/"
    ],
    "keywords": "语法检查 字节码",
    "source": "Python 文档",
    "risk": false
  },
  {
    "category": "Python",
    "name": "unittest",
    "syntax": "python -m unittest discover",
    "description": "发现并运行 unittest 测试。",
    "examples": [
      "python -m unittest discover -s tests -v"
    ],
    "keywords": "测试 unittest",
    "source": "Python 文档",
    "risk": false
  },
  {
    "category": "Python",
    "name": "pytest",
    "syntax": "python -m pytest [路径]",
    "description": "运行 pytest 测试，可按文件、关键字筛选。",
    "examples": [
      "python -m pytest -q",
      "python -m pytest tests/ -k login"
    ],
    "keywords": "测试 pytest 单测",
    "source": "Python 文档",
    "risk": false
  },
  {
    "category": "Python",
    "name": "pdb",
    "syntax": "python -m pdb <脚本.py>",
    "description": "使用标准库交互式调试器运行脚本。",
    "examples": [
      "python -m pdb app.py"
    ],
    "keywords": "调试 断点 pdb",
    "source": "Python 文档",
    "risk": false
  },
  {
    "category": "C / C++",
    "name": "gcc",
    "syntax": "gcc [选项] 源文件.c -o 程序",
    "description": "用 GCC 编译并链接 C 程序；-Wall -Wextra 启用常用警告。",
    "examples": [
      "gcc -Wall -Wextra -O2 main.c -o app"
    ],
    "keywords": "C 编译 gcc 链接",
    "source": "GCC / GNU Binutils 手册",
    "risk": false
  },
  {
    "category": "C / C++",
    "name": "g++",
    "syntax": "g++ [选项] 源文件.cpp -o 程序",
    "description": "用 G++ 编译 C++ 程序；通过 -std 选择语言标准。",
    "examples": [
      "g++ -std=c++20 -Wall -Wextra main.cpp -o app"
    ],
    "keywords": "C++ 编译 标准",
    "source": "GCC / GNU Binutils 手册",
    "risk": false
  },
  {
    "category": "C / C++",
    "name": "gcc 多文件",
    "syntax": "gcc main.c util.c -Iinclude -Llib -lmylib -o app",
    "description": "编译多个源文件并指定头文件、库搜索路径及链接库。",
    "examples": [
      "gcc src/*.c -Iinclude -o app"
    ],
    "keywords": "多文件 include 链接库",
    "source": "GCC / GNU Binutils 手册",
    "risk": false
  },
  {
    "category": "C / C++",
    "name": "预处理输出",
    "syntax": "gcc -E 源文件.c -o out.i",
    "description": "只运行 C 预处理器，检查宏展开和 include 结果。",
    "examples": [
      "gcc -E main.c -o main.i"
    ],
    "keywords": "预处理 宏 include",
    "source": "GCC / GNU Binutils 手册",
    "risk": false
  },
  {
    "category": "C / C++",
    "name": "汇编输出",
    "syntax": "gcc -S 源文件.c -o out.s",
    "description": "编译到汇编阶段，不生成最终可执行文件。",
    "examples": [
      "gcc -S -O2 main.c -o main.s"
    ],
    "keywords": "汇编 编译阶段",
    "source": "GCC / GNU Binutils 手册",
    "risk": false
  },
  {
    "category": "C / C++",
    "name": "nm",
    "syntax": "nm -C <程序或库>",
    "description": "查看目标文件符号；-C 解码 C++ 修饰名。",
    "examples": [
      "nm -C app"
    ],
    "keywords": "符号表 二进制",
    "source": "GCC / GNU Binutils 手册",
    "risk": false
  },
  {
    "category": "C / C++",
    "name": "ldd",
    "syntax": "ldd <可执行文件>",
    "description": "查看 ELF 动态库依赖；不要对不可信文件直接运行 ldd。",
    "examples": [
      "ldd ./app"
    ],
    "keywords": "依赖 so ELF",
    "source": "GCC / GNU Binutils 手册",
    "risk": false
  },
  {
    "category": "C / C++",
    "name": "gdb",
    "syntax": "gdb <程序> [核心文件]",
    "description": "启动 GDB 调试器，可设置断点、查看调用栈及变量。",
    "examples": [
      "gdb ./app",
      "gdb ./app core"
    ],
    "keywords": "调试 core 断点",
    "source": "GCC / GNU Binutils 手册",
    "risk": false
  },
  {
    "category": "C / C++",
    "name": "cmake build",
    "syntax": "cmake -S . -B build && cmake --build build",
    "description": "配置并构建 CMake 项目；生成物集中在 build 目录。",
    "examples": [
      "cmake -S . -B build -DCMAKE_BUILD_TYPE=Release",
      "cmake --build build -j"
    ],
    "keywords": "CMake 构建 make",
    "source": "GCC / GNU Binutils 手册",
    "risk": false
  },
  {
    "category": "Go",
    "name": "go version",
    "syntax": "go version",
    "description": "显示 Go 工具链版本。",
    "examples": [
      "go version"
    ],
    "keywords": "版本 工具链",
    "source": "Go 命令文档",
    "risk": false
  },
  {
    "category": "Go",
    "name": "go run",
    "syntax": "go run <文件或包>",
    "description": "编译并运行 Go 程序，适合开发期间快速执行。",
    "examples": [
      "go run .",
      "go run main.go"
    ],
    "keywords": "运行 执行",
    "source": "Go 命令文档",
    "risk": false
  },
  {
    "category": "Go",
    "name": "go build",
    "syntax": "go build [包]",
    "description": "编译当前包；-o 指定可执行文件路径。",
    "examples": [
      "go build ./...",
      "go build -o bin/server ./cmd/server"
    ],
    "keywords": "编译 构建 二进制",
    "source": "Go 命令文档",
    "risk": false
  },
  {
    "category": "Go",
    "name": "go test",
    "syntax": "go test [包]",
    "description": "运行 Go 测试；-race 启用数据竞争检测（有额外开销）。",
    "examples": [
      "go test ./...",
      "go test -race ./..."
    ],
    "keywords": "测试 竞态 race",
    "source": "Go 命令文档",
    "risk": false
  },
  {
    "category": "Go",
    "name": "go test coverage",
    "syntax": "go test -coverprofile=coverage.out ./...",
    "description": "生成覆盖率数据，可再用 go tool cover 查看。",
    "examples": [
      "go test -cover ./...",
      "go tool cover -func=coverage.out"
    ],
    "keywords": "覆盖率",
    "source": "Go 命令文档",
    "risk": false
  },
  {
    "category": "Go",
    "name": "go mod tidy",
    "syntax": "go mod tidy",
    "description": "整理 go.mod/go.sum 依赖声明，可能修改这两个文件。",
    "examples": [
      "go mod tidy"
    ],
    "keywords": "依赖 mod tidy",
    "source": "Go 命令文档",
    "risk": true
  },
  {
    "category": "Go",
    "name": "go get",
    "syntax": "go get <模块>@<版本>",
    "description": "添加或升级模块依赖；不同时期 Go 版本行为有所变化。",
    "examples": [
      "go get example.com/lib@v1.2.3"
    ],
    "keywords": "依赖 下载 升级",
    "source": "Go 命令文档",
    "risk": true
  },
  {
    "category": "Go",
    "name": "go pprof",
    "syntax": "go tool pprof <配置文件>",
    "description": "交互式分析 Go CPU 或内存 profile。",
    "examples": [
      "go tool pprof cpu.prof"
    ],
    "keywords": "性能 profile",
    "source": "Go 命令文档",
    "risk": false
  },
  {
    "category": "Rust",
    "name": "rustc",
    "syntax": "rustc [选项] <源文件.rs>",
    "description": "直接编译 Rust 单文件；工程依赖通常交给 Cargo。",
    "examples": [
      "rustc main.rs",
      "rustc -O main.rs"
    ],
    "keywords": "编译 单文件",
    "source": "Cargo / Rust 工具链",
    "risk": false
  },
  {
    "category": "Rust",
    "name": "cargo new",
    "syntax": "cargo new <项目名>",
    "description": "创建 Cargo 项目骨架；--lib 创建库项目。",
    "examples": [
      "cargo new hello",
      "cargo new --lib mylib"
    ],
    "keywords": "项目 初始化",
    "source": "Cargo / Rust 工具链",
    "risk": false
  },
  {
    "category": "Rust",
    "name": "cargo run",
    "syntax": "cargo run [--release]",
    "description": "编译并运行当前 Cargo 项目。",
    "examples": [
      "cargo run",
      "cargo run --release"
    ],
    "keywords": "运行 执行",
    "source": "Cargo / Rust 工具链",
    "risk": false
  },
  {
    "category": "Rust",
    "name": "cargo build",
    "syntax": "cargo build [--release]",
    "description": "构建项目和依赖；输出通常位于 target/。",
    "examples": [
      "cargo build --release",
      "cargo build --workspace"
    ],
    "keywords": "构建 workspace",
    "source": "Cargo / Rust 工具链",
    "risk": false
  },
  {
    "category": "Rust",
    "name": "cargo test",
    "syntax": "cargo test [过滤词]",
    "description": "运行单元测试、集成测试及文档测试。",
    "examples": [
      "cargo test",
      "cargo test parser"
    ],
    "keywords": "测试 单测",
    "source": "Cargo / Rust 工具链",
    "risk": false
  },
  {
    "category": "Rust",
    "name": "cargo check",
    "syntax": "cargo check",
    "description": "快速检查 Rust 项目类型和编译错误，不生成最终可执行文件。",
    "examples": [
      "cargo check --workspace"
    ],
    "keywords": "检查 类型",
    "source": "Cargo / Rust 工具链",
    "risk": false
  },
  {
    "category": "Rust",
    "name": "cargo clippy",
    "syntax": "cargo clippy --all-targets --all-features",
    "description": "运行 Clippy 静态检查，提示惯用写法和潜在问题。",
    "examples": [
      "cargo clippy -- -D warnings"
    ],
    "keywords": "lint 静态分析",
    "source": "Cargo / Rust 工具链",
    "risk": false
  },
  {
    "category": "JavaScript / TypeScript",
    "name": "node",
    "syntax": "node [选项] <文件.js>",
    "description": "使用 Node.js 运行 JavaScript，也可直接进入 REPL。",
    "examples": [
      "node --version",
      "node server.js"
    ],
    "keywords": "运行 版本",
    "source": "Node.js / npm / TypeScript CLI",
    "risk": false
  },
  {
    "category": "JavaScript / TypeScript",
    "name": "npm install",
    "syntax": "npm install",
    "description": "按 package.json 安装依赖；可能更改 lockfile。",
    "examples": [
      "npm install"
    ],
    "keywords": "依赖 安装",
    "source": "Node.js / npm / TypeScript CLI",
    "risk": true
  },
  {
    "category": "JavaScript / TypeScript",
    "name": "npm ci",
    "syntax": "npm ci",
    "description": "根据 lockfile 重建依赖，常用于 CI；会移除现有 node_modules。",
    "examples": [
      "npm ci"
    ],
    "keywords": "CI 锁文件 安装",
    "source": "Node.js / npm / TypeScript CLI",
    "risk": true
  },
  {
    "category": "JavaScript / TypeScript",
    "name": "npm run",
    "syntax": "npm run <脚本>",
    "description": "执行 package.json scripts 中定义的命令。",
    "examples": [
      "npm run build",
      "npm run dev"
    ],
    "keywords": "构建 脚本",
    "source": "Node.js / npm / TypeScript CLI",
    "risk": false
  },
  {
    "category": "JavaScript / TypeScript",
    "name": "npx",
    "syntax": "npx <包或命令>",
    "description": "运行本地或临时获取的 npm 包；执行前确认包名与来源。",
    "examples": [
      "npx vite --version"
    ],
    "keywords": "包工具 临时执行",
    "source": "Node.js / npm / TypeScript CLI",
    "risk": false
  },
  {
    "category": "JavaScript / TypeScript",
    "name": "tsc",
    "syntax": "npx tsc [选项]",
    "description": "运行 TypeScript 编译器；通常由项目 tsconfig.json 控制。",
    "examples": [
      "npx tsc --noEmit",
      "npx tsc -p tsconfig.json"
    ],
    "keywords": "TypeScript 编译 类型检查",
    "source": "Node.js / npm / TypeScript CLI",
    "risk": false
  },
  {
    "category": "JavaScript / TypeScript",
    "name": "Node 调试",
    "syntax": "node --inspect-brk <文件.js>",
    "description": "开启 Node Inspector 并在首行暂停；不要把调试端口暴露到不可信网络。",
    "examples": [
      "node --inspect-brk=127.0.0.1:9229 app.js"
    ],
    "keywords": "调试 inspector",
    "source": "Node.js / npm / TypeScript CLI",
    "risk": false
  },
  {
    "category": ".NET / C#",
    "name": "dotnet --info",
    "syntax": "dotnet --info",
    "description": "查看 .NET SDK、运行时、系统和安装路径。",
    "examples": [
      "dotnet --info"
    ],
    "keywords": "版本 SDK runtime",
    "source": "dotnet CLI",
    "risk": false
  },
  {
    "category": ".NET / C#",
    "name": "dotnet new",
    "syntax": "dotnet new <模板>",
    "description": "按模板创建 .NET 项目。",
    "examples": [
      "dotnet new console -n Hello",
      "dotnet new webapi -n Api"
    ],
    "keywords": "项目 初始化 模板",
    "source": "dotnet CLI",
    "risk": false
  },
  {
    "category": ".NET / C#",
    "name": "dotnet restore",
    "syntax": "dotnet restore",
    "description": "还原项目 NuGet 依赖。",
    "examples": [
      "dotnet restore"
    ],
    "keywords": "NuGet 依赖",
    "source": "dotnet CLI",
    "risk": false
  },
  {
    "category": ".NET / C#",
    "name": "dotnet build",
    "syntax": "dotnet build [项目]",
    "description": "构建 .NET 项目或解决方案。",
    "examples": [
      "dotnet build -c Release"
    ],
    "keywords": "构建 编译",
    "source": "dotnet CLI",
    "risk": false
  },
  {
    "category": ".NET / C#",
    "name": "dotnet run",
    "syntax": "dotnet run --project <项目>",
    "description": "构建并运行 .NET 项目。",
    "examples": [
      "dotnet run --project src/App"
    ],
    "keywords": "执行 启动",
    "source": "dotnet CLI",
    "risk": false
  },
  {
    "category": ".NET / C#",
    "name": "dotnet test",
    "syntax": "dotnet test [项目]",
    "description": "构建并运行 .NET 测试项目。",
    "examples": [
      "dotnet test --configuration Release"
    ],
    "keywords": "测试 单元测试",
    "source": "dotnet CLI",
    "risk": false
  },
  {
    "category": ".NET / C#",
    "name": "dotnet publish",
    "syntax": "dotnet publish -c Release -o <目录>",
    "description": "生成用于部署的发布输出。",
    "examples": [
      "dotnet publish -c Release -o publish"
    ],
    "keywords": "发布 部署",
    "source": "dotnet CLI",
    "risk": false
  },
  {
    "category": "PHP / Ruby / Swift / Kotlin",
    "name": "php -l",
    "syntax": "php -l <文件.php>",
    "description": "对单个 PHP 文件做语法检查。",
    "examples": [
      "php -v",
      "php -l index.php"
    ],
    "keywords": "PHP 版本 lint 语法",
    "source": "语言运行时 CLI",
    "risk": false
  },
  {
    "category": "PHP / Ruby / Swift / Kotlin",
    "name": "php CLI",
    "syntax": "php <脚本.php> [参数]",
    "description": "在命令行运行 PHP 脚本；-S 可启动开发服务器。",
    "examples": [
      "php artisan list",
      "php -S 127.0.0.1:8000"
    ],
    "keywords": "运行 server",
    "source": "语言运行时 CLI",
    "risk": false
  },
  {
    "category": "PHP / Ruby / Swift / Kotlin",
    "name": "composer install",
    "syntax": "composer install",
    "description": "根据 composer.lock 安装 PHP 依赖。",
    "examples": [
      "composer install --no-interaction"
    ],
    "keywords": "PHP 依赖 包管理",
    "source": "语言运行时 CLI",
    "risk": true
  },
  {
    "category": "PHP / Ruby / Swift / Kotlin",
    "name": "ruby",
    "syntax": "ruby <脚本.rb>",
    "description": "运行 Ruby 脚本；-c 只检查语法。",
    "examples": [
      "ruby -v",
      "ruby -c app.rb"
    ],
    "keywords": "Ruby 运行 语法",
    "source": "语言运行时 CLI",
    "risk": false
  },
  {
    "category": "PHP / Ruby / Swift / Kotlin",
    "name": "bundle exec",
    "syntax": "bundle exec <命令>",
    "description": "在 Gemfile 锁定的 Ruby bundle 环境中运行命令。",
    "examples": [
      "bundle install",
      "bundle exec rake test"
    ],
    "keywords": "Ruby Gem 依赖 测试",
    "source": "语言运行时 CLI",
    "risk": false
  },
  {
    "category": "PHP / Ruby / Swift / Kotlin",
    "name": "swift",
    "syntax": "swift <文件.swift>",
    "description": "运行 Swift 文件；swiftc 可显式编译二进制。",
    "examples": [
      "swift main.swift",
      "swiftc main.swift -o app"
    ],
    "keywords": "Swift 运行 编译",
    "source": "语言运行时 CLI",
    "risk": false
  },
  {
    "category": "PHP / Ruby / Swift / Kotlin",
    "name": "kotlinc",
    "syntax": "kotlinc <源文件.kt> -include-runtime -d app.jar",
    "description": "编译 Kotlin/JVM 并打包运行时到 JAR。",
    "examples": [
      "kotlinc Main.kt -include-runtime -d app.jar",
      "java -jar app.jar"
    ],
    "keywords": "Kotlin 编译 jar JVM",
    "source": "语言运行时 CLI",
    "risk": false
  },
  {
    "category": "构建 / 测试 / 包管理",
    "name": "make",
    "syntax": "make [目标]",
    "description": "按 Makefile 执行构建目标；-j 并行构建。",
    "examples": [
      "make -j4",
      "make clean"
    ],
    "keywords": "构建 编译 并行",
    "source": "构建工具手册",
    "risk": false
  },
  {
    "category": "构建 / 测试 / 包管理",
    "name": "ninja",
    "syntax": "ninja [-C 构建目录] [目标]",
    "description": "运行 Ninja 构建；常由 CMake 生成 build.ninja。",
    "examples": [
      "ninja -C build",
      "ninja -C build -t targets"
    ],
    "keywords": "构建",
    "source": "构建工具手册",
    "risk": false
  },
  {
    "category": "构建 / 测试 / 包管理",
    "name": "mvn",
    "syntax": "mvn [生命周期阶段]",
    "description": "运行 Maven 生命周期，如 package、test、verify。",
    "examples": [
      "mvn test",
      "mvn -DskipTests package"
    ],
    "keywords": "Maven Java 构建 测试",
    "source": "构建工具手册",
    "risk": false
  },
  {
    "category": "构建 / 测试 / 包管理",
    "name": "gradle",
    "syntax": "./gradlew [任务]",
    "description": "运行 Gradle Wrapper，优先使用项目固定版本。",
    "examples": [
      "./gradlew test",
      "./gradlew build"
    ],
    "keywords": "Gradle Java Kotlin 构建",
    "source": "构建工具手册",
    "risk": false
  },
  {
    "category": "构建 / 测试 / 包管理",
    "name": "bazel",
    "syntax": "bazel build //路径:目标",
    "description": "使用 Bazel 构建目标；标签取决于 BUILD 文件。",
    "examples": [
      "bazel build //..."
    ],
    "keywords": "Bazel 构建",
    "source": "构建工具手册",
    "risk": false
  },
  {
    "category": "构建 / 测试 / 包管理",
    "name": "ctest",
    "syntax": "ctest --test-dir build --output-on-failure",
    "description": "运行 CMake 注册的测试并显示失败输出。",
    "examples": [
      "ctest --test-dir build -j4 --output-on-failure"
    ],
    "keywords": "C C++ 测试",
    "source": "构建工具手册",
    "risk": false
  },
  {
    "category": "Docker / 容器",
    "name": "docker build",
    "syntax": "docker build -t <镜像名> <上下文>",
    "description": "从 Dockerfile 构建镜像；构建上下文会发送给 Docker daemon。",
    "examples": [
      "docker build -t demo:dev ."
    ],
    "keywords": "镜像 构建 Dockerfile",
    "source": "Docker CLI 手册",
    "risk": false
  },
  {
    "category": "Docker / 容器",
    "name": "docker run",
    "syntax": "docker run [选项] <镜像>",
    "description": "创建并启动容器；端口、挂载和环境变量需按应用配置。",
    "examples": [
      "docker run --rm -p 8080:80 nginx:alpine",
      "docker run -d --name web nginx"
    ],
    "keywords": "启动 容器 端口",
    "source": "Docker CLI 手册",
    "risk": false
  },
  {
    "category": "Docker / 容器",
    "name": "docker logs",
    "syntax": "docker logs [-f] <容器>",
    "description": "查看容器标准输出和错误输出。",
    "examples": [
      "docker logs --tail 100 web",
      "docker logs -f web"
    ],
    "keywords": "日志 排查",
    "source": "Docker CLI 手册",
    "risk": false
  },
  {
    "category": "Docker / 容器",
    "name": "docker exec",
    "syntax": "docker exec -it <容器> <命令>",
    "description": "在运行中的容器内执行命令。",
    "examples": [
      "docker exec -it web sh"
    ],
    "keywords": "进入 shell",
    "source": "Docker CLI 手册",
    "risk": false
  },
  {
    "category": "Docker / 容器",
    "name": "docker compose",
    "syntax": "docker compose up -d",
    "description": "按 compose.yaml 创建并启动多容器应用。",
    "examples": [
      "docker compose config",
      "docker compose up -d"
    ],
    "keywords": "Compose 启动 编排",
    "source": "Docker CLI 手册",
    "risk": false
  },
  {
    "category": "Docker / 容器",
    "name": "docker inspect",
    "syntax": "docker inspect <容器或镜像>",
    "description": "输出对象详细 JSON，包括网络、挂载和配置。",
    "examples": [
      "docker inspect web"
    ],
    "keywords": "检查 配置 JSON",
    "source": "Docker CLI 手册",
    "risk": false
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl config get-contexts",
    "syntax": "kubectl config get-contexts",
    "description": "列出 kubeconfig 上下文；先核对当前集群和用户。",
    "examples": [
      "kubectl config current-context",
      "kubectl config get-contexts"
    ],
    "keywords": "集群 context 上下文",
    "source": "Kubernetes kubectl 参考",
    "risk": false
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl config use-context",
    "syntax": "kubectl config use-context <上下文>",
    "description": "切换 kubectl 当前上下文，会影响后续操作目标。",
    "examples": [
      "kubectl config use-context staging"
    ],
    "keywords": "切换 集群 环境",
    "source": "Kubernetes kubectl 参考",
    "risk": true
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl get",
    "syntax": "kubectl get <资源> [-n 命名空间]",
    "description": "查看集群资源；-o wide/yaml/json 可扩展详情。",
    "examples": [
      "kubectl get pods -A -o wide",
      "kubectl get deploy,svc -n default"
    ],
    "keywords": "查询 pod service deployment",
    "source": "Kubernetes kubectl 参考",
    "risk": false
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl describe",
    "syntax": "kubectl describe <资源> <名称>",
    "description": "查看资源详情及 Events，适合排查调度、挂载和探针问题。",
    "examples": [
      "kubectl describe pod <pod> -n <ns>"
    ],
    "keywords": "排查 事件 pod",
    "source": "Kubernetes kubectl 参考",
    "risk": false
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl logs",
    "syntax": "kubectl logs <pod> [-c 容器]",
    "description": "读取容器日志；-p 查看上一次崩溃容器日志。",
    "examples": [
      "kubectl logs -f <pod> -n <ns>",
      "kubectl logs <pod> -c <container> --previous"
    ],
    "keywords": "日志 崩溃 容器",
    "source": "Kubernetes kubectl 参考",
    "risk": false
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl exec",
    "syntax": "kubectl exec -it <pod> [-c 容器] -- <命令>",
    "description": "在容器内执行命令；镜像可能不含 shell 或调试工具。",
    "examples": [
      "kubectl exec -it <pod> -n <ns> -- sh"
    ],
    "keywords": "进入 shell",
    "source": "Kubernetes kubectl 参考",
    "risk": false
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl events",
    "syntax": "kubectl get events -A --sort-by=.lastTimestamp",
    "description": "按时间查看集群事件，排查调度、拉镜像和探针错误。",
    "examples": [
      "kubectl get events -n <ns> --sort-by=.lastTimestamp"
    ],
    "keywords": "events 事件 排错",
    "source": "Kubernetes kubectl 参考",
    "risk": false
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl rollout status",
    "syntax": "kubectl rollout status deployment/<名称> -n <命名空间>",
    "description": "观察 Deployment 更新进度；history 查看修订记录。",
    "examples": [
      "kubectl rollout status deployment/api -n prod"
    ],
    "keywords": "发布 rollout 部署",
    "source": "Kubernetes kubectl 参考",
    "risk": false
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl rollout undo",
    "syntax": "kubectl rollout undo deployment/<名称> -n <命名空间>",
    "description": "回滚 Deployment 到上一修订；会改变线上工作负载。",
    "examples": [
      "kubectl rollout undo deployment/api -n prod"
    ],
    "keywords": "回滚 部署",
    "source": "Kubernetes kubectl 参考",
    "risk": true
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl diff / apply",
    "syntax": "kubectl diff -f <清单.yaml> 然后 kubectl apply -f <清单.yaml>",
    "description": "先审阅差异，再创建或更新清单声明的资源。",
    "examples": [
      "kubectl diff -f app.yaml",
      "kubectl apply -f app.yaml"
    ],
    "keywords": "部署 yaml 配置",
    "source": "Kubernetes kubectl 参考",
    "risk": true
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl port-forward",
    "syntax": "kubectl port-forward svc/<服务> 8080:80 -n <命名空间>",
    "description": "临时转发本地端口到集群服务，默认仅绑定本机。",
    "examples": [
      "kubectl port-forward svc/api 8080:80 -n staging"
    ],
    "keywords": "端口 转发 调试",
    "source": "Kubernetes kubectl 参考",
    "risk": false
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl auth can-i",
    "syntax": "kubectl auth can-i <动词> <资源> -n <命名空间>",
    "description": "检查当前身份是否有指定 RBAC 权限。",
    "examples": [
      "kubectl auth can-i list pods -n prod",
      "kubectl auth can-i --list -n prod"
    ],
    "keywords": "RBAC 权限 授权",
    "source": "Kubernetes kubectl 参考",
    "risk": false
  },
  {
    "category": "Kubernetes / kubectl",
    "name": "kubectl top",
    "syntax": "kubectl top pods -A",
    "description": "查看节点或 Pod CPU/内存使用量；需要 Metrics Server。",
    "examples": [
      "kubectl top nodes",
      "kubectl top pods -n prod --containers"
    ],
    "keywords": "资源 CPU 内存",
    "source": "Kubernetes kubectl 参考",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "证书查看",
    "syntax": "openssl x509 -in <证书.pem> -noout -text",
    "description": "查看证书主题、颁发者、有效期、SAN 和扩展。",
    "examples": [
      "openssl x509 -in server.crt -noout -subject -issuer -dates",
      "openssl x509 -in server.crt -noout -text"
    ],
    "keywords": "证书 x509 subject issuer SAN",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "证书到期时间",
    "syntax": "openssl x509 -in <证书.pem> -noout -enddate",
    "description": "读取证书 notAfter 到期时间。",
    "examples": [
      "openssl x509 -in tls.crt -noout -enddate"
    ],
    "keywords": "证书 到期 有效期 expiry",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "证书指纹",
    "syntax": "openssl x509 -in <证书.pem> -noout -fingerprint -sha256",
    "description": "计算证书 SHA-256 指纹用于比对。",
    "examples": [
      "openssl x509 -in ca.crt -noout -fingerprint -sha256"
    ],
    "keywords": "指纹 SHA256 比对",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "远端 TLS 握手",
    "syntax": "openssl s_client -connect <主机>:443 -servername <域名> -showcerts",
    "description": "检查远端 TLS 握手、SNI 证书链与验证结果。",
    "examples": [
      "openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null"
    ],
    "keywords": "TLS 握手 SNI 证书链",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "证书链验证",
    "syntax": "openssl verify -CAfile <CA文件> <证书.pem>",
    "description": "用指定 CA 文件验证证书链；需正确提供中间证书链。",
    "examples": [
      "openssl verify -CAfile ca-chain.pem server.crt"
    ],
    "keywords": "验证 CA 链 trust",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "私钥匹配检查",
    "syntax": "openssl x509 -in cert.pem -pubkey -noout",
    "description": "导出证书公钥供比对；私钥可用 openssl pkey 导出公钥后比较摘要，不输出私钥。",
    "examples": [
      "openssl x509 -in tls.crt -pubkey -noout",
      "openssl pkey -in tls.key -pubout"
    ],
    "keywords": "证书 私钥 匹配 公钥",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "CSR 查看",
    "syntax": "openssl req -in <请求.csr> -noout -text",
    "description": "检查证书签名请求中的主题、公钥和 SAN 请求字段。",
    "examples": [
      "openssl req -in server.csr -noout -text"
    ],
    "keywords": "CSR 请求 SAN 证书",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "查看 kubelet 证书",
    "syntax": "sudo openssl x509 -in /var/lib/kubelet/pki/kubelet-client-current.pem -noout -text",
    "description": "在节点本地检查 kubelet 客户端证书；路径依发行版和配置而异。",
    "examples": [
      "sudo openssl x509 -in /var/lib/kubelet/pki/kubelet-client-current.pem -noout -dates -subject"
    ],
    "keywords": "kubelet 证书 节点 客户端",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "kubeadm 证书到期",
    "syntax": "sudo kubeadm certs check-expiration",
    "description": "在 kubeadm 管理的控制平面节点查看证书到期信息。",
    "examples": [
      "sudo kubeadm certs check-expiration"
    ],
    "keywords": "kubeadm 到期 检查 expiration",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "API Server readiness",
    "syntax": "kubectl get --raw='/readyz?verbose'",
    "description": "查看 API Server readiness 检查详情，辅助识别证书或依赖组件异常。",
    "examples": [
      "kubectl get --raw='/livez?verbose'",
      "kubectl get --raw='/readyz?verbose'"
    ],
    "keywords": "apiserver 健康 探针",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "TLS Secret 类型",
    "syntax": "kubectl get secret <名称> -n <命名空间> -o jsonpath='{.type}'",
    "description": "确认 Secret 类型；避免输出私钥字段。",
    "examples": [
      "kubectl get secret ingress-tls -n prod -o jsonpath='{.type}'"
    ],
    "keywords": "Secret TLS 类型",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  },
  {
    "category": "TLS / OpenSSL / SSH",
    "name": "openssl version",
    "syntax": "openssl version -a",
    "description": "查看 OpenSSL 版本、构建选项和默认目录。",
    "examples": [
      "openssl version -a"
    ],
    "keywords": "版本 构建",
    "source": "OpenSSL / OpenSSH 手册",
    "risk": false
  },
  {
    "category": "TLS / OpenSSL / SSH",
    "name": "证书 PEM/DER 转换",
    "syntax": "openssl x509 -in cert.pem -outform DER -out cert.der",
    "description": "转换 X.509 证书编码格式。",
    "examples": [
      "openssl x509 -inform DER -in cert.der -out cert.pem"
    ],
    "keywords": "PEM DER 转换",
    "source": "OpenSSL / OpenSSH 手册",
    "risk": false
  },
  {
    "category": "TLS / OpenSSL / SSH",
    "name": "生成 CSR 与私钥",
    "syntax": "openssl req -new -newkey rsa:3072 -keyout server.key -out server.csr",
    "description": "生成私钥和 CSR；私钥需妥善保管。",
    "examples": [
      "openssl req -new -newkey rsa:3072 -keyout server.key -out server.csr"
    ],
    "keywords": "CSR 私钥 RSA 生成",
    "source": "OpenSSL / OpenSSH 手册",
    "risk": true
  },
  {
    "category": "TLS / OpenSSL / SSH",
    "name": "自签名测试证书",
    "syntax": "openssl req -x509 -newkey rsa:3072 -keyout test.key -out test.crt -days 30",
    "description": "生成短期自签名测试证书；不适合作为公开服务信任链。",
    "examples": [
      "openssl req -x509 -newkey rsa:3072 -nodes -keyout test.key -out test.crt -days 30"
    ],
    "keywords": "自签名 测试证书",
    "source": "OpenSSL / OpenSSH 手册",
    "risk": true
  },
  {
    "category": "TLS / OpenSSL / SSH",
    "name": "导出公钥",
    "syntax": "openssl pkey -in <私钥文件> -pubout",
    "description": "从私钥导出公钥部分；不要将私钥内容输出或分享。",
    "examples": [
      "openssl pkey -in server.key -pubout -out server.pub"
    ],
    "keywords": "公钥 私钥 摘要",
    "source": "OpenSSL / OpenSSH 手册",
    "risk": false
  },
  {
    "category": "TLS / OpenSSL / SSH",
    "name": "SSH 密钥指纹",
    "syntax": "ssh-keygen -lf <公钥文件>",
    "description": "查看 SSH 公钥指纹和算法。",
    "examples": [
      "ssh-keygen -lf ~/.ssh/id_ed25519.pub"
    ],
    "keywords": "SSH 指纹 公钥",
    "source": "OpenSSL / OpenSSH 手册",
    "risk": false
  },
  {
    "category": "TLS / OpenSSL / SSH",
    "name": "SSH 连通性调试",
    "syntax": "ssh -vvv -p <端口> <用户>@<主机>",
    "description": "输出详细 SSH 客户端调试信息；日志可能包含用户名和主机信息。",
    "examples": [
      "ssh -vvv user@example.com"
    ],
    "keywords": "SSH 调试 连接",
    "source": "OpenSSL / OpenSSH 手册",
    "risk": false
  },
  {
    "category": "构建 / 测试 / 包管理",
    "name": "pytest 并行",
    "syntax": "pytest -n auto",
    "description": "通过 pytest-xdist 并行测试；需安装插件且测试彼此隔离。",
    "examples": [
      "pytest -n auto"
    ],
    "keywords": "Python 测试 并行",
    "source": "构建工具手册",
    "risk": false
  },
  {
    "category": "调试 / 性能 / 诊断",
    "name": "time",
    "syntax": "time <命令>",
    "description": "测量命令墙钟时间、用户态和内核态 CPU 时间。",
    "examples": [
      "time ./app"
    ],
    "keywords": "性能 耗时",
    "source": "系统诊断工具手册",
    "risk": false
  },
  {
    "category": "调试 / 性能 / 诊断",
    "name": "strace",
    "syntax": "strace -f -o trace.log <命令>",
    "description": "跟踪 Linux 系统调用及信号，可定位文件、网络和权限问题。",
    "examples": [
      "strace -f -o trace.log ./app"
    ],
    "keywords": "系统调用 追踪 排查",
    "source": "系统诊断工具手册",
    "risk": false
  },
  {
    "category": "调试 / 性能 / 诊断",
    "name": "ltrace",
    "syntax": "ltrace -f <命令>",
    "description": "跟踪动态库函数调用，适用于部分 Linux 程序诊断。",
    "examples": [
      "ltrace ./app"
    ],
    "keywords": "动态库 调用 追踪",
    "source": "系统诊断工具手册",
    "risk": false
  },
  {
    "category": "调试 / 性能 / 诊断",
    "name": "perf stat",
    "syntax": "perf stat <命令>",
    "description": "统计程序运行期间的性能事件；可用事件受内核配置影响。",
    "examples": [
      "perf stat ./app"
    ],
    "keywords": "CPU 性能 profiling",
    "source": "系统诊断工具手册",
    "risk": false
  },
  {
    "category": "调试 / 性能 / 诊断",
    "name": "valgrind",
    "syntax": "valgrind --leak-check=full <程序>",
    "description": "使用 Memcheck 检查内存访问错误和泄漏；运行速度会明显下降。",
    "examples": [
      "valgrind --leak-check=full ./app"
    ],
    "keywords": "内存 泄漏 C C++",
    "source": "系统诊断工具手册",
    "risk": false
  },
  {
    "category": "调试 / 性能 / 诊断",
    "name": "ASan 编译",
    "syntax": "gcc -fsanitize=address -g <源文件> -o <程序>",
    "description": "编译时启用 AddressSanitizer，检测常见越界和 use-after-free。",
    "examples": [
      "gcc -fsanitize=address -fno-omit-frame-pointer -g main.c -o app"
    ],
    "keywords": "AddressSanitizer 越界 内存",
    "source": "系统诊断工具手册",
    "risk": false
  },
  {
    "category": "调试 / 性能 / 诊断",
    "name": "ulimit",
    "syntax": "ulimit -a",
    "description": "查看当前 shell 及其子进程的资源限制。",
    "examples": [
      "ulimit -a"
    ],
    "keywords": "资源 限制 文件句柄",
    "source": "系统诊断工具手册",
    "risk": false
  },
  {
    "category": "Kubernetes 证书 / TLS",
    "name": "K8s Secret 证书",
    "syntax": "kubectl get secret <名称> -n <命名空间> -o go-template='{{index .data \"tls.crt\"}}' | base64 -d | openssl x509 -noout -dates -subject -issuer",
    "description": "从 TLS Secret 读取证书并显示有效期、主题和颁发者；不要打印或导出 tls.key。",
    "examples": [
      "kubectl get secret ingress-tls -n prod -o go-template='{{index .data \"tls.crt\"}}' | base64 -d | openssl x509 -noout -dates -subject"
    ],
    "keywords": "Kubernetes secret tls.crt 证书有效期 base64",
    "source": "Kubernetes TLS / OpenSSL 手册",
    "risk": false
  }
];
