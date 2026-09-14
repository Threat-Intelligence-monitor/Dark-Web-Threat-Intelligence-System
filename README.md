# Dark Web Threat Intelligence System

暗网威胁情报系统，用于采集、标准化、检索和分析公开暗网线索、论坛内容、泄露信息与网络安全风险数据。系统包含后端采集调度服务、前端分析工作台、任务队列、运行时数据库和 Tor 网桥控制能力。

## 功能概览

- 暗网与公开风险线索采集：支持站点配置、定时入队、列表页和详情页采集。
- 威胁情报标准化：将采集内容整理为可检索、可筛选、可追踪的数据记录。
- 前端分析工作台：提供数据浏览、任务状态、采集结果和风险线索查看能力。
- 后台任务调度：使用 Redis 协议兼容服务和 Celery 处理采集、渲染、详情解析和同步任务；Windows 一键启动默认使用项目托管的 Microsoft Garnet。
- Tor 网桥控制：支持在系统内配置并启动 Snowflake / obfs4 等 Tor 网桥模式，为采集代理提供本地 SOCKS 入口。
- 一键在线更新：Windows 用户点击版本信息区域的更新按钮即可下载经校验的正式发布包，自动安装、重启并在失败时回滚，不要求安装 Git。
- Windows / WSL 启动脚本：提供一键准备依赖、注册命令、启动服务和查看状态的脚本。

## 项目结构

```text
.
├── darkweb_collector/              # 后端 API、采集器、任务队列、运行脚本
│   ├── scripts/                    # Windows / WSL 启动脚本和采集辅助脚本
│   ├── src/darkweb_collector/      # 后端应用源码
│   └── requirements.txt            # Python 依赖
├── threat-intelligence-dashboard/  # 前端工作台
│   ├── src/                        # 前端源码
│   ├── package.json
│   └── package-lock.json
└── README.md
```

## 环境要求

手动启动时需要：

- Python 3.10+
- Node.js 18+
- Redis 或兼容服务；Windows 一键启动可自动准备 Garnet
- npm

使用 Windows / WSL 启动脚本时，脚本会尽量自动检测和补齐缺失依赖。

如需使用内置 Tor 网桥，Windows、Linux 和 WSL 启动脚本会自动下载、校验并更新项目私有的 Tor Expert Bundle，不要求主机预装 Tor Browser。

## 手动启动

### 后端

```bash
cd darkweb_collector
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH="$PWD/src"
python -m uvicorn darkweb_collector.api_app:app --host 127.0.0.1 --port 8000
```

Windows PowerShell：

```powershell
cd darkweb_collector
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH = "$PWD\src"
python -m uvicorn darkweb_collector.api_app:app --host 127.0.0.1 --port 8000
```

### 前端

```bash
cd threat-intelligence-dashboard
npm install
npm run dev
```

默认前端端口为 `5174`，开发代理会转发到 `127.0.0.1:8000`。

## 一键启动

### WSL / Linux

```bash
bash darkweb_collector/scripts/start_all_services_wsl.sh start
```

常用命令：

```bash
bash darkweb_collector/scripts/start_all_services_wsl.sh start
bash darkweb_collector/scripts/start_all_services_wsl.sh status
bash darkweb_collector/scripts/start_all_services_wsl.sh attach
bash darkweb_collector/scripts/start_all_services_wsl.sh stop
```

WSL / Linux 脚本会准备后端虚拟环境、前端依赖、Redis、Playwright、本机 PostgreSQL 16 迁移目标、运行时数据库和 Tor 网桥运行组件，并拉起 API、前端、worker、scheduler 等服务；显式配置外部 PostgreSQL 时会跳过本机安装。

### Windows

普通使用只需要双击一个入口：

```powershell
.\darkweb.cmd
```

首次运行会列出本机可用磁盘和剩余空间，输入 `C`、`D`、`E` 等盘符即可。业务数据和后续在线更新的程序版本会自动放到所选磁盘并保存配置，随后继续安装依赖和启动；以后仍然只需运行 `darkweb.cmd`，不会重复询问。选择系统盘时使用 `%LOCALAPPDATA%\DarkWebThreatIntel`，选择其他盘时使用 `<盘符>:\DarkWebThreatIntel`。当前版本仍从发布包的解压目录运行；如需当前程序本体也位于所选盘，应先把发布包解压到该盘。

首次配置时如果检测到已有受管理数据，脚本会自动改用安全迁移：先停止服务、逐文件复制并执行 SHA-256 校验，切换失败会恢复旧配置，旧目录保留供复核。只有以后需要再次更换数据盘时，才使用高级迁移工具预检并迁移：

```powershell
.\configure-data-root.cmd plan -DataRoot D:\DarkWebThreatIntel
.\configure-data-root.cmd migrate -DataRoot D:\DarkWebThreatIntel
```

复测数据库查询、列表、详情、镜像下载和新采集写入后，再执行受控清理：

```powershell
.\configure-data-root.cmd cleanup
```

清理器会按迁移时保存的逐文件 SHA-256 清单复核旧副本，确认新目录文件仍存在后要求输入 `CLEANUP`，只删除未被改动的旧数据；不要手工删除整个 `%LOCALAPPDATA%\DarkWebThreatIntel`，其中仍包含很小的控制配置、命令入口和加密的 PostgreSQL 目标配置。

已有环境中显式指定、且原本就在旧数据根目录之外的输出或数据库路径会继续保留，避免迁移时擅自改写业务数据引用；`status` 命令和前端存储卡会把这些外部路径标为“部分数据仍在其他目录”。

应用版本目录与业务数据分离。默认 `DARKWEB_APP_ROOT=<数据根目录>\app`；迁移已有数据时不会复制正在运行的 Release，当前版本会暂留旧位置，下一次一键更新才写入新的应用根。需要把程序版本放到另一专用盘时，可在迁移或启动前显式设置 `DARKWEB_APP_ROOT`。

自动化部署也可以显式传入数据目录，跳过交互选择：

```powershell
.\darkweb.cmd install -DataRoot D:\DarkWebThreatIntel
```

也可以直接调用 PowerShell 脚本：

```powershell
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File .\darkweb_collector\scripts\start_all_services_windows.ps1 start
```

安装环境但不立即启动服务：

```powershell
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File .\darkweb_collector\scripts\start_all_services_windows.ps1 install
```

安装完成后，重新打开 PowerShell 或 CMD，可以使用：

```powershell
darkweb
darkweb status
darkweb stop
```

Windows 脚本会优先复用可达的显式 `REDIS_URL`。未配置服务时，脚本自动下载并校验 Microsoft Garnet 2.1.4 与项目私有 .NET 10.0.11，监听 `127.0.0.1:6380` 并固定使用 DB 0，不再要求通过 `winget` 安装 Memurai Developer。新安装环境的 Garnet 检查点、AOF、SQLite、迁移批次、证据镜像和缓存均使用已配置的数据根目录，默认每 6 小时执行一次后台检查点；完整第三方许可见 [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md)。

Windows 一键启动的采集 Worker 由后台守护进程管理，每 15 秒检查进程与队列类型，意外退出后按 15 秒至 5 分钟退避重试。Celery 就绪后才标记运行；守护进程离线、Worker 未就绪或队列类型异常会在依赖该队列的站点上显示异常原因。队列类型异常时不自动删除数据，需保留现场并定点处理后恢复。守护状态位于当前 release 的 `darkweb_collector/.runtime/windows/worker-health/`，日志沿用各 Worker 日志。该机制不替代 Garnet 底层修复，也不保证卡住但仍存活的任务已恢复。

任务列表的历史失败区支持查看近 7 天记录，每页 30 条，搜索覆盖该时间范围内全部失败记录。情报检索的报告时间排序与列表显示时间保持一致；首次启动会以每批 500 条回填旧记录的规范时间，并同步全文检索排序索引，大库首次初始化可能比平时更久。

全新安装 PostgreSQL 时，程序文件仍由 EDB 安装到系统程序目录，但数据库集群通过官方 `--datadir` 参数创建在 `<数据根目录>\postgresql\16\data`。已经存在的 PostgreSQL 服务会被复用且不会被脚本直接复制或改写；如果其集群仍在 C 盘，`darkweb status` 和数据迁移页面会明确告警，需要另行执行 PostgreSQL 备份恢复后再释放旧集群空间。

可通过 `DARKWEB_GARNET_CHECKPOINT_INTERVAL_SECONDS` 调整后台检查点间隔，最低为 300 秒；离线部署可分别用 `DARKWEB_GARNET_ARCHIVE_PATH` 和 `DARKWEB_DOTNET_RUNTIME_ARCHIVE_PATH` 指向已下载的官方压缩包，启动器仍会执行固定哈希校验。

当前托管 Garnet 路径覆盖项目已使用的 Redis 命令、Celery broker/result backend 和状态锁，不支持把它当作任意 Redis 功能的完整替代。不要为该实例引入 Redis Streams 或非 DB 0 依赖；外部 Redis、Valkey 或其他兼容服务仍可通过 `REDIS_URL` 显式配置。

## 安全卸载

默认使用“保留数据”模式，只停止项目服务并移除 `darkweb` 命令、项目虚拟环境、前端依赖、运行时文件和项目私有 Tor 组件；数据库、采集输出、登录会话和账户配置会保留，重新安装后可继续使用：

```powershell
darkweb uninstall
# 等同于
darkweb uninstall keep-data
```

需要同时删除数据库、采集输出、登录会话和账户配置时，必须显式选择“彻底删除数据”并按提示输入 `DELETE`；自动化环境可增加 `-Force`：

```powershell
darkweb uninstall purge-data
darkweb uninstall purge-data -Force
```

WSL / Linux 使用相同的两种模式：

```bash
darkweb uninstall keep-data
darkweb uninstall purge-data
darkweb uninstall purge-data --yes
```

卸载只处理项目明确管理的路径。指向项目目录和默认数据目录之外的自定义数据库、输出目录或 Tor 运行时会保留并给出提示；源码目录和 Python、Node.js、外部 Redis 或 Docker 等共享系统依赖不会被删除。Windows 的 `keep-data` 会删除项目托管的 Garnet/.NET 二进制但保留检查点，`purge-data` 才删除 Garnet 数据；PostgreSQL 集群始终由其 Windows 服务管理，项目卸载不会直接删除。Windows 可用 `-WhatIf`、WSL / Linux 可用 `--dry-run` 预览操作。

## 一键更新

登录系统后，侧边栏的版本信息区域提供“一键更新”按钮。点击后系统会：

1. 从稳定更新通道读取 `latest-stable.json`，比较发布版本。
2. 在旧服务保持运行时下载发布 ZIP，并校验清单、下载大小、SHA-256；配置公钥后还会强制验证 Ed25519 签名。
3. 安全解压到 `<DARKWEB_APP_ROOT>\releases` 下的独立版本目录，提前准备新版依赖；默认应用根为 `<数据根目录>\app`。
4. 停止旧服务，原子切换 `installation.json`，启动新版并检查 API、前端和全部托管进程。
5. 新版健康检查失败时自动恢复旧版本；成功后页面自动跳转到登录页。

更新完成后需要重新登录。Windows 在线更新不读取 `.git`、不执行 Git 命令，也不会覆盖数据库、采集输出、Cookie、账号配置、Tor 或 Garnet 数据。首次安装包含该更新器的过渡版本后，后续版本即可完全通过按钮更新；原安装目录的 `darkweb.cmd` 会自动转发到当前活动版本。

首次从普通源码目录切换到托管版本目录时，为避免复制体量较大的历史镜像，`installation.json` 会继续引用原来的 `darkweb_collector\output`。在通过数据迁移功能把镜像转入新的共享数据位置前，不要删除或移动最初的源码目录。

数据根迁移不会复制正在运行的应用版本目录；迁移完成后当前 Release 会暂时保留在旧应用根，下一次一键更新才安装到新的 `DARKWEB_APP_ROOT`。确认新版本运行和回滚均正常前，不要手工删除旧应用根。

默认清单地址为仓库最新 GitHub Release 中的 `latest-stable.json`。可通过 `DARKWEB_UPDATE_MANIFEST_URL` 指向内部 HTTPS 更新服务，使用 `DARKWEB_UPDATE_ALLOWED_HOSTS` 限制允许的下载域名，通过 `DARKWEB_SELF_UPDATE_ENABLED=0` 禁用按钮更新。配置 `DARKWEB_UPDATE_PUBLIC_KEY_FILE` 后可校验清单中的 Ed25519 签名；生产环境可同时设置 `DARKWEB_UPDATE_REQUIRE_SIGNATURE=1` 拒绝未签名发布包。当前无 Git 发布包更新器先支持 Windows，WSL / Linux 仍使用人工发布升级流程。

仓库默认 Release 流水线不接触签名私钥，因此默认发布包使用 GitHub HTTPS 来源约束和 SHA-256 完整性校验。需要强制签名时，应在受保护的独立签名环境中调用 `scripts/build_update_package.py --signing-key <私钥路径>`，并先把对应 `update-signing-public.pem` 随过渡版本交付给客户端，再启用 `DARKWEB_UPDATE_REQUIRE_SIGNATURE=1`。

## 数据库与镜像文件迁移

管理员可以在“配置中心 → 数据迁移”导入外部工具生成的 `.dwti` 文件。迁移包同时包含 SQLite 数据和证据镜像；后端会先在独立 PostgreSQL Schema 中完成安全预检、逐表导入、摘要复核和镜像释放，只有全部一致并再次确认后才切换活动数据库和镜像目录。

Windows 以及 Debian / Ubuntu / WSL / Codespaces 首次启动会自动安装或复用 PostgreSQL 16，并创建项目专用数据库和账号；已有 SQLite 数据不会自动删除或覆盖。Windows 直接下载并校验固定版本的 EDB 官方安装程序，不依赖 `winget` 或 Microsoft App Installer；离线部署可用 `DARKWEB_POSTGRESQL_INSTALLER_PATH` 指向预先下载的安装程序，仍会执行固定 SHA-256 校验。Linux 应用口令保存在当前用户私有、权限为 `600` 的配置文件中；显式设置外部 PostgreSQL URL 时不会安装本机服务。旧系统的离线打包、校验工具及 `.dwti` 包继续独立存放在项目目录之外。完整流程、回退边界和容量限制见 [`darkweb_collector/DATA_MIGRATION.md`](./darkweb_collector/DATA_MIGRATION.md)。

## 超级鹰验证码与长安会话守护

在“配置中心 → 平台接入”中可以分别配置“超级鹰验证码服务”和“长安不夜城自动登录”。超级鹰配置是公共验证码服务，后续其他图片验证码登录站点可以复用；长安配置只保存该站点的账号和密码。前端不会回显账号、密码或摘要，配置文件位于运行输出目录，不会进入 Git 仓库。

也可以在启动服务前使用环境变量配置：

```powershell
$env:DARKWEB_CHAOJIYING_USER = "<超级鹰账号>"
$env:DARKWEB_CHAOJIYING_PASSWORD = "<超级鹰密码>"
$env:DARKWEB_CHAOJIYING_SOFT_ID = "<软件 ID，可留空>"
$env:DARKWEB_CHANGAN_USERNAME = "<长安账号>"
$env:DARKWEB_CHANGAN_PASSWORD = "<长安密码>"
```

超级鹰默认使用验证码类型 `5000`，支持长安登录流程出现的中文、英文、数字和计算题图片验证码；当前不处理滑块、点选或扫码验证。识别错误时，登录流程会调用超级鹰报错接口返分。

调度器每分钟独立检查长安会话，不等待采集任务到期。发现会话失效或超过到期时间后会立即执行自动登录并保存新会话；失败后冷却 5 分钟再试。长安 API 在采集过程中返回认证失效时，也会尝试恢复会话并重试一次原请求。

## GitHub 代码监测

代码监测在 `auto` 模式下优先使用 GitHub 认证代码搜索 API。API 未配置或临时不可用时，手动扫描会继续使用现有的登录态浏览器通道；长期后台扫描不会自动启动浏览器。

PowerShell 配置示例：

```powershell
$env:DARKWEB_GITHUB_CODE_SEARCH_MODE = "auto"
$env:DARKWEB_GITHUB_TOKEN = "<GitHub App installation token 或 fine-grained token>"
```

在“代码监测”页面点击“配置 GitHub App”，填写 App ID、Installation ID 和私钥后，服务会验证安装状态并自动签发、刷新 installation token。私钥保存在已被 Git 忽略的运行数据目录，不会写入数据库、扫描结果或接口响应；Linux 下配置文件权限为 `0600`。

也可以继续由外部进程维护令牌文件，采集服务每次请求都会重新读取，无需重启：

```powershell
$env:DARKWEB_GITHUB_TOKEN_FILE = "C:\ProgramData\DarkWebThreatIntel\github-token"
```

令牌只保存在内存或从环境变量、运行时文件读取，不会保存到数据库、扫描结果或 Git 仓库。可用模式：

- `auto`：有令牌时使用 API，必要时由手动扫描回退到登录态浏览器。
- `api`：只使用 API；令牌缺失或限流时返回明确状态。
- `browser`：保持原有登录态网页搜索方式。

系统会串行发送 GitHub API 请求，读取限流响应头并进入冷却，同时在短时间内复用相同查询。GitHub 全局代码搜索仍只覆盖仓库默认分支；非默认分支不能通过全局搜索完整发现。

系统不会轮换多个个人账号来规避 GitHub 限制。需要隔离不同客户授权范围时，应为不同采集实例配置各自的 GitHub App。

## Tor 网桥

前端提供 Tor 网桥配置页面。启用后，后端会生成独立 `torrc`，启动本地 Tor 进程，并提供本地 SOCKS 代理给采集逻辑使用。

默认 SOCKS 地址：

```text
socks5h://127.0.0.1:9050
```

Windows 脚本会从 Tor Project 官方发布源自动安装并每天检查项目私有的 Tor Expert Bundle，同时从对应的官方构建标签更新内置网桥配置，并写入：

- `DARKWEB_TOR_EXECUTABLE`
- `DARKWEB_TOR_TRANSPORT_EXECUTABLE`
- `DARKWEB_TOR_PT_CONFIG_PATH`

默认安装位置是 `<数据根目录>\tor-expert`。本机 Tor Browser 仅作为自动安装失败时的兼容回退；项目不会读取其 `Browser/omni.ja`。设置 `DARKWEB_TOR_BRIDGE_AUTO_INSTALL=0` 或 `DARKWEB_TOR_BRIDGE_AUTO_UPDATE=0` 可以分别关闭运行时安装或更新检查。

## 运行数据

Windows 运行数据统一位于 `DARKWEB_DATA_ROOT` 指定的目录；未配置时使用 `%LOCALAPPDATA%\DarkWebThreatIntel`。主要目录包括：

- `<数据根目录>\collector.db`
- `<数据根目录>\output\`
- `<数据根目录>\migrations\`
- `<数据根目录>\garnet-data\`
- `<数据根目录>\playwright\`
- `<数据根目录>\app\`（后续 Release 的默认应用根）
- `<数据根目录>\postgresql\16\data\`（全新安装 PostgreSQL 时）
- `darkweb_collector/.runtime/windows/`

WSL / Linux 默认运行数据位于：

- `$HOME/.local/share/bishe/collector.db`
- `darkweb_collector/output/`
- `darkweb_collector/.runtime/wsl/`

## 访问地址

启动成功后，默认访问地址为：

- 前端：`http://localhost:5174`
- 后端健康检查：`http://127.0.0.1:8000/api/health`
