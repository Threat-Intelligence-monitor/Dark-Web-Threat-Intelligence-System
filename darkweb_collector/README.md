# Darkweb Collector

统一管理暗网公开信息采集和威胁情报提取的爬虫框架。

当前项目已经从“每个站点一个独立脚本”演进为“统一 CLI + 站点适配器 + SQLite + 可选 Celery/Redis 队列”的结构，适合持续增加新站点并复用现有抓取、去重、入库和输出逻辑。

## 当前能力

- 统一站点接入方式：`parser + adapter + sites.yaml`
- 统一运行入口：`scripts/crawl.py`
- 支持单次运行和持续轮询
- 支持 SQLite 结果落库和 `crawl_jobs` 审计
- 支持列表页增量判断和详情页按变化抓取
- 数据泄露站点支持最新页发现、持久历史回补游标和详情待抓队列
- 支持浏览器抓取与非浏览器抓取两种模式
- 按目标 URL 主机名自动区分 Tor 路径和普通代理路径

## 当前已接入站点

- `changan`
- `dragonforce`
- `darkforums`
- `cracked`
- `breachforums`（BreachForums，`bf.st`）
- `raidforums`
- `pwnfrm`
- `chaos`
- `lynx`

站点配置在 [sites.yaml](./sites.yaml)。

## 抓取路由规则

当前代理选择规则不是按 `http://` / `https://` 协议判断，而是按目标 URL 的主机名判断：

- 主机名以 `.onion` 结尾：走 Tor
- 主机名不以 `.onion` 结尾：走普通 HTTP/HTTPS 代理；未配置代理时允许直连

因此：

- `http://abc.onion/...` 走 Tor
- `https://abc.onion/...` 也走 Tor
- `https://darkforums.as/...` 优先直连，失败时回退浏览器抓取
- `https://cracked.st/...` 由浏览器队列执行，仍优先直连；403 时回退 Chromium，并在数据目录保存隔离的匿名站点状态
- `https://raidforums.im/...` 使用 MyBB 通用解析逻辑，优先直连，页面校验失败时回退 Chromium
- `https://bf.st/...` 接入 Databases、Other Leaks、Leaks Market 和 Sellers Place 四个入口，使用独立 `breachforums` 来源标识和公网浏览器队列；各入口分别保存分页游标，两个交易入口统一归入卖家交易板块，并按主题 URL 去重

`sites.yaml` 中的：

- `seed_fetch_mode`
- `detail_fetch_mode`
- `browser_queue`
- `max_concurrent_details`

只表示抓取方式：

- `tor_http`：非浏览器直取
- `browser`：浏览器渲染

浏览器任务按来源隔离：公网论坛使用 `browser_public`，`.onion` 站点使用
`browser_onion`。`browser_render` 仅用于兼容升级前已经入队的任务。
`max_concurrent_details` 限制同一站点同时执行的详情任务数量，默认值为 `1`。

是否走 Tor 由目标 URL 自动决定。

## 运行前提

### 1. Python 环境

推荐先进入虚拟环境：

```bash
cd /path/to/project/darkweb_collector
source venv/bin/activate
```

安装依赖：

```bash
pip install -r requirements.txt
```

### 2. Tor 环境

启动脚本会自动安装并更新项目私有的 Tor Expert Bundle，不要求 Windows 侧预装或启动 Tor Browser。默认由脚本设置 SOCKS 地址；仅在连接外部 Tor 时才需要手动覆盖：

```bash
export TOR_SOCKS_HOST=127.0.0.1
export TOR_SOCKS_PORT=9150
```

快速检查：

```bash
curl --socks5-hostname 127.0.0.1:9150 https://check.torproject.org/api/ip
```

### 3. 明网 HTTP/HTTPS 代理

如果要让明网站点走普通代理，可设置：

```bash
export PROXY_HOST=127.0.0.1
export PROXY_PORT=7890
```

如果不设置这两个变量，明网站点会尝试直连。

## 常用运行方式

先进入项目目录：

```bash
cd /path/to/project/darkweb_collector
```

## 一键启动整套服务

如果你希望一次性启动 Redis、后端 API、前端、采集 worker、scheduler 和同步任务，推荐在 WSL 中使用：

```bash
bash scripts/start_all_services_wsl.sh start
```

脚本会自动：

- 校验 `tmux`、`python3`、`python3-venv`、`python3-pip`、`npm`、`redis-server`、`redis-cli`、`curl`
- 在 Debian/Ubuntu/WSL 环境下，缺失时自动通过 `apt-get` 安装系统依赖
- 自动创建后端虚拟环境并安装 `requirements.txt`
- 自动安装 Playwright Firefox/Chromium 运行时，并在 Debian/Ubuntu/WSL 环境下补齐浏览器系统依赖
- 检查前端 `node_modules`，缺失时自动执行 `npm install`
- 自动安装或复用 PostgreSQL 16，幂等准备项目迁移数据库和账号；显式配置外部 PostgreSQL 时跳过本机安装
- 准备 WSL 本地运行时数据库；如果没有历史数据库，会自动初始化空库
- 用 `tmux` 拉起整套服务并保留各窗口日志

常用子命令：

```bash
# 启动
bash scripts/start_all_services_wsl.sh start

# 查看状态
bash scripts/start_all_services_wsl.sh status

# 进入 tmux 会话
bash scripts/start_all_services_wsl.sh attach

# 停止
bash scripts/start_all_services_wsl.sh stop

# 卸载运行组件但保留数据库、采集输出和登录配置
bash scripts/start_all_services_wsl.sh uninstall keep-data

# 彻底删除项目管理的数据（需要输入 DELETE）
bash scripts/start_all_services_wsl.sh uninstall purge-data
```

默认启动后可访问：

- 前端：`http://localhost:5174`
- 后端健康检查：`http://127.0.0.1:8000/api/health`

### 查看当前站点

```bash
python scripts/crawl.py list-sites
```

### 单次运行一个站点

```bash
python scripts/crawl.py run-site --site dragonforce --once
python scripts/crawl.py run-site --site darkforums --once
python scripts/crawl.py run-site --site chaos --once
```

### 持续运行一个站点

持续轮询，按站点配置的默认间隔运行：

```bash
python scripts/crawl.py run-site --site darkforums --continuous
```

手动指定轮询间隔：

```bash
python scripts/crawl.py run-site --site darkforums --continuous --interval-seconds 120
```

### 查看最近运行记录

```bash
python scripts/crawl.py show-runs --limit 20
```

## Bot 助手推送

`darkweb_collector.bot_assistant` 和 `darkweb_collector.dingtalk_bot` 支持同时配置企业微信智能机器人和钉钉自定义机器人。企业微信可接收威胁情报摘要与监测通知；代码监测完成后，两类机器人都会收到新增且进入“代码泄露监测主列表”的记录，已抑制列表不会推送。

### 前端配置

启动后端 API 和前端后，进入：

```text
http://localhost:5174/collector-control
```

在“Bot 助手推送”卡片中填写：

- `Bot ID`：企业微信“智能机器人”API 配置中显示的 Bot ID。
- `Secret`：企业微信“智能机器人”API 配置中显示的 Secret。
- `钉钉 Webhook`：钉钉群自定义机器人提供的完整 Webhook，也可以只填写 `access_token`。
- `钉钉加签 Secret`：自定义机器人启用“加签”安全设置时填写；未启用加签时可留空。

企业微信后台需选择“API 配置”，连接方式选择“使用长连接”。点击“保存配置”后，配置会保存到后端运行数据目录的 `bot_assistant_settings.json`，页面只显示脱敏后的 Bot ID，不回显完整 Secret。保存后把机器人拉进目标群聊，或直接私聊机器人，后端会通过长连接收到回调并自动登记该会话；监测事件和测试推送会发送到所有已登记会话。

钉钉配置独立保存到同一运行数据目录下的 `dingtalk_bot_settings.json`，页面只显示脱敏后的 Webhook。企业微信与钉钉配置互不覆盖，可同时接收代码泄露监测主列表的新命中通知。

### API 配置

查看配置状态：

```bash
curl http://127.0.0.1:8000/api/bot/status
```

保存企业微信机器人配置：

```bash
curl -X POST http://127.0.0.1:8000/api/bot/config \
  -H "Content-Type: application/json" \
  -d '{"provider":"wechat_work_aibot","bot_id":"企业微信智能机器人 Bot ID","secret":"企业微信智能机器人 Secret"}'
```

保存并测试钉钉机器人配置：

```bash
curl -X POST http://127.0.0.1:8000/api/dingtalk/config \
  -H "Content-Type: application/json" \
  -d '{"webhook_url":"https://oapi.dingtalk.com/robot/send?access_token=TOKEN","secret":"SEC..."}'
curl -X POST http://127.0.0.1:8000/api/dingtalk/send \
  -H "Content-Type: application/json" \
  -d '{"title":"测试推送","content":"### 暗网情报系统\n> 钉钉机器人测试消息"}'
```

触发情报摘要推送：

```bash
curl -X POST http://127.0.0.1:8000/api/bot/send \
  -H "Content-Type: application/json" \
  -d '{"type":"digest","limit":5}'
```

本地调试不实际发出请求：

```bash
curl -X POST http://127.0.0.1:8000/api/bot/send \
  -H "Content-Type: application/json" \
  -d '{"type":"markdown","content":"### 测试推送","dry_run":true}'
```

### CLI 与环境变量兜底

CLI 会优先使用后端已保存配置和已自动登记的会话目标；也可以通过参数临时传入 Bot ID、Secret 和推送目标：

```bash
python scripts/crawl.py send-bot-message --type digest --limit 5
python scripts/crawl.py send-bot-message --type digest --bot-id "Bot ID" --secret "Secret" --chat-id "userid 或 chatid"
python scripts/crawl.py send-bot-message --type text --content "暗网情报系统测试消息"
python scripts/crawl.py send-bot-message --type markdown --content "### 暗网情报系统\n> 测试推送"
python scripts/crawl.py send-bot-message --type digest --bot-id "Bot ID" --secret "Secret" --chat-id "userid 或 chatid" --dry-run
```

部署时也可以继续使用环境变量作为兜底配置：

```bash
export WECOM_BOT_ID="企业微信智能机器人 Bot ID"
export WECOM_SECRET="企业微信智能机器人 Secret"
export WECOM_HOME_CHANNEL="userid 或 chatid"
export DINGTALK_BOT_WEBHOOK="钉钉自定义机器人 Webhook"
export DINGTALK_BOT_SECRET="钉钉加签 Secret"
```

群机器人 Webhook 仍作为兼容模式保留，显式设置 `BOT_PROVIDER=wechat_work_webhook` 后可使用：

- `WECHAT_WORK_BOT_WEBHOOK`
- `WECHAT_WORK_BOT_SECRET`
- `WECHAT_BOT_WEBHOOK`

### 启动 API

```bash
export PYTHONPATH="$PWD/src"
python -m uvicorn darkweb_collector.api_app:app --host 127.0.0.1 --port 8000
```

## 兼容脚本

项目里还保留了一些兼容或辅助脚本：

- [fetch_dragonforce.py](./scripts/fetch_dragonforce.py)
- [fetch_darkforums.py](./scripts/fetch_darkforums.py)
- [fetch_onion_playwright.py](./scripts/fetch_onion_playwright.py)
- [fetch_onion_playwright_windows.py](./scripts/fetch_onion_playwright_windows.py)

其中：

- `fetch_dragonforce.py` 和 `fetch_darkforums.py` 本质上只是对统一 CLI 的薄包装
- 推荐优先使用 `scripts/crawl.py`

## 队列模式

如果需要使用 Celery/Redis 进行任务队列化运行：

设置 Redis：

```bash
export REDIS_URL=redis://127.0.0.1:6379/0
```

Windows 一键启动未显式配置 `REDIS_URL` 时会自动准备项目托管的 Microsoft Garnet，并使用 `redis://127.0.0.1:6380/0`。该兼容路径固定使用 DB 0，支持本项目当前 Celery 与状态锁命令，不应扩展为 Redis Streams 或其他未经验证的命令。

启动 worker：

```bash
python scripts/crawl.py worker --queue seed_http
python scripts/crawl.py worker --queue detail_http
python scripts/crawl.py worker --queue browser_public
python scripts/crawl.py worker --queue browser_onion
```

一键启动脚本默认启动两个公网浏览器 worker 和一个 Onion 浏览器 worker。
可用 `DARKWEB_BROWSER_PUBLIC_CONCURRENCY`、`DARKWEB_BROWSER_ONION_CONCURRENCY`
分别扩容；旧的 `DARKWEB_BROWSER_CONCURRENCY` 仍作为总量兼容配置。
为保证两个队列都可消费，隔离模式下浏览器 worker 总数最低为 `2`。

投递到期任务：

```bash
python scripts/crawl.py enqueue-due
```

详细说明可参考 [QUEUE_WORKFLOW.md](./QUEUE_WORKFLOW.md)。

## 输出与数据

### 输出目录

各站点输出在：

- `output/<site_name>/`

例如：

- `output/dragonforce/`
- `output/darkforums/`
- `output/chao/`

常见输出包括：

- `latest.json`
- `latest.html`
- `details/*.json`
- `details/*.html`
- 分板块输出目录，例如 `output/darkforums/databases/`

### 数据库

SQLite 默认路径：

- `data/collector.db`

激活 PostgreSQL 数据发布后，API 和 worker 在各自进程内复用线程安全连接池，
归还连接前会回滚未结束事务。默认每进程最少 `1`、最多 `8` 个连接，等待连接
最长 `10` 秒；可分别通过 `DARKWEB_POSTGRES_POOL_MIN`、
`DARKWEB_POSTGRES_POOL_MAX`、`DARKWEB_POSTGRES_POOL_WAIT_SECONDS` 调整。

主要包含：

- 采集结果表
- forum topic/detail 表
- `crawl_jobs` 审计表
- `crawl_frontier` 详情待抓队列和 `crawl_page_cursors` 历史分页游标

## 数据泄露站点的持续采集

`changan`、`darkforums`、`cracked`、`breachforums`、`raidforums` 和 `pwnfrm` 使用统一的分页回补与详情待抓机制；`pwnfrm` 仍按配置默认停用。

- 每轮先检查各分区最新页，默认 `recent_pages_per_run=1`
- 每站每轮共回补最多 `backfill_pages_per_run=5` 个历史页，按分区公平分配并保存游标
- 未完成的详情积压达到 `frontier_max_pending=500` 时，暂停历史回补，继续检查最新页
- 已发现详情持久保存；本轮额度不足、等待重试或任务中断都不会把它们误标为抓取完成
- 详情成功领取后才计入 `max_detail_pages_per_run`，按分区轮转，冷却中的任务不会挡住后续可抓任务
- 分开记录发现版本与成功入库版本，已成功抓取且未变化的内容会跳过

“站点管理”的展开信息和采集运行摘要展示待抓、执行中、队列已完成及各分区历史游标。队列已完成统计已发现任务，不等于源站总量；列表扫描到末页也不代表所有详情已补齐。

如果使用 `--continuous`，它不会无限无间隔请求，而是：

1. 跑一轮
2. 休眠
3. 再跑下一轮

默认间隔来自 `sites.yaml` 中该站点的 `effective_interval_seconds`。

## 新站点接入方式

新增一个站点时，必须接入当前统一架构，而不是新写一套独立脚本。

标准接入点：

1. 在 `src/darkweb_collector/sites/<site>.py` 中实现 parser
2. 在 `src/darkweb_collector/adapters/<site>.py` 中实现 `SiteAdapter`
3. 在 [registry.py](./src/darkweb_collector/adapters/registry.py) 中注册
4. 在 [sites.yaml](./sites.yaml) 中新增站点配置
5. 通过：

```bash
python scripts/crawl.py run-site --site <site_name> --once
```

验证接入是否成功

有分页列表的数据泄露站点须复用共享分页与待抓机制，接入协议、默认预算、失败恢复和验收标准见 [CRAWLER_ADAPTER_GUIDE.md](./CRAWLER_ADAPTER_GUIDE.md)。无分页、增量 API 或仅少量公告的来源应按自身能力选择发现方式，仍复用稳定标识、版本确认和有界重试；不应为了统一形式增加无效请求。

## 本地 HTML 导入与样本开发

如果你已经通过授权方式获取 HTML 样本，可以用本地样本开发 parser，而不是直接在线调试：

```bash
python scripts/import_html_sample.py \
  --site dragonforce \
  --input /mnt/d/project/darkweb_collector/output/dragonforce/latest.html \
  --source-url http://dragonforxxbp3awc7mzs5dkswrua3znqyx5roefmi4smjrsdi22xwqd.onion/ \
  --output-json /mnt/d/project/darkweb_collector/output/imported/dragonforce_from_sample.json
```

这个模式适合：

- 离线解析开发
- 字段抽取调试
- 回归测试样本沉淀

## 当前稳态策略

- 请求超时
- 有界重试
- SQLite 去重和增量更新
- 列表页每轮重抓，详情页按变化抓取
- 单个 detail 失败不阻断整轮 seed 任务
- 原始 HTML 与结构化 JSON 双落盘

## 已知边界

- 明网站点如果目标站限流、TLS 异常或代理不稳定，单个 detail 仍可能失败，但不会中断整轮任务
- `.onion` 站点依赖 Tor Browser SOCKS 可用性
- `browser` 模式资源开销高于非浏览器模式，应只在确实需要 JS 渲染时使用
- 当前持续运行模式是“轮询式持续运行”，不是无间隔高频抓取

## 数据库与镜像文件迁移

项目支持用确定性的外部工具生成 `.dwti` 迁移包，再由管理员页面一次性导入 PostgreSQL 和镜像文件。Windows、Debian / Ubuntu、WSL 和 Codespaces 首次启动会自动准备 PostgreSQL 16；显式配置外部目标时不会安装本机服务。外部打包工具和迁移包应独立存放在项目目录之外；项目内只保留 PostgreSQL 运行时准备、导入、校验、激活和回退功能。部署前提和导入流程见 [DATA_MIGRATION.md](./DATA_MIGRATION.md)。
