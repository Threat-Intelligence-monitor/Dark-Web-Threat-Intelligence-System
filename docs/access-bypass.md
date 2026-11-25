# 访问绕过（Access Bypass）

暗网论坛之外，项目里还有七个明网站点（darkforums、cracked、bf.st、spear.st、leakforum、raidforums、xforums）位于 Cloudflare / DDoS-Guard 之后。这些站点的采集此前只有「明文 curl → 失败 → 等浏览器」这一条路，而明文 curl 在指纹层就已经被拒绝，浏览器又因为缺隐身和挑战交互而经常拿到挑战页。本文记录绕过层的设计、配置与实测结论。

## 1. 问题定位（实测证据）

| 请求方式 | `https://darkforums.as/` | 结论 |
| --- | --- | --- |
| `curl.exe`（Windows 自带 8.21） | `403`，响应头 `Cf-Mitigated: challenge`，body 是 `<title>Checking your browser | DarkForums</title>` + `window._cf_chl_opt` | 明文客户端在 TLS 指纹层被判定为脚本 |
| Playwright + 真 Chrome（headless） | `200`，title `DarkForums`，≈195 KB | 浏览器指纹可通过，不需要解挑战 |
| `curl_cffi` `impersonate="chrome"` | `200`，≈195 KB，无 `cf-mitigated` | **TLS/HTTP2 指纹伪装即可通过** |

因此顺序是：先做便宜的 TLS 指纹伪装，只有它被挑战页挡住时才动用浏览器；浏览器侧负责隐身（去掉 `navigator.webdriver`、`cdc_` 变量、headless GPU 特征）与挑战交互（拟人点击 + 轮询），通过后把 `cf_clearance` 记下来，回灌给 HTTP 路由复用。

另一个必须记住的坑：**正常论坛页面也会内联 `/cdn-cgi/challenge-platform/` 脚本**（Cloudflare bot management 常驻）。只按 marker 判定挑战页，会把 198 KB 的真页面误判成挑战——这正是第一版 `probe` 出现 `FAIL ... cloudflare/js (HTTP 200)` 的原因。现在的判定同时要求「正文结构标记缺失」与「可见文本足够短」，见 `detect.py`。

## 2. 分层

```
adapters/*.py
   ├─ HTTP 路由: tor_fetch.fetch_via_http_proxy(site_key=...)
   │      └─ access_bypass.httpfetch  → curl_cffi(impersonate) │ curl.exe(降级)
   └─ 浏览器路由: browser_client.fetch_*_with_browser(bypass_profile=...)
          ├─ access_bypass.stealth    初始化脚本 + 启动参数
          ├─ access_bypass.challenge  挑战页拟人交互
          └─ access_bypass.clearance  记录 / 复用 cf_clearance
共同依赖: detect（响应判定）、headers（浏览器请求头）、pacing（节奏与惩罚）、profiles（配置）
```

| 模块 | 职责 |
| --- | --- |
| `model.py` | `BypassProfile`（站点级参数）、`ProtectionSignal`（单次响应判定）、`BypassOutcome`（路由结果） |
| `detect.py` | 挑战页/登录墙/限流/WAF 的识别；`classify_response(status, headers, html)` |
| `headers.py` | Chrome/Firefox/Safari/Edge 的导航请求头与 `sec-ch-ua` 指纹 |
| `httpfetch.py` | curl_cffi 伪装取数（首选）+ curl.exe 降级；clearance 注入与回写 |
| `stealth.py` | 浏览器隐身：init script、Chromium 启动参数、Firefox prefs |
| `challenge.py` | 挑战页驱动：iframe 内勾选、贝塞尔轨迹点击、等待放行、回收 cookie |
| `clearance.py` | `cf_clearance` 持久化，绑定 UA 家族 + 出口代理，带 TTL |
| `pacing.py` | 每主机抖动间隔（默认 1.5–4.5 s）与 429/503 惩罚窗口 |
| `profiles.py` | 配置解析：内置默认 → 配置文件 → 站点 `extras` → 环境变量 |
| `probe.py` | 逐站点实测可用路由的 CLI |

异常契约保持不变：绕过层只抛既有的 `CollectionFailure` kind。被挑战拦截时抛 `blocked`，而 `blocked` 在适配器里**不是终态**，所以 HTTP 被拦会自动退到浏览器路由，适配器不需要额外重试循环。

## 3. 配置

### 3.1 站点配置（`sites.yaml` 的站点条目）

```json
{
  "site_name": "darkforums",
  "access_bypass": {
    "protection": "cloudflare",
    "http_strategy": "auto",
    "stealth": "full",
    "challenge_wait_seconds": 30
  }
}
```

`access_bypass` 是可选键，缺省时使用 `profiles.py` 的内置默认值（已覆盖全部 12 个站点）。`http_strategy` 取值 `auto` / `impersonate` / `curl` / `browser`；`stealth` 取值 `none` / `basic` / `full`。

### 3.2 全局配置（`darkweb_collector/bypass_profiles.yaml`）

该文件用 **JSON 语法**（`config.py` 先按 JSON 解析，PyYAML 只是兜底且不在依赖里）。可用 `DARKWEB_COLLECTOR_BYPASS_FILE` 指向其他路径。

```json
{
  "version": 1,
  "profiles": {
    "darkforums": {"challenge_wait_seconds": 30, "clearance_ttl_seconds": 1800},
    "raidforums": {"protection": "ddos-guard", "min_interval_seconds": 4, "max_interval_seconds": 9}
  },
  "hosts": {
    "www.darkforums.as": {"challenge_wait_seconds": 30}
  }
}
```

优先级：内置默认 → `profiles[站点]` → `hosts[主机]` → `sites.yaml` 的 `access_bypass` → 环境变量。

### 3.3 参数

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `protection` | `unknown` | `cloudflare` / `ddos-guard` / `akamai` / `incapsula` / `none` |
| `http_strategy` | `auto` | `auto` 有伪装目标就用伪装，`curl` 强制降级，`browser` 直接走浏览器 |
| `impersonate` | `chrome` | curl_cffi 指纹（`chrome` / `chrome136` / `safari` / `firefox`…） |
| `header_profile` | `chrome` | 请求头身份，浏览器 UA 与之一致才能复用 clearance |
| `browser_engine` | `chromium` | 明网站点用 chromium，onion 站点用 firefox |
| `browser_channel` | 空 | 置为 `chrome` 时用本机真实 Chrome（bundled shell 最易被识别） |
| `stealth` | `full` | `none` 回退到原行为 |
| `challenge_wait_seconds` | 25 | 挑战页最长等待（上限 180），网站点默认 20–30 |
| `challenge_interactive` | `true` | 是否允许拟人点击；onion 站点默认关闭 |
| `clearance_ttl_seconds` | 1800 | clearance 复用时长（上限 86400） |
| `min/max_interval_seconds` | 1.5 / 4.5 | 同主机请求间隔，按区间下半区抖动 |
| `login_wall` | `false` | 标注该站内容需要登录 |

### 3.4 开关与回滚

- `ACCESS_BYPASS_DISABLE=1`：强制 `stealth=none`、`http_strategy=curl`、`challenge_interactive=false`，即回到改造前的行为，用于快速回滚。
- 删除 `bypass_profiles.yaml` 不影响运行，内置默认仍在。
- 清空状态：删除 `<数据根目录>/access-bypass/` 下对应主机目录。

## 4. 运行时状态

| 路径 | 内容 |
| --- | --- |
| `<data_root>/access-bypass/<host>/clearance.json` | `cf_clearance` 槽位，绑定 UA 家族 + 代理出口哈希，含 `obtained_at`/`expires_at`/来源 |
| `<data_root>/access-bypass/pacing.json` | 各主机上次请求时间与惩罚截止时间（多进程共享） |
| `<data_root>/browser-state/<site>/storage-state.json` | 浏览器会话（原有机制，xforums 依赖它复用会话） |

clearance 只在「UA 家族 + 代理出口」都匹配时复用。这是有意的：`cf_clearance` 绑定签发时的指纹，换 UA 或换出口再拿去用只会得到一个 403，反而污染状态。

## 5. 验证

```powershell
$env:PYTHONPATH = "darkweb_collector/src"
python -m darkweb_collector.access_bypass.probe --all
python -m darkweb_collector.access_bypass.probe --url https://darkforums.as/ --route impersonate
python -m darkweb_collector.access_bypass.probe --list --clearance
```

单元测试（全部离线，不需要浏览器/代理）：

```powershell
python -m pytest darkweb_collector/tests/test_access_bypass.py -q
```

### 实测结果（2026-11，经本机 7897 代理）

| 站点 | impersonate 路由 | 浏览器路由 | 结论 |
| --- | --- | --- | --- |
| darkforums.as | `200` ≈103 KB（复用 clearance） | `200` ≈195 KB，记录 `cf_clearance` | 双路由可用，HTTP 优先 |
| cracked.st | `200` ≈36 KB | 可用 | HTTP 优先 |
| breachforums (bf.st) | `200` ≈89 KB | 可用 | HTTP 优先 |
| leakforum.io | `200` ≈122 KB | 可用 | HTTP 优先 |
| raidforums.im | `200` ≈74 KB | 可用 | HTTP 优先 |
| xforums.st | `302` → `One More Step - Browser Check` | `200` ≈123 KB，**无 clearance** | 只能浏览器（约 17 s/次，靠 storage_state 复用） |
| spear.st（原 spear.cx） | 明文 curl 也是 `200` ≈84 KB，`server: ddos-guard` 不发挑战 | 待实测 | DDoS-Guard 目前是「放行」状态，HTTP 路由直接用 |

xforums 使用的是自定义 JS 挑战（`/verify-challenge?token=...`，页面 title 是 `Loading` 后脚本跳转），不放发 `cf_clearance`，所以它的 HTTP 路由永远拿不到复用凭证。这是站点实现决定的，不是配置问题；该站保持 `browser_engine=chromium` + `storage-state` 会话复用。

## 6. 已知限制

- **curl_cffi 走代理偶发握手中断**：`BoringSSL SSL_connect: Connection closed abruptly`。已保留 curl.exe 降级与重试；出现该错误时先重跑 probe 再判断站点是否真的不可达。
- **代理出口必须一致**：`_proxy_url` 优先读 `PROXY_HOST`/`PROXY_PORT`，未设置时回退 `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`。换代理会换掉 clearance 槽位。
- **浏览器启动 channel**：`browser_channel=chrome` 需要本机装有 Chrome；缺失时会自动回退到 bundled chromium，只降低隐蔽性，不影响可用性。
- **导航等待有上限**：受保护站点（cloudflare/ddos-guard/akamai/incapsula/datadome）的 `page.goto` 最多等 45s。若迟迟等不到 `domcontentloaded`，只要主文档已经到达（≥512 字节）就继续做渲染等待与挑战求解，而不是把整个请求判成超时——实测 CF 偶发把 `domcontentloaded` 挂住 58~88s。
- **挑战求解不是通用验证码识别**：只处理 Cloudflare/DDoS-Guard 的托管挑战（勾选、等待放行）。真正的图片验证码走已有的 `chaojiying` 打码路径，两者不混用。
- **不要叠加循环**：站点/目标的每小时请求预算由采集框架统一管理，绕过层不做额外的无限重试。
- **登录墙不是反爬**：站点用 403 + 「You are either not logged in or do not have permission…」这类模板拒绝游客时，请求会归为 `restricted`（正文需要账号），不会再去解挑战。这类源必须配 `session_cookie_env`/`session_cookie_file` 或在浏览器侧提供 `storage_state`，否则只能抓公开列表。bf.st、cracked、darkforums、leakforum、xforums 的部分分区属此类。
- **采集出口的信誉就是成功率**：明网请求若走 Tor 出口，Cloudflare/DDoS-Guard 会明显更严（同一个 darkforums 线程，本机直连 200，Tor 出口 403 `cloudflare/managed`）。明网站点应走普通出口，Tor 只留给 `.onion`。
- **MyBB「Hidden Content」不是权限错误**：darkforums 的线程页对游客返回 200，正文位置是 `Hidden Content — You must register or login to view this content.`。挑战解得出、页面也渲染得出来，但首帖正文仍被隐藏，只能走下面第 8 节的 RSS 订阅源（或配登录会话）。
- **别回放过期会话**：`cf_clearance` 绑定出口与 UA，过期后回放会换来硬 403（不给可解挑战）。会话超过 6 小时后自动失效、回放被 403 时自动清盘，详见 8.2。

## 7. 依赖

`curl_cffi` 是 HTTP 伪装路由的唯一依赖，已写入 `darkweb_collector/requirements.txt`。缺失时 `httpfetch` 自动降级到 `curl.exe`：请求仍带完整浏览器头，但没有 TLS 指纹，Cloudflare 站点会重新回到 403。

## 8. 站点专项：darkforums 的 RSS 发现 + 真页面镜像

darkforums 在不同出口上的待遇差别很大：有的出口明文 curl 就是 200，有的出口把列表页和线程页一起判给托管挑战（线上表现为 `direct: cloudflare/managed (HTTP 403)` + `browser: HTTP 403`）。所以这个站点把「发现主题」和「取正文镜像」两件事拆开：

1. `collect_seed` **先抓 RSS**（`https://darkforums.as/syndication.php?limit=40`，约 3 秒），把每个 `<item>` 当一条主题写入 `feed` 分区；RSS 也失败时才回退到原列表路由；
2. RSS 的 HTTP 请求若被同一出口判给挑战，自动改走浏览器路由再取一次（订阅源本身没有交互挑战，浏览器通常一次就能拿到）；
3. 主题快照落盘到 `<output_dir>/darkforums-feed.json`（默认保留 7 天、最多 300 条），供详情路由做兜底；
4. `collect_detail` **正常走真实线程页**（`direct` → `browser`），拿到的就是源站原页面的截图——这是「来源页面镜像」唯一合规的来源；
5. 真实路由全部失败时，才依次回退：feed 快照 → 已存记录的本地重建页（两者都会在镜像上打说明条，见 8.1）；
6. RSS 窗口之外、且浏览器在该出口必然 403 的老主题，不再为它们烧 90 秒的浏览器路由：一次 cheap 的 direct 探测失败后直接走兜底。

为什么发现顺序是「RSS 优先」而不是「先撞墙再兜底」：线上首轮实测里，列表路由失败要烧掉约 94 秒才轮到兜底，而 RSS 只要 3 秒。

实测（本机，2026-11-23）：40 条主题 / 3.3 s，40/40 带正文；线程页经真浏览器 9–15 s 拿到真页面 + 200 KB 级截图。

### 8.1 兜底镜像：本地重建页

真实线程页拿不到时（出口被封、或该帖对游客隐藏正文），证据页仍需要一张可看的图：

- `feed` 路由用 `render_darkforums_feed_document()` 把 RSS 正文拼成自包含页面（深色主题、绿色标题栏、作者栏、正文、原文链接），再用 `screenshot_html_with_browser()` 本地渲染截图；
- 已存记录缺图时，`mirror_render.render_mirror_document()` 用库里已有的正文做同样的事（`adapters/forum_artifacts.py:_capture_local_mirror`）；
- 这两种图都会在顶部打说明条，`源站页面拒绝访问，正文取自已保存的采集结果` 或 `正文取自 DarkForums RSS 订阅源`——**不能当作源站原始截图引用**；
- MyBB 的 `Hidden Content / You must register or login…` 标记会被改写成独立的「受限内容」提示块：原样保留会被证据渲染器误判成登录墙而中止出图。

首次渲染约 2.2 s（含浏览器启动），之后同 worker 约 0.5 s/条。

### 8.2 过期的浏览器会话必须丢弃

线上的 darkforums 详情曾长期报 `HTTP 403; browser verification page returned`，而同一台服务器上用同一份代码、**不传 `storage_state`** 的浏览器 9–15 s 就能拿到真页面。差别只有一个：`<data_root>/browser-state/darkforums/storage-state.json` 里存着 5 天前的 `cf_clearance`。

`cf_clearance` 绑定签发时的出口 IP 与 UA 指纹。拿一个过期的 clearance 去回放，Cloudflare 不会重新给可解挑战，而是直接返回硬 403 —— 比从干净上下文开始更糟。现在的规则：

- `MAX_SESSION_AGE_SECONDS = 6 小时`（`DARKWEB_BROWSER_SESSION_MAX_AGE_SECONDS` 可覆盖）：sidecar 里 `verified_at_ns` 超龄的会话，既不会喂给浏览器，也不会被 `http_session_options` 回放；
- 回放中的会话换来 403 时，`browser_client.remember_main_response()` 直接调用 `invalidate_browser_session()` 把 state + sidecar 删掉，下一次请求从干净上下文重来；
- 会话通过验证后会重新写入 sidecar，`verified_at_ns` 刷新。

排查同类问题时，先确认「是不是在回放过期会话」：拿掉 `storage_state_path` 再跑一次，如果成功，问题就在会话而不是出口。


﻿
## 9. 失效目标退休与待执行队列

同一条目标反复失败是队列里最大的隐性成本：一条已删除的帖子会先走 `direct` 再走浏览器，每次约 90 秒，而结果永远是 404。

`crawl_frontier` 现在带三个字段：`failure_streak`（连续失败次数）、`retired_at`、`retire_reason`。默认阈值：

| 失败类型 | 连续次数 | 环境变量覆盖 |
|---|---|---|
| `not_found`（404/410，帖子被删） | 2 | `DARKWEB_FRONTIER_RETIRE_NOT_FOUND` |
| `parse`（页面拿到了但解析不出正文） | 3 | `DARKWEB_FRONTIER_RETIRE_PARSE` |

达到阈值的目标变成 `retired`：不再被 `claim_frontier` 认领，`count_frontier_pending` 与 `frontier_counts` 都不再把它算进待办。站点恢复可访问后，可以在控制台点「恢复已退休」或调 `POST /api/collector/queue/retired/reset`（可限定 `site_name` / `target_url`）把它们放回队列。

队列本身通过 `GET /api/collector/queue?site=&status=&page=&page_size=` 暴露，返回每条目标的站点、状态、来源分区与发现通道、`failure_streak`、`retire_reason`，以及 `pending/running/queued/retired` 汇总。`collector_metrics.build_queue_view` 是它的数据层。

> 队列卡片的前端在 `threat-intelligence-dashboard/src/views/CollectorControl.vue`；线上控制台是另一套前端，接同样的接口即可显示。

## 10. 登录态中枢（login broker）

账号类站点（MyBB / XenForo）的正文只对登录用户开放，而 Cloudflare 的 clearance 与论坛会话是两码事：前者小时级、不需要账号；后者周/月级、必须有账号。

一个地方管三件事：

1. **凭证**：`<data_root>/credentials/<site>.json`，密码在 Windows 上走 DPAPI 加密（换机器或换账号解不开），非 Windows 退化为明文并保留 600 权限。
   - 从桌面笔记导入：`python -m darkweb_collector.login_broker import "C:\path\accounts.txt"`（识别 `网址：…` / `账密：user/pass` 这种写法）
   - 单条写入：`python -m darkweb_collector.login_broker set darkforums --username … --password …`
2. **登录**：`python -m darkweb_collector.login_broker login darkforums` 会用无头浏览器打开站点自己的登录表单，填表、提交、确认出现登出链接，然后把 storage state 通过 `source_sessions.persist_browser_session` 提交。采集器无需改动，下一次请求就会用上这份会话。
   - 登录页被托管挑战挡住时会先尝试解挑战；遇到 hCaptcha/reCAPTCHA 直接返回 `needs_human`，不会盲试。
   - 结果：`logged_in` / `failed` / `needs_human` / `no_credentials` / `imported`（附 `step` 说明卡在哪一步）。
3. **巡检**：`python -m darkweb_collector.login_broker status` 输出每个站点的 `valid` / `expired` / `missing`、cookie 数、会话年龄。会话超过 6 小时（见第 6 节）即判过期，这正是「保持登录」反而被 Cloudflare 硬 403 的根因。

挑战与验证码过不去的站点（darkforums、breachforums、cracked 等实测都属于此类），走「真人登录一次 → 导出会话」：

```bash
# 在放着桌面的机器上跑，登录完成后自动保存
python darkweb_collector/tools/capture_session.py darkforums --out darkforums.json

# 在采集器主机上导入（或用 POST /api/collector/logins/<site>/state）
python -m darkweb_collector.login_broker import-state darkforums --state-file darkforums.json
```

控制台接口：`GET /api/collector/logins`、`POST /api/collector/logins/<site>/refresh`、`POST /api/collector/logins/refresh`、`POST /api/collector/logins/<site>/state`。
