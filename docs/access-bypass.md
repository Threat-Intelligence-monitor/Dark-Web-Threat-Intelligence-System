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

## 7. 依赖

`curl_cffi` 是 HTTP 伪装路由的唯一依赖，已写入 `darkweb_collector/requirements.txt`。缺失时 `httpfetch` 自动降级到 `curl.exe`：请求仍带完整浏览器头，但没有 TLS 指纹，Cloudflare 站点会重新回到 403。

## 8. 站点专项：darkforums 改走 RSS 订阅源

darkforums 在部分出口 IP 上会把列表页和线程页一起判给托管挑战（线上表现为 `direct: cloudflare/managed (HTTP 403)` + `browser: HTTP 403`），即使换 UA、换浏览器引擎也拿不到。

同一站点的 MyBB 订阅源 `https://darkforums.as/syndication.php?limit=40` 不受挑战保护，且 `<item>` 的 `<content:encoded>` 直接携带首帖正文——正好是线程页对游客隐藏的那段内容。因此这个站点的取数顺序是倒过来的：

1. `collect_seed` **先抓 RSS**（约 3 秒），把每个 `<item>` 当一条主题写入 `feed` 分区；RSS 也失败时才回退到原列表路由；
2. RSS 的 HTTP 请求若被同一出口判给挑战，自动改走浏览器路由再取一次（订阅源本身没有交互挑战，浏览器通常一次就能拿到）；
3. 主题正文同时落盘到 `<output_dir>/darkforums-feed.json`（默认保留 7 天、最多 300 条）；
4. `collect_detail` 开头的 `_detail_from_feed` 直接复用该快照，不再请求线程页，因此**不产生截图**（`metadata["artifact_error"]` 记为待补采，后续浏览器路由可用时会自动升级）；
5. RSS 窗口之外的老主题（pending 队列里的历史线程）只走一次 cheap 的 direct 探测，不再尝试浏览器路由——在封 IP 的出口上浏览器必然 403，一次要烧 90 秒，2493 条积压就是 60 多个小时的无效等待。

为什么不是「先撞墙再兜底」：线上首轮实测里，列表路由失败要烧掉约 94 秒才轮到兜底，而 RSS 只要 3 秒——顺序对调后，同样的采集窗口能多跑十几轮。

实测（本机，2026-11-23）：40 条主题 / 3.3 s，40/40 带正文，最长 4 KB 级帖子完整可取。

可调项（写在 `sites.yaml` 的 `darkforums` 块里，走 `extras`）：

```json
{
  "site_name": "darkforums",
  "darkforums_feed_url": "https://darkforums.as/syndication.php?limit=40",
  "darkforums_feed_first": true
}
```

不配置时按 `seed_urls` 的 origin 自动拼 `/syndication.php?limit=40`；`darkforums_feed_first` 设为 `false` 可恢复「先列表、失败再兜底」的旧顺序。
