# Garnet 2.2.1-dwti.3

这是 DWTI 基于 Microsoft Garnet v2.2.1 编译并本地验证的项目补丁，不是微软官方发行二进制。组件与应用分别发布，服务器由操作者自行更新。

保留 dwti.1 的生产者通知锁序修复和 dwti.2 的会话生命周期修复：已超时的初始化事件不再访问旧存储会话、消费消息或删除同连接的新观察者；存储销毁先取消观察者，并及时清理所有键队列里的旧引用。阻塞读取和 AOF 提交等待检查客户端断开，覆盖明文 TCP、TLS、尚有后续命令的断连与输入半关闭。活连接仍在所需提交完成后才收到成功响应。

dwti.3 修复 AOF 事务写入与恢复：`RENAME` 源不存在和 `RENAMENX` 目标已存在时仍闭合已启动的内部事务；单日志读取合法事务中止记录不再访问多日志专用的序列管理器。单机 DB0 单日志完整恢复存在未完成事务时，在开放连接前为已提交状态生成原生检查点，等待日志起点持久化后才允许新会话写入，防止重启复用会话编号而把后续写入归入旧事务。检查点失败、日志或恢复元数据写入失败均阻止该恢复流程继续。

恢复检查点仅在完整成功回放、实际扫描到冻结尾部且尾部未变化时触发；无未完成事务、部分回放、集群及多日志不进入此分支。日志截断提交延后至恢复元数据写完才公布状态，元数据或截断异常会传递给等待者并拒绝后续提交；普通不推进日志起点的快速提交保持原行为。已经存在嵌套事务的损坏日志仍严格拒绝，需先单独核验并恢复数据；正式组件没有跳过坏记录的恢复开关。生产旧日志无法单凭事务头证明最初中断的全部触发条件。

生产 7,367 线程事件没有留下本次线程栈，其全部触发条件尚未得到直接证明。本地确定性回归证实了无限阻塞断连、过期事件访问旧会话、提交等待缺少断连取消等资源保留机制；正常 1 秒 BRPOP 和正常 AOF 提交对照均通过。AOF 停滞测试主动暂停的是本地 fixture 的提交任务，不能据此认定生产提交任务曾停止。

源码依据：上游标签 `v2.2.1`，提交 `b0255a31de95b1e903ee187feb59ceb04819a639`。[官方源码包](https://github.com/microsoft/garnet/archive/refs/tags/v2.2.1.zip) SHA256 为 `29d682d40e1e9e715201097d438016729224794de1684ca90ba9365c936a0fb1`。补丁与交付文件 SHA256 见 [build.json](build.json)，上游许可证见 [LICENSE.txt](LICENSE.txt)。

## 构建

使用现成 .NET SDK 10.0.400，将上述源码包解压到独立目录。在 PowerShell 中设置以下绝对路径后执行；`core.autocrlf=false` 保持源码 LF 换行，以便核对源码字节摘要。

```powershell
$garnetSourceRoot = 'D:\build\garnet-2.2.1'
$garnetPatchPath = 'D:\repo\patches\garnet\garnet-v2.2.1-broker-lock-order.patch'
$garnetSdkPath = 'D:\tools\dotnet-sdk-10.0.400\dotnet.exe'
$garnetPublishPath = 'D:\build\garnet-2.2.1-dwti.3\net10.0'

git -c core.autocrlf=false -C $garnetSourceRoot apply --check $garnetPatchPath
if ($LASTEXITCODE -ne 0) { throw 'Garnet patch check failed' }
git -c core.autocrlf=false -C $garnetSourceRoot apply $garnetPatchPath
if ($LASTEXITCODE -ne 0) { throw 'Garnet patch apply failed' }

& $garnetSdkPath publish (Join-Path $garnetSourceRoot 'main\GarnetServer\GarnetServer.csproj') `
  -c Release -f net10.0 -r win-x64 --self-contained false `
  -p:TargetFrameworks=net10.0 -p:VersionSuffix=dwti.3 `
  -p:RestoreSources=https://api.nuget.org/v3/index.json -o $garnetPublishPath
if ($LASTEXITCODE -ne 0) { throw 'Garnet build failed' }
```

补丁对未应用项目补丁的原始上游树使用。已验证补丁能够应用，应用后十二个文件的字节摘要均与实际构建源码一致。

运行需要 .NET 10；本次验证使用 10.0.11。归档名为 `garnet-2.2.1-dwti.3-win-x64.zip`，根目录包含 `LICENSE.txt`、`README.txt`、`garnet-build.json` 和 `net10.0/`。完整复制运行时树；实际修复代码涉及 `Garnet.server.dll`、`Garnet.common.dll` 和 `Tsavorite.core.dll`，只替换 exe 无法交付修复。启动器分别校验 exe 与三个 DLL，拒绝旧 manifest、缺失、旧版或篡改的 DLL。打包排除 `testcert.pfx`、`.snk`、`.pdb`、源码、测试、日志和其他平台原生库。

## 本地验证

所有测试使用新建的回环端口、合成 DB0 数据和隔离数据目录，未连接生产环境。

dwti.3 本地回归：

- 无检查点及已有原生检查点两组各五类重启场景：未完成事务后复用会话编号写普通键或完整事务、合法 Abort、无未完成事务、已有嵌套事务严格拒绝。新进程 READY 前检查点与持久化日志起点已越过旧尾部；随后两次冷启动保持数据并且不重复创建检查点。原发布 dwti.2 在四个场景中均能读取新检查点及后续写入。
- 两个真实同连接命令序列复现旧版问题：RENAME 源缺失、RENAMENX 目标已存在，再执行正常 MULTI/EXEC。修复后开始与结束记录匹配，命令返回、数据及冷启动一致。
- 前台检查点元数据写入失败、AOF 刷写错误、提交元数据阻塞及磁盘写入错误均使用受控 I/O 故障验证。阻塞时恢复不提前确认，失败后当前等待和后续提交报错，已排队回调不能越过错误；普通快速提交对照保持原行为。
- 不开启监听的真实恢复验证覆盖部分回放、集群配置及单物理日志双回放任务；新检查点逻辑均不触发。双回放任务原有元数据重写行为与 dwti.2 对照相同；多物理日志和多逻辑数据库仅检查了排除条件，未进行完整集群验证。

以下为 dwti.2 的既有本地验证记录：

- 九个生命周期与提交停滞回归：过期初始化、后续观察者登记、已销毁存储会话、有限及无限阻塞断连、pipeline 断连、活连接 pipeline、输入半关闭、暂停本地提交后的断连取消；完成观察者无残留。
- 真实 Kombu/采集任务：101 条正常详情完成，543 条旧消息迁移后完成 545 条详情，最近新增优先、并发窗口上限 2、零重复、零未确认残留。
- 15 分钟持续事务收发、反复断连和定期检查点完成 82,620 条任务、31,184 次主动断连，零重复和未确认残留。线程采样峰值 42，空闲后降至 16；稳定阶段私有内存 66.5–88.6 MiB。AOF 恢复后整轮业务队列、元数据和未确认索引均无残留，待处理与未确认 canary 保留。
- 二十二项启动器离线验证：完整候选包解压、三项哈希及 manifest 拒绝、旧 dwti.1 的所有权识别与并排制备、普通启动拒绝旧组件、有效 .NET 复用及损坏修复；不执行真实服务启动或停止。

组件发布标签为 [garnet-2.2.1-dwti.3](https://github.com/Threat-Intelligence-monitor/Dark-Web-Threat-Intelligence-System/releases/tag/garnet-2.2.1-dwti.3)，不作为应用 latest。主程序启动器按固定 SHA256 自动下载，离线准备可通过 `DARKWEB_GARNET_ARCHIVE_PATH` 指定对应版本的完整 ZIP。测试脚本、数据库、日志与压测数据保留在本地输出目录，没有随生产源码发布；发布流程不自动部署或重启服务器。

正常在线更新先制备新组件，再停止旧服务、切换应用并启动；不需要手工替换 DLL。旧组件 Release 保留供在线回滚使用。若设置了离线组件包覆盖路径，回滚旧应用时需要匹配旧组件包，不能宣称完全离线回滚。
