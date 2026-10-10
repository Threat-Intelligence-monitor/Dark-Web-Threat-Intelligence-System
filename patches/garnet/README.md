# Garnet 2.2.1-dwti.1

这是 DWTI 基于 Microsoft Garnet v2.2.1 编译的项目补丁，不是微软官方发行二进制。

生产线程栈显示，事务 RPUSH 持有队列键锁后等待观察者锁，阻塞读取初始化持有观察者锁后等待队列键锁。补丁只修改 `CollectionItemBroker.cs`：生产者直接投递异步通知；没有活动观察者时跳过通知；注册时清除失效队头以保留初始 WRONGTYPE 响应，并在释放观察者锁后按原 FIFO 路径重新检查键，避免超时与重新注册之间漏唤醒。

源码依据：上游标签 `v2.2.1`，提交 `b0255a31de95b1e903ee187feb59ceb04819a639`。[官方源码包](https://github.com/microsoft/garnet/archive/refs/tags/v2.2.1.zip) SHA256 为 `29d682d40e1e9e715201097d438016729224794de1684ca90ba9365c936a0fb1`。补丁与交付文件 SHA256 见 [build.json](build.json)，上游许可证见 [LICENSE.txt](LICENSE.txt)。

## 构建

使用现成 .NET SDK 10.0.400，将上述源码包解压到独立目录。在 PowerShell 中设置以下绝对路径后执行；`core.autocrlf=false` 保持源码 LF 换行，以便核对源码字节摘要。

```powershell
$garnetSourceRoot = 'D:\build\garnet-2.2.1'
$garnetPatchPath = 'D:\repo\patches\garnet\garnet-v2.2.1-broker-lock-order.patch'
$garnetSdkPath = 'D:\tools\dotnet-sdk-10.0.400\dotnet.exe'
$garnetPublishPath = 'D:\build\garnet-2.2.1-dwti.1\net10.0'

git -c core.autocrlf=false -C $garnetSourceRoot apply --check $garnetPatchPath
if ($LASTEXITCODE -ne 0) { throw 'Garnet patch check failed' }
git -c core.autocrlf=false -C $garnetSourceRoot apply $garnetPatchPath
if ($LASTEXITCODE -ne 0) { throw 'Garnet patch apply failed' }

& $garnetSdkPath publish (Join-Path $garnetSourceRoot 'main\GarnetServer\GarnetServer.csproj') `
  -c Release -f net10.0 -r win-x64 --self-contained false `
  -p:TargetFrameworks=net10.0 -p:VersionSuffix=dwti.1 `
  -p:RestoreSources=https://api.nuget.org/v3/index.json -o $garnetPublishPath
if ($LASTEXITCODE -ne 0) { throw 'Garnet build failed' }
```

运行需要 .NET 10；本次验证使用 10.0.11。归档名为 `garnet-2.2.1-dwti.1-win-x64.zip`，根目录包含 `LICENSE.txt`、`README.txt`、`garnet-build.json` 和 `net10.0/`。完整复制运行时树；实际修复代码位于 `Garnet.server.dll`，只替换 exe 无法交付修复。打包排除 `testcert.pfx`、`.snk`、`.pdb`、源码、测试、日志和其他平台原生库。

## 本地验证

所有测试使用新建的回环端口、合成 DB0 数据和隔离数据目录，未连接生产环境。

- 确定性锁回归：人为持观察者写锁，原版通知阻塞，补丁通知返回；验证实际 .NET SemaphoreSlim waiter 使用异步 continuation，消费者未在持事务锁的生产线程内执行。
- 确定性超时回归：暂停在移除 session 与完成超时状态之间；无活动 session 时写入，再注册观察者。缺少末尾检查的版本超时且留下消息，最终补丁按 FIFO 交付。取消连接和 Dispose 后 broker 主任务正常完成。
- 真实 Garnet：16 种初始先后次序、8 次超时重新注册、4 组过期及活动观察者 FIFO、WRONGTYPE 与空列表恢复；64 条 FIFO 任务完成确认，3 个生产者及 4 个消费者并发完成 180 条事务 RPUSH/BRPOP 和 HSET/ZADD/HDEL/ZREM 确认操作，任务无重复、无丢失、无残留。
- 并发期间 PING/TYPE 正常；WATCH 冲突使 EXEC 中止。提交 AOF 后终止并重启自建实例，2 条排队消息和 2 条未确认任务恢复，已被阻塞取走的消息未复活。每次停止前均核验进程路径；全部自建实例已停止。

组件使用独立发布标签 [garnet-2.2.1-dwti.1](https://github.com/Threat-Intelligence-monitor/Dark-Web-Threat-Intelligence-System/releases/tag/garnet-2.2.1-dwti.1)，主程序启动器按固定 SHA256 校验下载，离线安装可使用 `DARKWEB_GARNET_ARCHIVE_PATH`。组件发布不替代应用的最新版本，也不会自动部署生产环境。
