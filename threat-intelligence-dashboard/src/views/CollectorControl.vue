<template>
  <div class="collector-control-page ti-page">
    <section class="ti-panel ti-reveal-up">
      <div class="control-hero">
        <div class="control-hero__copy">
          <span class="ti-kicker">采集控制台</span>
          <h3>站点运行控制与情报同步</h3>
          <p>统一触发采集任务、维护漏洞与勒索情报同步，并集中查看站点健康和最近失败任务。</p>
        </div>
        <div class="control-hero__stats">
          <div class="metric-card">
            <span>总体状态</span>
            <strong>{{ jobsData.overall_status || '未知' }}</strong>
          </div>
          <div class="metric-card">
            <span>运行中任务</span>
            <strong>{{ jobsData.running_jobs || 0 }}</strong>
          </div>
          <div class="metric-card">
            <span>异常挂起</span>
            <strong>{{ jobsData.stale_jobs || 0 }}</strong>
          </div>
          <div class="metric-card">
            <span>24 小时失败</span>
            <strong>{{ jobsData.failed_jobs_24h || 0 }}</strong>
          </div>
          <div class="metric-card">
            <span>持续运行</span>
            <strong>{{ continuousStatus.enabled ? '运行中' : '未启动' }}</strong>
          </div>
          <div class="metric-card">
            <span>最近调度</span>
            <strong class="metric-card__value metric-card__value--small">{{ continuousStatus.last_tick_at || '暂无' }}</strong>
          </div>
          <div class="metric-card">
            <span>浏览器 Worker</span>
            <strong>{{ browserWorkerLabel }}</strong>
          </div>
          <div class="metric-card">
            <span>本地浏览器池</span>
            <strong>{{ localBrowserPoolLabel }}</strong>
          </div>
        </div>
      </div>
    </section>

    <section class="ti-card ti-reveal-up tor-bridge-panel">
      <div class="tor-bridge-panel__header">
        <div>
          <h3>网桥</h3>
          <p>在 Tor 被封锁的地区，网桥可用于安全访问 Tor 网络。不同地区的网络环境存在差异，网桥效果可能因人而异。</p>
        </div>
        <div class="health-actions">
          <el-button plain :loading="torBridgeLoading" @click="loadTorBridgeStatus">刷新状态</el-button>
          <el-button type="primary" :loading="torBridgeStartLoading || torBridgeSaveLoading" :disabled="!torBridgeConfig.enabled || torBridgeConfig.process_running" @click="startTorBridge">连接</el-button>
          <el-button type="danger" plain :loading="torBridgeStopLoading" :disabled="!torBridgeConfig.process_running" @click="stopTorBridge">断开</el-button>
        </div>
      </div>

      <div class="tor-bridge-body">
        <div class="tor-bridge-primary">
          <div class="tor-bridge-toggle">
            <el-switch v-model="torBridgeConfig.enabled" @change="handleTorBridgeEnabledChange" />
            <span>使用网桥</span>
          </div>

          <div class="tor-bridge-current">
            <div class="tor-bridge-current__head">
              <strong>您的网桥</strong>
              <div>
                <span>内置</span>
                <el-button text class="tor-bridge-current__menu" @click="openBuiltinBridgeDialog">...</el-button>
              </div>
            </div>
            <div class="tor-bridge-current__body">
              <strong>{{ torBridgeModeLabel }}</strong>
              <p>{{ torBridgeDescription }}</p>
            </div>
          </div>

          <div class="tor-bridge-change">
            <h4>更换网桥</h4>
            <div class="tor-bridge-change__row">
              <div>
                <span>选择 Tor 浏览器内置网桥</span>
                <p>obfs4 / Snowflake / meek</p>
              </div>
              <el-button @click="openBuiltinBridgeDialog">选择内置网桥...</el-button>
            </div>
            <div class="tor-bridge-change__row">
              <div>
                <span>输入已知的网桥地址</span>
                <p>粘贴 Bridge 行后连接</p>
              </div>
              <el-button @click="openCustomBridgeDialog">更换网桥...</el-button>
            </div>
          </div>
        </div>

        <div class="tor-bridge-runtime">
          <div class="tor-bridge-runtime__item">
            <span>连接状态</span>
            <strong :class="{ 'tor-bridge-runtime__connected': torBridgeConfig.connected }">{{ torBridgeStatusLabel }}</strong>
          </div>
          <div class="tor-bridge-runtime__item">
            <span>Tor 出口 IP</span>
            <strong class="tor-bridge-runtime__ip">{{ torBridgeExitIpLabel }}</strong>
          </div>
          <div class="tor-bridge-runtime__item tor-bridge-runtime__progress">
            <div class="tor-bridge-runtime__progress-head">
              <span>连接进度</span>
              <strong>{{ torBridgeProgress }}%</strong>
            </div>
            <el-progress :percentage="torBridgeProgress" :status="torBridgeProgressStatus" :stroke-width="8" :show-text="false" />
            <p>{{ torBridgeProgressSummary }}</p>
          </div>
          <div class="tor-bridge-runtime__item">
            <span>采集代理</span>
            <strong>{{ torBridgeConfig.collector_proxy || `socks5h://${torBridgeConfig.socks_host}:${torBridgeConfig.socks_port}` }}</strong>
          </div>
        </div>
      </div>
      <p v-if="torBridgeConfig.last_error" class="panel-note panel-note--danger">最近错误：{{ torBridgeConfig.last_error }}</p>
    </section>

    <el-dialog v-model="builtinBridgeDialogVisible" title="选择内置网桥" width="720px" class="builtin-bridge-dialog">
      <p class="builtin-bridge-dialog__intro">Tor 浏览器包括一些称为“可插拔传输”的特殊网桥，可隐藏您使用 Tor 这一事实。</p>
      <el-radio-group v-model="builtinBridgeSelection" class="builtin-bridge-list">
        <el-radio v-for="option in builtinBridgeOptions" :key="option.value" :label="option.value" class="builtin-bridge-option">
          <div>
            <div class="builtin-bridge-option__title">
              <strong>{{ option.label }}</strong>
              <span v-if="option.value === torBridgeConfig.bridge_mode">当前网桥</span>
            </div>
            <p>{{ option.description }}</p>
          </div>
        </el-radio>
      </el-radio-group>
      <template #footer>
        <el-button type="primary" :loading="torBridgeStartLoading || torBridgeSaveLoading" @click="confirmBuiltinBridgeSelection">连接</el-button>
        <el-button @click="builtinBridgeDialogVisible = false">取消</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="customBridgeDialogVisible" title="输入已知的网桥地址" width="720px">
      <el-input v-model="customBridgeLinesDraft" type="textarea" :rows="6" placeholder="Bridge obfs4 ... / Bridge snowflake ..." />
      <template #footer>
        <el-button type="primary" :loading="torBridgeStartLoading || torBridgeSaveLoading" @click="confirmCustomBridgeSelection">连接</el-button>
        <el-button @click="customBridgeDialogVisible = false">取消</el-button>
      </template>
    </el-dialog>

    <section class="ti-card ti-reveal-up">
      <div class="ti-card-header">
        <div class="ti-card-title">公开源漏洞同步</div>
        <div class="health-actions">
          <el-select v-model="vulnerabilityIntervalHours" style="width: 150px">
            <el-option label="每 1 小时" :value="1" />
            <el-option label="每 4 小时" :value="4" />
          </el-select>
          <el-button plain :loading="vulnerabilityRunLoading" @click="runVulnerabilitySyncOnce">同步一次</el-button>
          <el-button type="success" :loading="vulnerabilityContinuousLoading" :disabled="vulnerabilitySync.enabled" @click="startVulnerabilitySync">开始自动同步</el-button>
          <el-button type="danger" plain :loading="vulnerabilityContinuousLoading" :disabled="!vulnerabilitySync.enabled" @click="stopVulnerabilitySync">停止自动同步</el-button>
        </div>
      </div>
      <div class="ti-card-body status-grid">
        <div class="metric-card">
          <span>自动同步</span>
          <strong>{{ vulnerabilitySync.enabled ? '已开启' : '未开启' }}</strong>
        </div>
        <div class="metric-card">
          <span>同步间隔</span>
          <strong>{{ vulnerabilitySync.interval_seconds ? `${Math.round(vulnerabilitySync.interval_seconds / 3600)} 小时` : '未设置' }}</strong>
        </div>
        <div class="metric-card">
          <span>漏洞记录数</span>
          <strong>{{ vulnerabilitySync.record_count || 0 }}</strong>
        </div>
        <div class="metric-card">
          <span>最近同步</span>
          <strong class="metric-card__value metric-card__value--small">{{ vulnerabilitySync.last_success_at || '暂无' }}</strong>
        </div>
      </div>
    </section>

    <section class="ti-card ti-reveal-up">
      <div class="ti-card-header">
        <div class="ti-card-title">ransomware.live 同步接入</div>
        <div class="health-actions">
          <el-select v-model="ransomwareIntervalHours" style="width: 150px">
            <el-option label="每 1 小时" :value="1" />
            <el-option label="每 4 小时" :value="4" />
          </el-select>
          <el-button plain :loading="ransomwareRunLoading" @click="runRansomwareSyncOnce">同步一次</el-button>
          <el-button type="success" :loading="ransomwareContinuousLoading" :disabled="ransomwareSync.enabled" @click="startRansomwareSync">开始自动同步</el-button>
          <el-button type="danger" plain :loading="ransomwareContinuousLoading" :disabled="!ransomwareSync.enabled" @click="stopRansomwareSync">停止自动同步</el-button>
        </div>
      </div>
      <div class="ti-card-body">
        <div class="status-grid status-grid--compact">
          <div class="metric-card">
            <span>API Key</span>
            <strong>{{ ransomwareConfig.has_api_key ? '已配置' : '未配置' }}</strong>
          </div>
          <div class="metric-card">
            <span>自动同步</span>
            <strong>{{ ransomwareSync.enabled ? '已开启' : '未开启' }}</strong>
          </div>
          <div class="metric-card">
            <span>记录数</span>
            <strong>{{ ransomwareSync.record_count || 0 }}</strong>
          </div>
          <div class="metric-card">
            <span>最近同步</span>
            <strong class="metric-card__value metric-card__value--small">{{ ransomwareSync.last_success_at || '暂无' }}</strong>
          </div>
        </div>
        <div class="status-grid status-grid--compact">
          <div class="metric-card">
            <span>最新披露</span>
            <strong class="metric-card__value metric-card__value--small">{{ ransomwareSync.latest_disclosure_time || '暂无' }}</strong>
          </div>
          <div class="metric-card">
            <span>最近来源</span>
            <strong class="metric-card__value metric-card__value--small metric-card__value--break">{{ ransomwareLastSourceLabel }}</strong>
          </div>
          <div class="metric-card">
            <span>最近新增 / 更新</span>
            <strong>{{ ransomwareSync.last_new || 0 }} / {{ ransomwareSync.last_updated || 0 }}</strong>
          </div>
          <div class="metric-card">
            <span>配置来源</span>
            <strong class="metric-card__value metric-card__value--small">{{ ransomwareConfig.source || 'none' }}</strong>
          </div>
        </div>
        <div class="credential-row">
          <el-input
            v-model="ransomwareApiKey"
            type="password"
            show-password
            placeholder="输入 ransomware.live API Key"
            class="credential-row__input"
          />
          <el-button type="primary" :loading="ransomwareSaveLoading || ransomwareConfigLoading" @click="saveRansomwareConfig">保存 Key</el-button>
        </div>
        <div class="panel-note-block">
          <p class="panel-note">当前 Key：{{ ransomwareConfig.masked_api_key || '未保存' }}</p>
          <p class="panel-note panel-note--mono">配置文件：{{ ransomwareConfig.settings_path || ransomwareConfig.env_var }}</p>
          <p class="panel-note">
            最近一轮：获取 {{ ransomwareSync.last_fetched || 0 }} 条，新增 {{ ransomwareSync.last_new || 0 }} 条，更新 {{ ransomwareSync.last_updated || 0 }} 条，重复 {{ ransomwareSync.last_unchanged || 0 }} 条。
          </p>
          <p v-if="ransomwareSync.pending || ransomwareSync.running" class="panel-note">
            当前任务：{{ ransomwareSync.running ? '同步中' : '排队中' }}
          </p>
          <p v-if="ransomwareSync.last_error" class="panel-note panel-note--danger">最近错误：{{ ransomwareSync.last_error }}</p>
        </div>
      </div>
    </section>

    <section class="ti-card ti-reveal-up">
      <div class="ti-card-header">
        <div class="ti-card-title">登录态站点 Cookie 管理</div>
        <div class="health-actions">
          <span class="ti-card-subtitle">{{ cookieSites.length }} 个站点需要会话 Cookie</span>
          <el-button plain :loading="cookieListLoading" @click="loadCookieSites">刷新全部</el-button>
        </div>
      </div>
      <div class="ti-card-body">
        <el-empty v-if="!cookieListLoading && cookieSites.length === 0" description="暂无需要 Cookie 的站点" />
        <el-collapse v-else v-model="activeCookiePanels" class="cookie-collapse">
          <el-collapse-item v-for="site in cookieSites" :key="site.site_name" :name="site.site_name">
            <template #title>
              <div class="cookie-panel-title">
                <strong>{{ site.display_name || site.site_name }}</strong>
                <el-tag :type="site.configured ? 'success' : 'warning'" size="small" effect="light">
                  {{ site.configured ? '已配置' : '未配置' }}
                </el-tag>
                <el-tag v-if="site.cookie_engine" size="small" effect="plain">{{ site.cookie_engine }}</el-tag>
                <span v-if="site.configured" class="cookie-panel-meta">来源：{{ cookieSourceLabel(site.source) }}</span>
              </div>
            </template>
            <div class="cookie-panel-body">
              <div class="status-grid status-grid--compact">
                <div class="metric-card">
                  <span>当前状态</span>
                  <strong>{{ site.configured ? '已配置' : '未配置' }}</strong>
                </div>
                <div class="metric-card">
                  <span>来源</span>
                  <strong class="metric-card__value metric-card__value--small">{{ cookieSourceLabel(site.source) }}</strong>
                </div>
                <div class="metric-card">
                  <span>环境变量</span>
                  <strong class="metric-card__value metric-card__value--small">{{ site.cookie_env || '未配置' }}</strong>
                </div>
                <div class="metric-card">
                  <span>最近更新</span>
                  <strong class="metric-card__value metric-card__value--small">{{ site.updated_at || '未知' }}</strong>
                </div>
              </div>
              <div class="credential-row">
                <el-input
                  v-model="cookieInputs[site.site_name]"
                  type="password"
                  show-password
                  :placeholder="cookieInputPlaceholder(site)"
                  class="credential-row__input"
                />
                <el-button type="primary" :loading="isCookieLoading(site.site_name, 'save')" @click="saveCookie(site.site_name)">保存 Cookie</el-button>
                <el-button
                  type="danger"
                  plain
                  :loading="isCookieLoading(site.site_name, 'clear')"
                  :disabled="!site.cookie_file_exists"
                  @click="clearCookie(site.site_name)"
                >清除文件 Cookie</el-button>
                <el-button plain :loading="isCookieLoading(site.site_name, 'refresh')" @click="refreshCookieStatus(site.site_name)">刷新</el-button>
              </div>
              <div class="panel-note-block">
                <p class="panel-note">当前预览：{{ site.masked_preview || '暂无' }}</p>
                <p class="panel-note panel-note--mono">文件路径：{{ site.cookie_file || '未配置 session_cookie_file' }}</p>
                <p class="panel-note">
                  <template v-if="site.cookie_engine || site.cookie_example">
                    {{ site.display_name || site.site_name }}<template v-if="site.cookie_engine"> 是 {{ site.cookie_engine }} 站点</template><template v-if="site.cookie_example">，请粘贴包含 {{ site.cookie_example }} 的完整 Cookie 字符串</template>。
                  </template>
                  环境变量优先于文件配置。
                </p>
              </div>
            </div>
          </el-collapse-item>
        </el-collapse>
      </div>
    </section>

    <section class="ti-card ti-reveal-up">
      <div class="ti-card-header">
        <div class="ti-card-title">Bot 助手推送（企业微信 / 钉钉）</div>
        <div class="health-actions">
          <el-button plain :loading="botConfigLoading || dingtalkConfigLoading" @click="refreshBotConfigs">刷新配置</el-button>
          <el-button type="success" plain :loading="botTestLoading" :disabled="!botSmartConfigured || !botHasTargets" @click="testBotMessage">测试企业微信</el-button>
          <el-button type="danger" plain :loading="botDeleteLoading" :disabled="!botConfig.configured" @click="deleteBotConfig">删除企业微信配置</el-button>
        </div>
      </div>
      <div class="ti-card-body">
        <h3 class="bot-provider-title">企业微信智能机器人</h3>
        <div class="status-grid status-grid--compact">
          <div class="metric-card">
            <span>智能机器人</span>
            <strong>{{ botSmartConfigured ? '已配置' : '未配置' }}</strong>
          </div>
          <div class="metric-card">
            <span>Secret</span>
            <strong>{{ botSecretConfigured ? '已配置' : '未配置' }}</strong>
          </div>
          <div class="metric-card">
            <span>已登记会话</span>
            <strong class="metric-card__value metric-card__value--small">{{ botTargetLabel }}</strong>
          </div>
          <div class="metric-card">
            <span>更新时间</span>
            <strong class="metric-card__value metric-card__value--small">{{ botConfig.updated_at || '暂无' }}</strong>
          </div>
        </div>
        <div class="credential-row">
          <el-input
            v-model="botIdInput"
            type="password"
            show-password
            placeholder="Bot ID"
            class="credential-row__input"
          />
          <el-input
            v-model="botSecretInput"
            type="password"
            show-password
            placeholder="Secret"
            class="credential-row__input credential-row__input--secret"
          />
          <el-button type="primary" :loading="botSaveLoading || botConfigLoading" @click="saveBotConfig">保存配置</el-button>
        </div>
        <div class="panel-note-block">
          <p class="panel-note">当前 Bot ID：{{ botConfig.bot_id || '未保存' }}</p>
          <p class="panel-note">连接地址：{{ botConfig.websocket_url || 'wss://openws.work.weixin.qq.com' }}</p>
          <p class="panel-note">推送目标：{{ botTargetsText }}</p>
          <p class="panel-note">保存 Bot ID 和 Secret 后，把机器人拉进群聊或直接私聊机器人，系统会自动登记会话并向这些会话推送监测事件。</p>
          <p class="panel-note panel-note--mono">配置文件：{{ botConfig.settings_path || '默认运行目录' }}</p>
          <p v-if="botConfig.listener?.last_error" class="panel-note panel-note--danger">监听错误：{{ botConfig.listener.last_error }}</p>
          <p v-if="botLastError" class="panel-note panel-note--danger">最近错误：{{ botLastError }}</p>
        </div>

        <div class="bot-provider-divider"></div>
        <div class="bot-provider-heading">
          <h3 class="bot-provider-title">钉钉自定义机器人</h3>
          <div class="health-actions">
            <el-button
              type="success"
              plain
              :loading="dingtalkTestLoading"
              :disabled="!dingtalkConfigured"
              @click="testDingTalkMessage"
            >测试钉钉</el-button>
            <el-button
              type="danger"
              plain
              :loading="dingtalkDeleteLoading"
              :disabled="!dingtalkConfigured"
              @click="deleteDingTalkConfig"
            >删除钉钉配置</el-button>
          </div>
        </div>
        <div class="status-grid status-grid--compact">
          <div class="metric-card">
            <span>Webhook</span>
            <strong>{{ dingtalkConfigured ? '已配置' : '未配置' }}</strong>
          </div>
          <div class="metric-card">
            <span>加签 Secret</span>
            <strong>{{ dingtalkConfig.has_secret ? '已配置' : '未配置（可选）' }}</strong>
          </div>
          <div class="metric-card">
            <span>连接域名</span>
            <strong class="metric-card__value metric-card__value--small">{{ dingtalkConfig.webhook_host || '暂无' }}</strong>
          </div>
          <div class="metric-card">
            <span>更新时间</span>
            <strong class="metric-card__value metric-card__value--small">{{ dingtalkConfig.updated_at || '暂无' }}</strong>
          </div>
        </div>
        <div class="credential-row">
          <el-input
            v-model="dingtalkWebhookInput"
            type="password"
            show-password
            placeholder="钉钉自定义机器人 Webhook 或 access_token"
            class="credential-row__input"
          />
          <el-input
            v-model="dingtalkSecretInput"
            type="password"
            show-password
            placeholder="加签 Secret（可选）"
            class="credential-row__input credential-row__input--secret"
          />
          <el-button type="primary" :loading="dingtalkSaveLoading || dingtalkConfigLoading" @click="saveDingTalkConfig">保存钉钉配置</el-button>
        </div>
        <div class="panel-note-block">
          <p class="panel-note panel-note--mono">当前 Webhook：{{ dingtalkConfig.masked_webhook_url || '未保存' }}</p>
          <p class="panel-note">企业微信和钉钉可同时启用；代码监测仅推送新增且进入“代码泄露监测主列表”的记录，不推送已抑制列表。</p>
          <p class="panel-note panel-note--mono">配置文件：{{ dingtalkConfig.settings_path || '默认运行目录' }}</p>
          <p v-if="dingtalkLastError" class="panel-note panel-note--danger">最近错误：{{ dingtalkLastError }}</p>
        </div>
      </div>
    </section>

    <section class="ti-card ti-reveal-up">
      <div class="ti-card-header">
        <div class="ti-card-title">运行库状态</div>
        <StatusBadge :label="runtimeDbStatus.using_runtime_db ? 'WSL 运行库' : 'Windows 源库'" :tone="runtimeDbStatus.using_runtime_db ? 'success' : 'warning'" :dot="false" />
      </div>
      <div class="ti-card-body status-grid">
        <div class="metric-card">
          <span>当前数据库</span>
          <strong class="metric-card__value metric-card__value--path">{{ runtimeDbStatus.runtime_db_path || '未知' }}</strong>
        </div>
        <div class="metric-card">
          <span>源库路径</span>
          <strong class="metric-card__value metric-card__value--path">{{ runtimeDbStatus.source_db_path || '未知' }}</strong>
        </div>
        <div class="metric-card">
          <span>上次准备</span>
          <strong class="metric-card__value metric-card__value--small">{{ runtimeDbStatus.prepared_at || '未知' }}</strong>
        </div>
        <div class="metric-card">
          <span>标准化事件</span>
          <strong>{{ runtimeDbStatus.copied_counts?.normalized_intelligence_events ?? '未知' }}</strong>
        </div>
      </div>
    </section>

    <section class="ti-card ti-reveal-up">
      <div class="ti-card-header">
        <div class="ti-card-title">监测规则</div>
        <div class="health-actions">
          <el-button plain :loading="keywordLoading" @click="loadMonitoringKeywords">刷新规则</el-button>
          <el-button type="primary" plain @click="addMonitoringKeyword">新增词条</el-button>
          <el-button type="success" :loading="keywordLoading" @click="saveMonitoringKeywords">保存规则</el-button>
        </div>
      </div>
      <div class="ti-card-body">
        <div class="status-grid status-grid--compact">
          <div class="metric-card">
            <span>启用规则数</span>
            <strong>{{ monitoringStatus.enabledKeywordCount || 0 }}</strong>
          </div>
          <div class="metric-card">
            <span>高优先事件</span>
            <strong>{{ monitoringStatus.highPriorityCount || 0 }}</strong>
          </div>
          <div class="metric-card">
            <span>样本证据事件</span>
            <strong>{{ monitoringStatus.sampleEvidenceCount || 0 }}</strong>
          </div>
          <div class="metric-card">
            <span>规则覆盖事件</span>
            <strong>{{ monitoringStatus.eventCount || 0 }}</strong>
          </div>
        </div>
        <p class="panel-note">英文完整词建议使用词边界匹配，中文关键词建议使用包含匹配。</p>
        <div class="ti-table-shell">
          <el-table :data="monitoringKeywords" table-layout="fixed" style="width: 100%">
            <el-table-column label="关键词" :min-width="monitoringKeywordMinWidth">
              <template #default="{ row }">
                <el-input v-model="row.keyword" placeholder="例如 中国 / 政府 / 能源 / 企业名" />
              </template>
            </el-table-column>
            <el-table-column label="类别" :width="monitoringKeywordCategoryWidth">
              <template #default="{ row }">
                <el-select v-model="row.category">
                  <el-option label="地理关键词" value="geo_keywords" />
                  <el-option label="组织关键词" value="org_keywords" />
                  <el-option label="自定义关键词" value="custom_keywords" />
                </el-select>
              </template>
            </el-table-column>
            <el-table-column label="权重" :width="monitoringKeywordWeightWidth">
              <template #default="{ row }">
                <el-input-number v-model="row.weight" :min="1" :max="25" />
              </template>
            </el-table-column>
            <el-table-column v-if="showMonitoringMatchModeColumn" label="匹配方式" :width="monitoringKeywordMatchWidth">
              <template #default="{ row }">
                <el-select v-model="row.match_mode">
                  <el-option label="包含匹配" value="contains" />
                  <el-option label="词边界匹配" value="word_boundary" />
                </el-select>
              </template>
            </el-table-column>
            <el-table-column label="启用" :width="monitoringKeywordEnabledWidth">
              <template #default="{ row }">
                <el-switch v-model="row.enabled" />
              </template>
            </el-table-column>
            <el-table-column label="操作" :width="monitoringKeywordActionWidth">
              <template #default="{ row }">
                <el-button text type="danger" @click="removeMonitoringKeyword(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </div>
    </section>

    <section class="ti-card ti-reveal-up">
      <div class="ti-card-header">
        <div class="ti-card-title">站点健康表</div>
        <div class="health-actions">
          <el-button plain @click="refreshAllPanels">刷新状态</el-button>
          <el-button type="primary" :loading="runningAllSites" @click="runAllSitesOnce">运行全部站点</el-button>
          <el-button type="success" :loading="continuousLoading" :disabled="continuousStatus.enabled" @click="startContinuousRun">开始持续运行</el-button>
          <el-button type="danger" plain :loading="continuousLoading" :disabled="!continuousStatus.enabled" @click="stopContinuousRun">停止持续运行</el-button>
          <StatusBadge :label="jobsData.overall_status || '未知'" tone="primary" :dot="false" />
        </div>
      </div>
      <div class="ti-card-body">
        <div class="ti-table-shell site-health-table-shell">
          <el-table :data="siteHealth" style="width: 100%" table-layout="fixed">
            <el-table-column label="站点" :min-width="siteHealthSiteMinWidth" show-overflow-tooltip>
              <template #default="{ row }">{{ row.display_name || row.site_name }}</template>
            </el-table-column>
            <el-table-column prop="overall_status" label="总体状态" :width="siteHealthStatusWidth">
              <template #default="{ row }">
                <StatusBadge v-if="row.worker_error" :label="row.overall_status" tone="danger" :title="row.worker_error" />
                <span v-else>{{ row.overall_status }}</span>
              </template>
            </el-table-column>
            <el-table-column v-if="showSiteHealthWide" prop="seed_status" label="种子页状态" :width="siteHealthWideStatusWidth" />
            <el-table-column v-if="showSiteHealthWide" prop="detail_status" label="详情页状态" :width="siteHealthWideStatusWidth" />
            <el-table-column prop="running_jobs" label="运行中" :width="siteHealthSmallMetricWidth" />
            <el-table-column prop="failed_jobs_24h" label="24h 失败" :width="siteHealthMetricWidth" />
            <el-table-column label="连续失败" :width="siteHealthMetricWidth">
              <template #default="{ row }">
                {{ row.consecutive_failures || 0 }}/{{ row.failure_threshold || 3 }}
              </template>
            </el-table-column>
            <el-table-column label="熔断" :width="siteHealthCircuitWidth">
              <template #default="{ row }">
                <StatusBadge :label="circuitBreakerLabel(row)" :tone="circuitBreakerTone(row)" :dot="false" />
              </template>
            </el-table-column>
            <el-table-column v-if="showSiteHealthWide" prop="failure_cooldown_until" label="冷却至" :width="siteHealthCooldownWidth" show-overflow-tooltip />
            <el-table-column v-if="showSiteHealthErrorColumn" label="错误分类" :width="siteHealthErrorCategoryWidth">
              <template #default="{ row }">
                <StatusBadge :label="errorCategoryLabel(row.error_category)" :tone="errorCategoryTone(row.error_category)" :dot="false" />
              </template>
            </el-table-column>
            <el-table-column prop="last_success_at" label="最近成功" :min-width="siteHealthLastSuccessMinWidth" show-overflow-tooltip />
            <el-table-column v-if="showSiteHealthMedium" prop="last_error" label="最近错误" :min-width="siteHealthLastErrorMinWidth" show-overflow-tooltip />
            <el-table-column label="操作" :width="siteHealthActionWidth">
              <template #default="{ row }">
                <div class="row-actions site-health-actions">
                  <el-button v-if="row.auth_platform" size="small" type="warning" plain @click="launchSiteLogin(row)">
                    {{ row.auth_required ? '登录' : '更新登录' }}
                  </el-button>
                  <el-button size="small" type="primary" :loading="!!runningSiteMap[row.site_name]" :disabled="isSiteRunBlocked(row) || !row.enabled" @click="runSiteOnce(row.site_name)">运行一次</el-button>
                  <el-button size="small" :type="row.enabled ? 'danger' : 'success'" plain :loading="!!togglingSiteMap[row.site_name]" @click="toggleSite(row.site_name, !row.enabled)">
                    {{ row.enabled ? '停用采集' : '启用采集' }}
                  </el-button>
                </div>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </div>
    </section>

    <section class="ti-card ti-reveal-up">
      <div class="ti-card-header">
        <div class="ti-card-title">最近失败任务</div>
        <StatusBadge label="按站点追踪" tone="warning" :dot="false" />
      </div>
      <div class="ti-card-body">
        <div v-if="recentFailures.length" class="alert-stream">
          <article v-for="item in recentFailures" :key="`${item.site_name}-${item.job_type}-${item.finished_at}`" class="alert-stream__item alert-stream__item--high">
            <div class="alert-stream__meta">
              <StatusBadge :label="item.status" tone="warning" />
              <StatusBadge :label="errorCategoryLabel(item.error_category)" :tone="errorCategoryTone(item.error_category)" :dot="false" />
              <span>{{ item.finished_at }}</span>
            </div>
            <h3>{{ item.site_name }} {{ item.job_type }} {{ item.status }}</h3>
            <p>{{ item.error_message || '暂无错误详情' }}</p>
            <div class="alert-stream__source">目标：{{ item.target }}</div>
          </article>
        </div>
        <div v-else class="empty-state"><p>最近 24 小时没有失败或异常挂起任务。</p></div>
      </div>
    </section>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRouter } from 'vue-router'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { useIntelligenceData } from '@/composables/useIntelligenceData'
import { useJobsData } from '@/composables/useJobsData'
import { useContinuousJobs } from '@/composables/useContinuousJobs'

const { refresh: refreshIntelligence } = useIntelligenceData()
const router = useRouter()
const { data: jobsState, refresh: refreshJobs } = useJobsData()
const { data: continuousState, refresh: refreshContinuous } = useContinuousJobs()

const jobsData = computed(() => jobsState.value || {})
const continuousStatus = computed(() => continuousState.value || {})
const siteHealth = computed(() => jobsData.value.site_health || [])
const viewportWidth = ref(typeof window === 'undefined' ? 1440 : window.innerWidth)
const showMonitoringMatchModeColumn = computed(() => viewportWidth.value >= 1180)
const monitoringKeywordMinWidth = computed(() => viewportWidth.value < 1180 ? 180 : 200)
const monitoringKeywordCategoryWidth = computed(() => viewportWidth.value < 1180 ? 132 : 140)
const monitoringKeywordWeightWidth = computed(() => viewportWidth.value < 1180 ? 100 : 110)
const monitoringKeywordMatchWidth = computed(() => 140)
const monitoringKeywordEnabledWidth = computed(() => viewportWidth.value < 1180 ? 72 : 76)
const monitoringKeywordActionWidth = computed(() => viewportWidth.value < 1180 ? 76 : 78)
const showSiteHealthWide = computed(() => viewportWidth.value >= 1680)
const showSiteHealthMedium = computed(() => viewportWidth.value >= 1500)
const showSiteHealthErrorColumn = computed(() => viewportWidth.value >= 1500)
const siteHealthSiteMinWidth = computed(() => viewportWidth.value < 1500 ? 104 : 116)
const siteHealthStatusWidth = computed(() => viewportWidth.value < 1500 ? 76 : 82)
const siteHealthWideStatusWidth = computed(() => 88)
const siteHealthSmallMetricWidth = computed(() => viewportWidth.value < 1500 ? 62 : 66)
const siteHealthMetricWidth = computed(() => viewportWidth.value < 1500 ? 72 : 76)
const siteHealthCircuitWidth = computed(() => viewportWidth.value < 1500 ? 68 : 72)
const siteHealthCooldownWidth = computed(() => 104)
const siteHealthErrorCategoryWidth = computed(() => 82)
const siteHealthLastSuccessMinWidth = computed(() => viewportWidth.value < 1500 ? 106 : 112)
const siteHealthLastErrorMinWidth = computed(() => 140)
const siteHealthActionWidth = computed(() => viewportWidth.value < 1500 ? 252 : 260)
const recentFailures = computed(() => jobsData.value.recent_failures || [])
const vulnerabilitySync = computed(() => jobsData.value.vulnerability_sync || {})
const ransomwareSync = computed(() => jobsData.value.ransomware_sync || {})
const runtimeDbStatus = computed(() => jobsData.value.runtime_db || {})
const browserRuntime = computed(() => jobsData.value.browser_runtime || {})
const localBrowserPool = computed(() => browserRuntime.value.local_process_pool || {})
const browserWorkerLabel = computed(() => {
  if (browserRuntime.value.worker_status !== 'ready') return browserRuntime.value.worker_status === 'refreshing' ? '正在检查' : '状态未知'
  const workers = Number(browserRuntime.value.browser_worker_count || 0)
  const capacity = Number(browserRuntime.value.browser_concurrency || browserRuntime.value.configured_concurrency || 2)
  return `${workers}/${capacity}`
})
const localBrowserPoolLabel = computed(() => {
  const running = Number(localBrowserPool.value.running_or_pending || 0)
  const capacity = Number(localBrowserPool.value.max_workers || browserRuntime.value.browser_concurrency || 2)
  return `${running}/${capacity}`
})
const botSmartConfigured = computed(() => botConfig.value.provider === 'wechat_work_aibot' && botConfig.value.configured)
const botSecretConfigured = computed(() => botConfig.value.provider === 'wechat_work_aibot' && botConfig.value.has_secret)
const botHasTargets = computed(() => Number(botConfig.value.chat_target_count || 0) > 0 || Boolean(botConfig.value.chat_id))
const dingtalkConfigured = computed(() => dingtalkConfig.value.configured)
const botTargetLabel = computed(() => {
  if (botConfig.value.provider !== 'wechat_work_aibot') return '未配置'
  const count = Number(botConfig.value.chat_target_count || 0)
  if (count > 0) return `${count} 个会话`
  return botConfig.value.chat_id ? '1 个会话' : '等待登记'
})
const botTargetsText = computed(() => {
  const targets = Array.isArray(botConfig.value.chat_ids) ? botConfig.value.chat_ids.filter(Boolean) : []
  if (targets.length) return targets.join('、')
  if (botConfig.value.chat_id) return botConfig.value.chat_id
  return '未登记；把机器人拉进目标群聊或私聊机器人后自动登记'
})
const ransomwareLastSourceLabel = computed(() => {
  const raw = String(ransomwareSync.value.last_source || '').trim()
  if (!raw) return '暂无'
  try {
    return new URL(raw).host || raw
  } catch {
    return raw
  }
})
const torBridgeModeLabel = computed(() => {
  const labels = {
    snowflake: 'Snowflake',
    obfs4: 'obfs4',
    webtunnel: 'WebTunnel',
    meek_lite: 'meek',
    vanilla: 'Vanilla',
    custom: 'Custom',
  }
  return labels[torBridgeConfig.value.bridge_mode] || torBridgeConfig.value.bridge_mode || '未设置'
})
const builtinBridgeOptions = [
  {
    value: 'obfs4',
    label: 'obfs4',
    description: '可使 Tor 流量看似随机数据，在审查严格的地区可能无效。',
  },
  {
    value: 'snowflake',
    label: 'Snowflake',
    description: '通过 Snowflake 代理路由连接，使其看似视频通话。',
  },
  {
    value: 'meek_lite',
    label: 'meek',
    description: '通过大型云服务提供商将您连接到 Tor 网络。可能在审查严格的地区有效，但通常速度很慢。',
  },
]
const torBridgeDescription = computed(() => {
  const option = builtinBridgeOptions.find((item) => item.value === torBridgeConfig.value.bridge_mode)
  if (option) return option.description
  if (torBridgeConfig.value.bridge_count) return `已配置 ${torBridgeConfig.value.bridge_count} 条网桥地址。`
  return '通过内置网桥连接，Tor 和传输插件会自动检测。'
})
const torBridgeStatusLabel = computed(() => {
  const state = torBridgeConfig.value.connection_state
  if (state === 'disabled') return '未启用'
  if (state === 'connected' || torBridgeConfig.value.connected) return '已连接'
  if (state === 'connecting' || torBridgeConfig.value.process_running) return `连接中 ${torBridgeProgress.value}%`
  if (state === 'error') return '连接失败'
  return '未运行'
})
const torBridgeProgress = computed(() => {
  const value = Number(torBridgeConfig.value.bootstrap_percent || 0)
  return Math.min(100, Math.max(0, Number.isFinite(value) ? Math.round(value) : 0))
})
const torBridgeProgressStatus = computed(() => {
  if (torBridgeConfig.value.connected) return 'success'
  if (torBridgeConfig.value.connection_state === 'error') return 'exception'
  return undefined
})
const torBridgeExitIpLabel = computed(() => {
  if (torBridgeConfig.value.exit_ip_error) return '检测失败'
  if (torBridgeConfig.value.exit_ip_checking) return '检测中...'
  if (torBridgeConfig.value.exit_ip && torBridgeConfig.value.exit_ip_fresh !== false) return torBridgeConfig.value.exit_ip
  return '连接成功后显示'
})
const torBridgeProgressSummary = computed(() => {
  if (torBridgeConfig.value.connection_state === 'error' && torBridgeConfig.value.exit_ip_error) {
    return 'Tor 出网检测失败'
  }
  const labels = {
    starting: '正在启动 Tor',
    conn_pt: '正在连接网桥',
    conn_done: '已连接网桥',
    handshake: '正在建立加密握手',
    handshake_done: '加密握手已完成',
    onehop_create: '正在建立目录线路',
    requesting_status: '正在请求网络状态',
    loading_status: '正在加载网络状态',
    loading_keys: '正在加载授权密钥',
    requesting_descriptors: '正在请求中继信息',
    loading_descriptors: '正在加载中继信息',
    enough_dirinfo: '目录信息已就绪',
    ap_conn_pt: '正在连接 Tor 中继',
    ap_conn_done: '已连接 Tor 中继',
    ap_handshake: '正在与 Tor 中继握手',
    ap_handshake_done: '中继握手已完成',
    circuit_create: '正在创建 Tor 线路',
    done: 'Tor 网络连接完成',
    not_running: torBridgeConfig.value.enabled ? '等待连接' : '网桥未启用',
  }
  return labels[torBridgeConfig.value.bootstrap_stage] || torBridgeConfig.value.bootstrap_summary || '等待连接'
})

const runningAllSites = ref(false)
const continuousLoading = ref(false)
const vulnerabilityRunLoading = ref(false)
const vulnerabilityContinuousLoading = ref(false)
const vulnerabilityIntervalHours = ref(1)
const torBridgeLoading = ref(false)
const torBridgeSaveLoading = ref(false)
const torBridgeStartLoading = ref(false)
const torBridgeStopLoading = ref(false)
const torBridgeLinesText = ref('')
const builtinBridgeDialogVisible = ref(false)
const customBridgeDialogVisible = ref(false)
const builtinBridgeSelection = ref('snowflake')
const customBridgeLinesDraft = ref('')
const torBridgeConfig = ref({
  enabled: false,
  bridge_mode: 'snowflake',
  tor_executable: '',
  transport_executable: '',
  socks_host: '127.0.0.1',
  socks_port: 9050,
  bridge_lines: [],
  extra_torrc_lines: [],
  bridge_count: 0,
  process_running: false,
  process_pid: null,
  bootstrap_status: 'not_running',
  bootstrap_percent: 0,
  bootstrap_stage: 'not_running',
  bootstrap_summary: '',
  connection_state: 'not_running',
  connected: false,
  exit_ip: '',
  exit_ip_checked_at: '',
  exit_ip_error: '',
  exit_ip_checking: false,
  collector_proxy: '',
  settings_path: '',
  torrc_path: '',
  data_directory: '',
  last_error: '',
})
const ransomwareRunLoading = ref(false)
const ransomwareContinuousLoading = ref(false)
const ransomwareSaveLoading = ref(false)
const ransomwareConfigLoading = ref(false)
const ransomwareIntervalHours = ref(1)
const ransomwareApiKey = ref('')
const ransomwareConfig = ref({
  has_api_key: false,
  masked_api_key: '',
  source: 'none',
  env_var: 'RANSOMWARE_LIVE_API_KEY',
  settings_path: '',
  updated_at: '',
})
let jobsPollTimer = null
const botConfigLoading = ref(false)
const botSaveLoading = ref(false)
const botTestLoading = ref(false)
const botDeleteLoading = ref(false)
const botIdInput = ref('')
const botSecretInput = ref('')
const botLastError = ref('')
const botConfig = ref({
  provider: 'wechat_work_aibot',
  configured: false,
  source: 'none',
  has_secret: false,
  dry_run: false,
  bot_id: '',
  chat_id: '',
  chat_ids: [],
  chat_target_count: 0,
  listener: {},
  websocket_url: '',
  webhook_key: '',
  masked_webhook_url: '',
  webhook_host: '',
  settings_path: '',
  updated_at: '',
})
const dingtalkConfigLoading = ref(false)
const dingtalkSaveLoading = ref(false)
const dingtalkTestLoading = ref(false)
const dingtalkDeleteLoading = ref(false)
const dingtalkWebhookInput = ref('')
const dingtalkSecretInput = ref('')
const dingtalkLastError = ref('')
const dingtalkConfig = ref({
  provider: 'dingtalk_webhook',
  configured: false,
  source: 'none',
  has_secret: false,
  dry_run: false,
  masked_webhook_url: '',
  webhook_host: '',
  settings_path: '',
  updated_at: '',
})
const runningSiteMap = ref({})
const togglingSiteMap = ref({})
const keywordLoading = ref(false)
const monitoringStatus = ref({ keywordCount: 0, enabledKeywordCount: 0, highPriorityCount: 0, sampleEvidenceCount: 0, eventCount: 0 })
const monitoringKeywords = ref([])
const cookieSites = ref([])
const cookieInputs = reactive({})
const cookieLoadingFlags = reactive({})
const cookieListLoading = ref(false)
const activeCookiePanels = ref([])

function cookieSourceLabel(source) {
  const labels = {
    env: '环境变量',
    file: '文件',
    inline: 'sites.yaml 内联',
  }
  return labels[source] || '未配置'
}

function cookieInputPlaceholder(site) {
  return `粘贴新的 ${site.display_name || site.site_name} 会话 Cookie`
}

function ensureCookieSiteState(siteName) {
  if (!(siteName in cookieInputs)) cookieInputs[siteName] = ''
  if (!(siteName in cookieLoadingFlags)) {
    cookieLoadingFlags[siteName] = { save: false, clear: false, refresh: false }
  }
}

function isCookieLoading(siteName, action) {
  return Boolean(cookieLoadingFlags[siteName]?.[action])
}

function applyCookieSiteUpdate(updated) {
  if (!updated?.site_name) return
  const index = cookieSites.value.findIndex((site) => site.site_name === updated.site_name)
  if (index >= 0) cookieSites.value[index] = { ...cookieSites.value[index], ...updated }
  else cookieSites.value = [...cookieSites.value, updated]
  ensureCookieSiteState(updated.site_name)
}

function isSiteRunBlocked(row) {
  return row?.auth_required || row?.blockingReason === 'active_seed_job' || row?.activeSeedJobStatus === 'running' || row?.activeSeedJobStatus === 'enqueued'
}

function launchSiteLogin(row) {
  if (!row?.auth_platform) return
  router.push({
    name: 'RemotePlatformLogin',
    query: { platform: row.auth_platform, return_to: '/collector-control' },
  })
}

function errorCategoryLabel(category) {
  const labels = {
    browser_runtime: '浏览器运行时',
    timeout: '超时',
    proxy: '代理/网络',
    parse: '解析',
    site_blocked: '站点阻断',
    unknown: '未知',
  }
  return labels[category] || '无'
}

function errorCategoryTone(category) {
  if (!category) return 'neutral'
  if (category === 'browser_runtime' || category === 'site_blocked') return 'danger'
  if (category === 'timeout' || category === 'proxy') return 'warning'
  if (category === 'parse') return 'primary'
  return 'neutral'
}

function circuitBreakerLabel(row) {
  if (row?.circuit_breaker_open) return '冷却中'
  if (Number(row?.consecutive_failures || 0) > 0) return '观察'
  return '正常'
}

function circuitBreakerTone(row) {
  if (row?.circuit_breaker_open) return 'danger'
  if (Number(row?.consecutive_failures || 0) > 0) return 'warning'
  return 'success'
}

function setSiteRunning(siteName, value) {
  runningSiteMap.value = { ...runningSiteMap.value, [siteName]: value }
}

function setSiteToggling(siteName, value) {
  togglingSiteMap.value = { ...togglingSiteMap.value, [siteName]: value }
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 8000) {
  const controller = new AbortController()
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
    })
  } finally {
    window.clearTimeout(timeoutId)
  }
}

async function readApiError(response, fallbackMessage) {
  try {
    const payload = await response.json()
    return payload?.detail || payload?.message || fallbackMessage
  } catch {
    return fallbackMessage
  }
}

async function loadCookieSites() {
  cookieListLoading.value = true
  try {
    const response = await fetchWithTimeout('/api/sites/cookies')
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    const payload = await response.json()
    const sites = Array.isArray(payload?.sites) ? payload.sites : []
    cookieSites.value = sites
    sites.forEach((site) => ensureCookieSiteState(site.site_name))
    if (!activeCookiePanels.value.length && sites.length) activeCookiePanels.value = [sites[0].site_name]
  } catch (error) {
    ElMessage.error(error.message || '读取 Cookie 站点列表失败')
  } finally {
    cookieListLoading.value = false
  }
}

async function refreshCookieStatus(siteName) {
  ensureCookieSiteState(siteName)
  cookieLoadingFlags[siteName].refresh = true
  try {
    const response = await fetchWithTimeout(`/api/sites/${encodeURIComponent(siteName)}/cookie`)
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    applyCookieSiteUpdate(await response.json())
  } catch (error) {
    ElMessage.error(error.message || `读取 ${siteName} Cookie 状态失败`)
  } finally {
    cookieLoadingFlags[siteName].refresh = false
  }
}

async function saveCookie(siteName) {
  ensureCookieSiteState(siteName)
  const cookie = String(cookieInputs[siteName] || '').trim()
  if (!cookie) {
    ElMessage.error('请粘贴新的 Cookie 字符串')
    return
  }
  cookieLoadingFlags[siteName].save = true
  try {
    const response = await fetchWithTimeout(`/api/sites/${encodeURIComponent(siteName)}/cookie`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cookie }),
    })
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    applyCookieSiteUpdate(await response.json())
    cookieInputs[siteName] = ''
    ElMessage.success(`已保存 ${siteName} Cookie`)
  } catch (error) {
    ElMessage.error(error.message || '保存 Cookie 失败')
  } finally {
    cookieLoadingFlags[siteName].save = false
  }
}

async function clearCookie(siteName) {
  ensureCookieSiteState(siteName)
  cookieLoadingFlags[siteName].clear = true
  try {
    const response = await fetchWithTimeout(`/api/sites/${encodeURIComponent(siteName)}/cookie`, { method: 'DELETE' })
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    applyCookieSiteUpdate(await response.json())
    ElMessage.success(`已清除 ${siteName} 文件 Cookie`)
  } catch (error) {
    ElMessage.error(error.message || '清除 Cookie 失败')
  } finally {
    cookieLoadingFlags[siteName].clear = false
  }
}

async function loadMonitoringKeywords() {
  keywordLoading.value = true
  try {
    const [keywordsResponse, statusResponse] = await Promise.all([
      fetchWithTimeout('/api/monitoring/keywords'),
      fetchWithTimeout('/api/analysis/monitoring-status'),
    ])
    monitoringKeywords.value = keywordsResponse.ok ? await keywordsResponse.json() : []
    monitoringStatus.value = statusResponse.ok ? await statusResponse.json() : monitoringStatus.value
  } finally {
    keywordLoading.value = false
  }
}

async function loadRansomwareConfig() {
  ransomwareConfigLoading.value = true
  try {
    const response = await fetch('/api/ransomware/config')
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    ransomwareConfig.value = await response.json()
  } catch (error) {
    ElMessage.error(error.message || '读取 ransomware.live 配置失败')
  } finally {
    ransomwareConfigLoading.value = false
  }
}

function textToLines(value) {
  return String(value || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
}

function applyTorBridgeStatus(payload) {
  torBridgeConfig.value = {
    ...torBridgeConfig.value,
    ...payload,
    socks_port: Number(payload?.socks_port || 9050),
    bridge_lines: Array.isArray(payload?.bridge_lines) ? payload.bridge_lines : [],
    extra_torrc_lines: Array.isArray(payload?.extra_torrc_lines) ? payload.extra_torrc_lines : [],
  }
  torBridgeLinesText.value = torBridgeConfig.value.bridge_lines.join('\n')
}

let torBridgePollTimer = null
let torBridgePollInFlight = false

function clearTorBridgePoll() {
  if (torBridgePollTimer) window.clearTimeout(torBridgePollTimer)
  torBridgePollTimer = null
}

function shouldPollTorBridge() {
  return Boolean(torBridgeConfig.value.process_running)
}

function scheduleTorBridgePoll(delay = null) {
  clearTorBridgePoll()
  if (!shouldPollTorBridge()) return
  const nextDelay = delay ?? (
    torBridgeConfig.value.connected && torBridgeConfig.value.exit_ip && !torBridgeConfig.value.exit_ip_checking
      ? 30000
      : 1500
  )
  torBridgePollTimer = window.setTimeout(async () => {
    if (torBridgePollInFlight) {
      scheduleTorBridgePoll()
      return
    }
    torBridgePollInFlight = true
    try {
      await loadTorBridgeStatus({ silent: true, schedule: false })
    } finally {
      torBridgePollInFlight = false
      scheduleTorBridgePoll()
    }
  }, nextDelay)
}

async function loadTorBridgeStatus(options = {}) {
  const silent = Boolean(options?.silent)
  if (!silent) torBridgeLoading.value = true
  try {
    const response = await fetch('/api/tor-bridge/status')
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    applyTorBridgeStatus(await response.json())
    if (options?.schedule !== false) scheduleTorBridgePoll()
  } catch (error) {
    if (!silent) ElMessage.error(error.message || '读取 Tor 网桥状态失败')
  } finally {
    if (!silent) torBridgeLoading.value = false
  }
}

async function saveTorBridgeConfig(options = {}) {
  const silent = Boolean(options?.silent)
  torBridgeSaveLoading.value = true
  try {
    const response = await fetch('/api/tor-bridge/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enabled: Boolean(torBridgeConfig.value.enabled),
        bridge_mode: torBridgeConfig.value.bridge_mode || 'snowflake',
        socks_host: torBridgeConfig.value.socks_host || '127.0.0.1',
        socks_port: Number(torBridgeConfig.value.socks_port || 9050),
        bridge_lines: textToLines(torBridgeLinesText.value),
        extra_torrc_lines: [],
        tor_executable: '',
        transport_executable: '',
        data_directory: '',
      }),
    })
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    applyTorBridgeStatus(await response.json())
    if (!silent) ElMessage.success('Tor 网桥配置已保存')
    return true
  } catch (error) {
    ElMessage.error(error.message || '保存 Tor 网桥配置失败')
    return false
  } finally {
    torBridgeSaveLoading.value = false
  }
}

async function startTorBridge() {
  torBridgeStartLoading.value = true
  try {
    const saved = await saveTorBridgeConfig({ silent: true })
    if (!saved) return
    const response = await fetch('/api/tor-bridge/start', { method: 'POST' })
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    applyTorBridgeStatus(await response.json())
    scheduleTorBridgePoll(300)
    ElMessage.success('正在连接 Tor 网桥')
  } catch (error) {
    ElMessage.error(error.message || '启动 Tor 网桥失败')
  } finally {
    torBridgeStartLoading.value = false
  }
}

async function stopTorBridge() {
  clearTorBridgePoll()
  torBridgeStopLoading.value = true
  try {
    const response = await fetch('/api/tor-bridge/stop', { method: 'POST' })
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    applyTorBridgeStatus(await response.json())
    ElMessage.success('Tor 网桥已停止')
  } catch (error) {
    ElMessage.error(error.message || '停止 Tor 网桥失败')
  } finally {
    torBridgeStopLoading.value = false
  }
}

async function handleTorBridgeEnabledChange(enabled) {
  if (!enabled && torBridgeConfig.value.process_running) {
    await stopTorBridge()
  }
  await saveTorBridgeConfig({ silent: true })
}

function openBuiltinBridgeDialog() {
  const current = builtinBridgeOptions.some((option) => option.value === torBridgeConfig.value.bridge_mode)
    ? torBridgeConfig.value.bridge_mode
    : 'snowflake'
  builtinBridgeSelection.value = current
  builtinBridgeDialogVisible.value = true
}

async function confirmBuiltinBridgeSelection() {
  torBridgeConfig.value.enabled = true
  torBridgeConfig.value.bridge_mode = builtinBridgeSelection.value || 'snowflake'
  torBridgeLinesText.value = ''
  builtinBridgeDialogVisible.value = false
  await startTorBridge()
}

function openCustomBridgeDialog() {
  customBridgeLinesDraft.value = torBridgeLinesText.value
  customBridgeDialogVisible.value = true
}

function inferBridgeModeFromLines(lines) {
  const first = String(lines?.[0] || '').replace(/^bridge\s+/i, '').trim().split(/\s+/)[0]?.toLowerCase()
  if (first === 'meek') return 'meek_lite'
  if (['snowflake', 'obfs4', 'webtunnel', 'meek_lite', 'vanilla'].includes(first)) return first
  return 'custom'
}

async function confirmCustomBridgeSelection() {
  const lines = textToLines(customBridgeLinesDraft.value)
  if (!lines.length) {
    ElMessage.error('请输入网桥地址')
    return
  }
  torBridgeConfig.value.enabled = true
  torBridgeConfig.value.bridge_mode = inferBridgeModeFromLines(lines)
  torBridgeLinesText.value = lines.join('\n')
  customBridgeDialogVisible.value = false
  await startTorBridge()
}

async function refreshAllPanels() {
  await Promise.all([
    refreshIntelligence(),
    refreshJobs(),
    refreshContinuous(),
    loadMonitoringKeywords(),
    loadRansomwareConfig(),
    loadCookieSites(),
    loadBotConfig(),
    loadDingTalkConfig(),
    loadTorBridgeStatus(),
  ])
}

async function refreshBotConfigs() {
  await Promise.all([loadBotConfig(), loadDingTalkConfig()])
}

async function loadBotConfig() {
  botConfigLoading.value = true
  try {
    const response = await fetch('/api/bot/status')
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    botConfig.value = await response.json()
    botLastError.value = ''
  } catch (error) {
    botLastError.value = error.message || '读取 Bot 配置失败'
    ElMessage.error(botLastError.value)
  } finally {
    botConfigLoading.value = false
  }
}

async function saveBotConfig() {
  const botIdValue = String(botIdInput.value || '').trim()
  const secretValue = String(botSecretInput.value || '').trim()
  if (!botIdValue || !secretValue) {
    ElMessage.error('请输入企业微信智能机器人的 Bot ID 和 Secret')
    return
  }

  botSaveLoading.value = true
  try {
    const response = await fetch('/api/bot/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: 'wechat_work_aibot',
        bot_id: botIdValue,
        secret: secretValue,
      }),
    })
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    botConfig.value = await response.json()
    botIdInput.value = ''
    botSecretInput.value = ''
    botLastError.value = ''
    ElMessage.success('Bot 助手配置已保存')
  } catch (error) {
    botLastError.value = error.message || '保存 Bot 助手配置失败'
    ElMessage.error(botLastError.value)
  } finally {
    botSaveLoading.value = false
  }
}

async function deleteBotConfig() {
  try {
    await ElMessageBox.confirm(
      '仅删除企业微信机器人保存配置和已登记会话，不会删除监测对象、企业画像或历史数据。',
      '删除企业微信配置',
      {
        type: 'warning',
        confirmButtonText: '确认删除',
        cancelButtonText: '取消',
      },
    )
  } catch {
    return
  }
  botDeleteLoading.value = true
  try {
    const response = await fetch('/api/bot/config', { method: 'DELETE' })
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    botConfig.value = await response.json()
    botIdInput.value = ''
    botSecretInput.value = ''
    botLastError.value = ''
    if (botConfig.value.configured) {
      ElMessage.warning('页面保存配置已删除，但环境变量中的企业微信配置仍在生效')
    } else {
      ElMessage.success('企业微信机器人配置已删除')
    }
  } catch (error) {
    botLastError.value = error.message || '删除企业微信机器人配置失败'
    ElMessage.error(botLastError.value)
  } finally {
    botDeleteLoading.value = false
  }
}

async function testBotMessage() {
  if (!botHasTargets.value) {
    ElMessage.error('请先把机器人拉进目标群聊或私聊机器人完成会话登记')
    return
  }
  botTestLoading.value = true
  try {
    const response = await fetch('/api/bot/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'markdown',
        content: `### 暗网情报系统\n> Bot 助手测试推送：${new Date().toLocaleString()}`,
      }),
    })
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    botLastError.value = ''
    ElMessage.success('Bot 测试推送已发送')
  } catch (error) {
    botLastError.value = error.message || 'Bot 测试推送失败'
    ElMessage.error(botLastError.value)
  } finally {
    botTestLoading.value = false
  }
}

async function loadDingTalkConfig() {
  dingtalkConfigLoading.value = true
  try {
    const response = await fetch('/api/dingtalk/status')
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    dingtalkConfig.value = await response.json()
    dingtalkLastError.value = ''
  } catch (error) {
    dingtalkLastError.value = error.message || '读取钉钉机器人配置失败'
    ElMessage.error(dingtalkLastError.value)
  } finally {
    dingtalkConfigLoading.value = false
  }
}

async function saveDingTalkConfig() {
  const webhookValue = String(dingtalkWebhookInput.value || '').trim()
  if (!webhookValue) {
    ElMessage.error('请输入钉钉自定义机器人 Webhook 或 access_token')
    return
  }
  dingtalkSaveLoading.value = true
  try {
    const response = await fetch('/api/dingtalk/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        webhook_url: webhookValue,
        secret: String(dingtalkSecretInput.value || '').trim(),
      }),
    })
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    dingtalkConfig.value = await response.json()
    dingtalkWebhookInput.value = ''
    dingtalkSecretInput.value = ''
    dingtalkLastError.value = ''
    ElMessage.success('钉钉机器人配置已保存')
  } catch (error) {
    dingtalkLastError.value = error.message || '保存钉钉机器人配置失败'
    ElMessage.error(dingtalkLastError.value)
  } finally {
    dingtalkSaveLoading.value = false
  }
}

async function deleteDingTalkConfig() {
  try {
    await ElMessageBox.confirm(
      '仅删除钉钉机器人保存配置，不会删除监测对象、企业画像或历史数据。',
      '删除钉钉配置',
      {
        type: 'warning',
        confirmButtonText: '确认删除',
        cancelButtonText: '取消',
      },
    )
  } catch {
    return
  }
  dingtalkDeleteLoading.value = true
  try {
    const response = await fetch('/api/dingtalk/config', { method: 'DELETE' })
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    dingtalkConfig.value = await response.json()
    dingtalkWebhookInput.value = ''
    dingtalkSecretInput.value = ''
    dingtalkLastError.value = ''
    if (dingtalkConfig.value.configured) {
      ElMessage.warning('页面保存配置已删除，但环境变量中的钉钉配置仍在生效')
    } else {
      ElMessage.success('钉钉机器人配置已删除')
    }
  } catch (error) {
    dingtalkLastError.value = error.message || '删除钉钉机器人配置失败'
    ElMessage.error(dingtalkLastError.value)
  } finally {
    dingtalkDeleteLoading.value = false
  }
}

async function testDingTalkMessage() {
  dingtalkTestLoading.value = true
  try {
    const response = await fetch('/api/dingtalk/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: '暗网情报系统测试推送',
        content: `### 暗网情报系统\n> 钉钉机器人测试推送：${new Date().toLocaleString()}`,
      }),
    })
    if (!response.ok) throw new Error(await readApiError(response, `请求失败: ${response.status}`))
    dingtalkLastError.value = ''
    ElMessage.success('钉钉测试推送已发送')
  } catch (error) {
    dingtalkLastError.value = error.message || '钉钉测试推送失败'
    ElMessage.error(dingtalkLastError.value)
  } finally {
    dingtalkTestLoading.value = false
  }
}

function addMonitoringKeyword() {
  monitoringKeywords.value = [
    ...monitoringKeywords.value,
    { id: `new-${Date.now()}`, keyword: '', category: 'custom_keywords', weight: 5, enabled: true, match_mode: 'contains' },
  ]
}

function removeMonitoringKeyword(id) {
  monitoringKeywords.value = monitoringKeywords.value.filter((item) => item.id !== id)
}

async function saveMonitoringKeywords() {
  keywordLoading.value = true
  try {
    const response = await fetch('/api/monitoring/keywords', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        keywords: monitoringKeywords.value.map((item) => ({
          keyword: item.keyword,
          category: item.category,
          weight: Number(item.weight || 0),
          enabled: Boolean(item.enabled),
          match_mode: item.match_mode || 'contains',
        })),
      }),
    })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    monitoringKeywords.value = await response.json()
    await loadMonitoringKeywords()
    await refreshIntelligence()
    ElMessage.success('监测规则已保存')
  } catch (error) {
    ElMessage.error(error.message || '保存监测规则失败')
  } finally {
    keywordLoading.value = false
  }
}

async function runSiteOnce(siteName) {
  setSiteRunning(siteName, true)
  try {
    const response = await fetch('/api/jobs/run-site', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ site_name: siteName, force: true }),
    })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    const payload = await response.json()
    await refreshJobs()
    if (payload.reason === 'auth_required') {
      ElMessage.warning(payload.message || '请先完成站点登录')
    } else {
      ElMessage.success(`已触发 ${siteName} 运行一次`)
    }
  } catch (error) {
    ElMessage.error(error.message || '触发站点运行失败')
  } finally {
    setSiteRunning(siteName, false)
  }
}

async function toggleSite(siteName, enabled) {
  setSiteToggling(siteName, true)
  try {
    const response = await fetch(`/api/sites/${encodeURIComponent(siteName)}/enabled`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    await refreshJobs()
    ElMessage.success(enabled ? `已启用 ${siteName}` : `已停用 ${siteName}`)
  } catch (error) {
    ElMessage.error(error.message || '更新站点状态失败')
  } finally {
    setSiteToggling(siteName, false)
  }
}

async function runAllSitesOnce() {
  runningAllSites.value = true
  try {
    const response = await fetch('/api/jobs/run-all-once', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ force: true }),
    })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    await refreshJobs()
    ElMessage.success('已触发全部站点运行')
  } catch (error) {
    ElMessage.error(error.message || '触发全部站点运行失败')
  } finally {
    runningAllSites.value = false
  }
}

async function startContinuousRun() {
  continuousLoading.value = true
  try {
    const response = await fetch('/api/jobs/run-all-continuous/start', { method: 'POST' })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    await refreshContinuous()
    ElMessage.success('已开启持续运行')
  } catch (error) {
    ElMessage.error(error.message || '开启持续运行失败')
  } finally {
    continuousLoading.value = false
  }
}

async function stopContinuousRun() {
  continuousLoading.value = true
  try {
    const response = await fetch('/api/jobs/run-all-continuous/stop', { method: 'POST' })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    await refreshContinuous()
    ElMessage.success('已停止持续运行')
  } catch (error) {
    ElMessage.error(error.message || '停止持续运行失败')
  } finally {
    continuousLoading.value = false
  }
}

async function runVulnerabilitySyncOnce() {
  vulnerabilityRunLoading.value = true
  try {
    const response = await fetch('/api/vulnerabilities/sync/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ limit: 300 }),
    })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    await refreshJobs()
    ElMessage.success('已触发漏洞同步')
  } catch (error) {
    ElMessage.error(error.message || '触发漏洞同步失败')
  } finally {
    vulnerabilityRunLoading.value = false
  }
}

async function startVulnerabilitySync() {
  vulnerabilityContinuousLoading.value = true
  try {
    const response = await fetch('/api/vulnerabilities/sync/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        interval_seconds: Number(vulnerabilityIntervalHours.value || 1) * 3600,
        limit: 300,
      }),
    })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    await refreshJobs()
    ElMessage.success('已开启漏洞自动同步')
  } catch (error) {
    ElMessage.error(error.message || '开启漏洞自动同步失败')
  } finally {
    vulnerabilityContinuousLoading.value = false
  }
}

async function stopVulnerabilitySync() {
  vulnerabilityContinuousLoading.value = true
  try {
    const response = await fetch('/api/vulnerabilities/sync/stop', { method: 'POST' })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    await refreshJobs()
    ElMessage.success('已停止漏洞自动同步')
  } catch (error) {
    ElMessage.error(error.message || '停止漏洞自动同步失败')
  } finally {
    vulnerabilityContinuousLoading.value = false
  }
}

async function saveRansomwareConfig() {
  const apiKey = String(ransomwareApiKey.value || '').trim()
  if (!apiKey) {
    ElMessage.error('请输入 ransomware.live API Key')
    return
  }

  ransomwareSaveLoading.value = true
  try {
    const response = await fetch('/api/ransomware/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: apiKey }),
    })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    ransomwareConfig.value = await response.json()
    ransomwareApiKey.value = ''
    ElMessage.success('已保存 ransomware.live API Key')
  } catch (error) {
    ElMessage.error(error.message || '保存 ransomware.live API Key 失败')
  } finally {
    ransomwareSaveLoading.value = false
  }
}

async function runRansomwareSyncOnce() {
  ransomwareRunLoading.value = true
  try {
    const response = await fetch('/api/ransomware/sync/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ limit: 0 }),
    })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    await refreshJobs()
    await refreshIntelligence()
    ElMessage.success('已触发 ransomware.live 同步')
  } catch (error) {
    ElMessage.error(error.message || '触发 ransomware.live 同步失败')
  } finally {
    ransomwareRunLoading.value = false
  }
}

async function startRansomwareSync() {
  ransomwareContinuousLoading.value = true
  try {
    const response = await fetch('/api/ransomware/sync/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        interval_seconds: Number(ransomwareIntervalHours.value || 1) * 3600,
        limit: 0,
      }),
    })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    await refreshJobs()
    ElMessage.success('已开启 ransomware.live 自动同步')
  } catch (error) {
    ElMessage.error(error.message || '开启 ransomware.live 自动同步失败')
  } finally {
    ransomwareContinuousLoading.value = false
  }
}

async function stopRansomwareSync() {
  ransomwareContinuousLoading.value = true
  try {
    const response = await fetch('/api/ransomware/sync/stop', { method: 'POST' })
    if (!response.ok) throw new Error(`请求失败: ${response.status}`)
    await refreshJobs()
    ElMessage.success('已停止 ransomware.live 自动同步')
  } catch (error) {
    ElMessage.error(error.message || '停止 ransomware.live 自动同步失败')
  } finally {
    ransomwareContinuousLoading.value = false
  }
}

function updateViewportWidth() {
  viewportWidth.value = window.innerWidth
}

onMounted(async () => {
  updateViewportWidth()
  window.addEventListener('resize', updateViewportWidth)
  await refreshAllPanels()
  const storedIntervalSeconds = Number(ransomwareSync.value.interval_seconds || 0)
  if (storedIntervalSeconds > 0) ransomwareIntervalHours.value = storedIntervalSeconds / 3600
  jobsPollTimer = window.setInterval(() => refreshJobs(), 30000)
})

onBeforeUnmount(() => {
  clearTorBridgePoll()
  if (jobsPollTimer) window.clearInterval(jobsPollTimer)
  window.removeEventListener('resize', updateViewportWidth)
})
</script>

<style scoped lang="scss">
.collector-control-page {
  min-width: 0;
  overflow-x: hidden;
}

.control-hero {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(320px, 1fr);
  gap: 24px;
  align-items: start;
}

.control-hero__copy h3 {
  margin: 10px 0 0;
  color: var(--ti-text-primary);
  font-size: 34px;
}

.control-hero__copy p {
  margin: 12px 0 0;
  color: var(--ti-text-secondary);
  line-height: 1.7;
}

.control-hero__stats,
.status-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
}

.metric-card {
  min-width: 0;
  padding: 16px 18px;
  border: 1px solid rgba(148, 163, 184, 0.18);
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.92);
}

.metric-card span {
  display: block;
  color: var(--ti-text-muted);
  font-size: 12px;
}

.metric-card strong {
  display: block;
  margin-top: 8px;
  color: var(--ti-text-primary);
  font-size: clamp(20px, 2vw, 28px);
  line-height: 1.25;
  word-break: break-word;
  overflow-wrap: anywhere;
}

.metric-card__value--small {
  font-size: clamp(16px, 1.35vw, 22px);
}

.metric-card__value--path {
  font-size: clamp(14px, 1.05vw, 18px);
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
}

.metric-card__value--break {
  word-break: break-all;
}

.status-grid--compact {
  margin-bottom: 16px;
}

.bot-provider-title {
  margin: 0 0 14px;
  color: var(--ti-text-primary);
  font-size: 16px;
}

.bot-provider-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.bot-provider-heading .bot-provider-title {
  margin-bottom: 14px;
}

.bot-provider-divider {
  height: 1px;
  margin: 22px 0;
  background: rgba(148, 163, 184, 0.24);
}

.credential-row {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 12px;
}

.credential-row__input {
  flex: 1 1 360px;
  min-width: 220px;
}

.cookie-collapse {
  border: none;
}

.cookie-collapse :deep(.el-collapse-item__header) {
  padding: 4px;
  background: transparent;
}

.cookie-panel-title {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  width: 100%;
}

.cookie-panel-title strong {
  color: var(--ti-text-primary);
  font-size: 15px;
}

.cookie-panel-meta {
  margin-left: auto;
  color: var(--ti-text-muted);
  font-size: 12px;
}

.cookie-panel-body {
  padding: 12px 4px 4px;
}

.tor-bridge-panel {
  display: grid;
  gap: 0;
  min-width: 0;
  padding: 30px;
  overflow: hidden;
}

.tor-bridge-panel__header {
  display: flex;
  justify-content: space-between;
  gap: 24px;
  align-items: flex-start;
  min-width: 0;
  padding-bottom: 22px;
  border-bottom: 1px solid var(--ti-border-soft);
}

.tor-bridge-panel__header h3 {
  margin: 0;
  color: var(--ti-text-primary);
  font-size: 30px;
  line-height: 1.18;
}

.tor-bridge-panel__header p {
  max-width: 880px;
  margin: 10px 0 0;
  color: var(--ti-text-secondary);
  line-height: 1.7;
}

.tor-bridge-panel__header .health-actions {
  flex: 0 0 auto;
  justify-content: flex-end;
}

.tor-bridge-body {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(240px, 280px);
  gap: 28px;
  min-width: 0;
  padding-top: 24px;
  align-items: start;
}

.tor-bridge-primary {
  display: grid;
  gap: 24px;
  min-width: 0;
}

.tor-bridge-toggle {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--ti-text-primary);
  min-height: 32px;
}

.tor-bridge-current {
  width: 100%;
  min-width: 0;
  border-radius: 8px;
  background: #f4f6fb;
  padding: 24px 28px;
}

.tor-bridge-current__head {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: center;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(148, 163, 184, 0.28);
  color: var(--ti-text-primary);
  min-width: 0;
}

.tor-bridge-current__head > div {
  display: flex;
  align-items: center;
  gap: 8px;
}

.tor-bridge-current__menu {
  width: 32px;
  height: 32px;
  padding: 0;
  color: var(--ti-text-primary);
  font-weight: 700;
  background: rgba(255, 255, 255, 0.84);
}

.tor-bridge-current__body {
  padding-top: 16px;
}

.tor-bridge-current__body strong {
  color: var(--ti-text-primary);
  font-size: 18px;
}

.tor-bridge-current__body p {
  margin: 12px 0 0;
  color: var(--ti-text-primary);
  line-height: 1.7;
}

.tor-bridge-change {
  display: grid;
  gap: 12px;
  min-width: 0;
}

.tor-bridge-change h4 {
  margin: 0;
  color: var(--ti-text-primary);
  font-size: 22px;
}

.tor-bridge-change__row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 18px;
  align-items: center;
  min-width: 0;
  padding: 14px 0;
  border-top: 1px solid var(--ti-border-soft);
}

.tor-bridge-change__row span {
  color: var(--ti-text-primary);
  font-weight: 600;
}

.tor-bridge-change__row p {
  margin: 4px 0 0;
  color: var(--ti-text-muted);
  font-size: 12px;
}

.tor-bridge-change__row .el-button {
  width: 178px;
  justify-self: end;
}

.tor-bridge-runtime {
  display: grid;
  gap: 14px;
  min-width: 0;
  padding: 18px;
  border: 1px solid var(--ti-border-soft);
  border-radius: 12px;
  background: rgba(248, 250, 253, 0.86);
}

.tor-bridge-runtime__item {
  min-width: 0;
}

.tor-bridge-runtime__item span {
  display: block;
  color: var(--ti-text-secondary);
  font-size: 12px;
}

.tor-bridge-runtime__item strong {
  display: block;
  margin-top: 4px;
  color: var(--ti-text-primary);
  font-size: 14px;
  line-height: 1.45;
  word-break: break-word;
  overflow-wrap: anywhere;
}

.tor-bridge-runtime__connected {
  color: var(--el-color-success) !important;
}

.tor-bridge-runtime__ip {
  font-variant-numeric: tabular-nums;
}

.tor-bridge-runtime__progress {
  grid-column: 1 / -1;
}

.tor-bridge-runtime__progress-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 8px;
}

.tor-bridge-runtime__progress-head strong {
  margin-top: 0;
  font-variant-numeric: tabular-nums;
}

.tor-bridge-runtime__progress p {
  margin: 8px 0 0;
  color: var(--ti-text-secondary);
  font-size: 12px;
  line-height: 1.45;
}

.builtin-bridge-dialog__intro {
  margin: 0 0 14px;
  color: var(--ti-text-primary);
  line-height: 1.7;
}

.builtin-bridge-list {
  display: grid;
  gap: 14px;
}

.builtin-bridge-option {
  width: 100%;
  height: auto;
  margin-right: 0;
  align-items: flex-start;
  white-space: normal;
}

.builtin-bridge-option__title {
  display: flex;
  gap: 10px;
  align-items: center;
}

.builtin-bridge-option__title strong {
  color: var(--ti-text-primary);
  font-size: 17px;
}

.builtin-bridge-option__title span {
  color: #1677ff;
  font-size: 13px;
}

.builtin-bridge-option p {
  margin: 8px 0 0;
  color: var(--ti-text-primary);
  line-height: 1.7;
}

.panel-note-block {
  display: grid;
  gap: 6px;
}

.panel-note {
  margin: 0;
  color: var(--ti-text-secondary);
  line-height: 1.7;
  word-break: break-word;
  overflow-wrap: anywhere;
}

.panel-note--mono {
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  font-size: 13px;
}

.panel-note--danger {
  color: #b91c1c;
}

.health-actions,
.row-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  align-items: center;
}

.site-health-table-shell {
  overflow-x: hidden;
}

.site-health-table-shell :deep(.el-table .cell) {
  overflow: hidden;
  padding: 0 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.site-health-table-shell :deep(.el-table__header-wrapper th.el-table__cell) {
  padding-top: 10px;
  padding-bottom: 10px;
}

.site-health-actions {
  gap: 6px;
  justify-content: flex-start;
}

.site-health-actions :deep(.el-button) {
  min-width: 74px;
  height: 28px;
  margin-left: 0 !important;
  padding: 0 9px;
}

.alert-stream {
  display: grid;
  gap: 12px;
}

.alert-stream__item {
  padding: 16px 18px;
  border-radius: 16px;
  border: 1px solid rgba(148, 163, 184, 0.18);
  background: rgba(255, 255, 255, 0.92);
}

.alert-stream__meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.alert-stream__item h3 {
  margin: 10px 0 0;
  color: var(--ti-text-primary);
}

.alert-stream__item p,
.alert-stream__source {
  margin: 10px 0 0;
  color: var(--ti-text-secondary);
  line-height: 1.7;
  word-break: break-word;
  overflow-wrap: anywhere;
}

@media (max-width: 1440px) {
  .control-hero,
  .control-hero__stats,
  .status-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 1200px) {
  .tor-bridge-panel__header,
  .tor-bridge-body {
    grid-template-columns: 1fr;
  }

  .tor-bridge-panel__header {
    display: grid;
  }

  .tor-bridge-panel__header .health-actions {
    justify-content: flex-start;
  }

  .tor-bridge-runtime {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 900px) {
  .control-hero {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 767px) {
  .control-hero__stats,
  .status-grid {
    grid-template-columns: 1fr;
  }

  .tor-bridge-panel {
    padding: 22px;
  }

  .tor-bridge-runtime,
  .tor-bridge-change__row {
    grid-template-columns: 1fr;
  }

  .tor-bridge-change__row .el-button {
    width: 100%;
    justify-self: stretch;
  }
}
</style>
