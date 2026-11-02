<template>
  <div class="collector-dashboard">
    <header class="collector-dashboard-head">
      <div>
        <h1>{{ historyMode ? '任务历史' : '采集总览' }}</h1>
        <p v-if="historyMode">按实际任务记录查看执行结果与失败原因</p>
        <p v-else>全部站点 {{ number(data?.scope?.total_sites) }} <span>·</span> 已启用 {{ number(data?.scope?.enabled_sites) }}</p>
      </div>
      <div class="collector-dashboard-controls">
        <label><span class="sr-only">统计时间范围</span><select v-model.number="hours" class="select"><option :value="1">近1小时</option><option :value="24">近24小时</option><option :value="168">近7天</option></select></label>
        <button class="btn btn-secondary" :disabled="loading" @click="refresh()">{{ loading ? '刷新中…' : '刷新' }}</button>
        <span class="collector-updated" aria-live="polite">{{ data?.updated_at ? '更新于 ' + time(data.updated_at) : '等待首次加载' }}</span>
      </div>
    </header>
    <nav class="collector-page-links" aria-label="采集页面">
      <RouterLink to="/collector-control/overview" :class="{ active: !historyMode }" :aria-current="!historyMode ? 'page' : undefined">总览</RouterLink>
      <RouterLink to="/collector-control/sites">站点状态</RouterLink>
      <RouterLink to="/collector-control/tasks" :class="{ active: historyMode }" :aria-current="historyMode ? 'page' : undefined">任务历史</RouterLink>
    </nav>
    <div v-if="error" class="collector-load-error" role="alert">{{ error }}<span v-if="data">，当前保留上次成功加载的数据。</span></div>

    <section v-if="!historyMode" class="collector-trend-panel" aria-label="全站采集趋势" :aria-busy="loading">
      <div class="collector-summary">
        <div><span>新增可见情报</span><strong class="collector-green">{{ number(data?.summary?.visible_new) }}</strong><small v-if="data?.coverage?.visible_complete === false" class="collector-incomplete">所选时段记录不完整</small></div>
        <div><span>待处理新帖</span><strong>{{ number(data?.summary?.pending_recent) }}</strong></div>
        <div><span>执行槽位</span><strong>{{ number(data?.summary?.running_jobs) }} <small>/</small> {{ number(data?.summary?.available_slots) }}</strong></div>
        <button type="button" class="collector-attention-metric" @click="showAttention"><span>需关注站点</span><strong>{{ number(data?.summary?.attention_sites) }}</strong></button>
      </div>
      <div class="collector-trend-heading">
        <div class="collector-chart-tabs" role="tablist" aria-label="趋势指标">
          <button v-for="item in chartTabs" :id="'collector-tab-' + item.key" :key="item.key" type="button" role="tab" :aria-selected="chartMode === item.key" aria-controls="collector-trend-chart" :class="{ active: chartMode === item.key }" @click="chartMode = item.key">{{ item.label }}</button>
        </div>
        <span class="collector-chart-help">点击图例可单独查看</span>
      </div>
      <div class="collector-chart-container">
        <div id="collector-trend-chart" ref="chartElement" class="collector-chart" role="tabpanel" :aria-labelledby="'collector-tab-' + chartMode" :aria-label="chartDescription"></div>
        <div v-if="!hasChartData" class="collector-chart-empty" role="status">{{ loading && !data ? '正在加载采集趋势…' : chartMode === 'backlog' ? '尚无积压快照' : '所选时段暂无统计数据' }}</div>
      </div>
      <p class="collector-chart-caption">{{ chartCaption }}<span v-if="coverageNote" class="collector-coverage-note">{{ coverageNote }}</span></p>
    </section>

    <section class="collector-record-panel" :aria-label="historyMode ? '任务记录' : '站点摘要'">
      <header class="collector-record-toolbar">
        <h2>{{ historyMode ? '任务记录' : '站点摘要' }}</h2>
        <div class="collector-record-filters">
          <label class="collector-search"><span class="sr-only">{{ historyMode ? '搜索任务ID、站点或目标' : '搜索站点' }}</span><input v-model="searchInput" class="input" type="search" :placeholder="historyMode ? '搜索任务ID、站点或目标' : '搜索站点'"></label>
          <template v-if="historyMode">
            <label><span class="sr-only">按站点筛选任务</span><select v-model="site" class="select"><option value="">全部站点</option><option v-for="item in siteOptions" :key="item.site_name" :value="item.site_name">{{ item.display_name || item.site_name }}</option></select></label>
            <label><span class="sr-only">按任务状态筛选</span><select v-model="taskState" class="select"><option value="">全部状态</option><option v-for="(label, value) in taskStates" :key="value" :value="value">{{ label }}</option></select></label>
          </template>
          <template v-else>
            <label><span class="sr-only">按站点状态筛选</span><select v-model="state" class="select"><option value="all">全部状态</option><option value="running">执行中</option><option value="waiting">等待中</option><option value="attention">需要关注</option><option value="disabled">已停用</option></select></label>
            <label class="collector-attention-toggle"><input v-model="attentionFirst" type="checkbox"><span>异常优先</span></label>
          </template>
        </div>
      </header>
      <div class="collector-table-scroll" :aria-busy="loading">
        <table v-if="!historyMode" class="collector-data-table">
          <thead><tr><th scope="col">站点</th><th scope="col">当前状态</th><th scope="col">{{ rangeLabel }}新增情报</th><th scope="col">待处理新帖</th><th scope="col">最近成功</th><th scope="col"><span class="sr-only">站点详情</span></th></tr></thead>
          <tbody>
            <template v-for="item in rows" :key="item.site_name">
              <tr :class="{ 'collector-selected-row': expanded === item.site_name }">
                <th scope="row">{{ item.display_name || item.site_name }}</th>
                <td><span class="collector-status" :class="tone(item.state)">{{ item.state || '状态未知' }}</span></td>
                <td class="collector-num">{{ number(item.new_visible) }}</td><td class="collector-num">{{ number(item.pending_recent) }}</td>
                <td class="collector-date">{{ time(item.last_success_at, true) }}</td>
                <td class="collector-row-action"><button type="button" :aria-expanded="expanded === item.site_name" :aria-label="(expanded === item.site_name ? '收起' : '展开') + (item.display_name || item.site_name) + '详情'" @click="toggleDetails(item.site_name)">{{ expanded === item.site_name ? '⌄' : '›' }}</button></td>
              </tr>
              <tr v-if="expanded === item.site_name" class="collector-detail-row"><td colspan="6">
                <div class="collector-site-detail">
                  <dl><div><dt>启用状态</dt><dd>{{ item.enabled ? '已启用' : '已停用' }}</dd></div><div><dt>历史回补待处理</dt><dd>{{ number(item.pending_backfill) }}</dd></div><div><dt>下次列表调度</dt><dd>{{ time(item.next_run_at, true) }}</dd></div><div v-if="item.detail_retry_at"><dt>详情重试时间</dt><dd>{{ time(item.detail_retry_at, true) }}</dd></div></dl>
                  <p v-if="item.last_error" class="collector-error-text">{{ item.last_error }}</p>
                  <div class="collector-detail-links"><RouterLink :to="{ path: '/collector-control/tasks', query: { site: item.site_name } }">查看该站任务历史</RouterLink><RouterLink to="/collector-control/sites">打开站点管理</RouterLink></div>
                </div>
              </td></tr>
            </template>
            <tr v-if="!rows.length"><td colspan="6" class="collector-empty-row">{{ loading && !data ? '正在加载站点…' : '没有符合条件的站点' }}</td></tr>
          </tbody>
        </table>
        <table v-else class="collector-data-table collector-task-table">
          <thead><tr><th scope="col">时间</th><th scope="col">站点</th><th scope="col">任务类型</th><th scope="col">状态</th><th scope="col">执行耗时</th><th scope="col">处理结果</th><th scope="col"><span class="sr-only">任务详情</span></th></tr></thead>
          <tbody>
            <template v-for="item in rows" :key="item.job_id">
              <tr :class="{ 'collector-selected-row': expanded === item.job_id }">
                <td class="collector-date">{{ time(item.finished_at || item.started_at || item.enqueued_at, true) }}</td>
                <th scope="row">{{ item.display_name || item.site_name }}</th><td>{{ taskType(item.job_type) }}</td>
                <td><span class="collector-status" :class="tone(item.status)">{{ taskStates[item.status] || item.status || '未知' }}</span></td>
                <td class="collector-num">{{ duration(item.duration_ms) }}</td><td class="collector-result"><span :title="resultText(item)">{{ resultText(item) }}</span></td>
                <td class="collector-row-action"><button type="button" :aria-expanded="expanded === item.job_id" :aria-label="(expanded === item.job_id ? '收起' : '展开') + '任务详情'" @click="toggleDetails(item.job_id)">{{ expanded === item.job_id ? '⌄' : '›' }}</button></td>
              </tr>
              <tr v-if="expanded === item.job_id" class="collector-detail-row"><td colspan="7">
                <div class="collector-task-detail">
                  <dl><div><dt>任务ID</dt><dd>{{ item.job_id }}</dd></div><div><dt>入队时间</dt><dd>{{ time(item.enqueued_at, true) }}</dd></div><div><dt>开始时间</dt><dd>{{ time(item.started_at, true) }}</dd></div><div><dt>结束时间</dt><dd>{{ time(item.finished_at, true) }}</dd></div></dl>
                  <p v-if="item.error_message" class="collector-error-text">{{ item.error_message }}</p>
                  <p v-if="item.target" class="collector-target"><span>目标：</span><a v-if="safeTarget(item.target)" :href="safeTarget(item.target)" target="_blank" rel="noopener noreferrer">{{ item.target }}</a><span v-else>{{ item.target }}</span></p>
                </div>
              </td></tr>
            </template>
            <tr v-if="!rows.length"><td colspan="7" class="collector-empty-row">{{ loading && !data ? '正在加载任务…' : '所选时段没有符合条件的任务' }}</td></tr>
          </tbody>
        </table>
      </div>
      <footer class="collector-pagination">
        <span>{{ total ? '第 ' + firstRow + '–' + lastRow + ' 条，共 ' + number(total) + (historyMode ? ' 条任务' : ' 个站点') : historyMode ? '0 条任务' : '0 个站点' }}</span>
        <div class="collector-pagination-controls">
          <button type="button" class="btn btn-secondary" :disabled="loading || page <= 1" aria-label="上一页" @click="page--">‹</button>
          <label class="collector-page-number"><span class="sr-only">页码</span><input :value="page" type="number" min="1" :max="pageCount" @change="jumpPage"></label><span>/ {{ pageCount }} 页</span>
          <button type="button" class="btn btn-secondary" :disabled="loading || page >= pageCount" aria-label="下一页" @click="page++">›</button>
          <label><span class="sr-only">每页条数</span><select v-model.number="pageSize" class="select"><option :value="10">10条/页</option><option :value="20">20条/页</option><option :value="50">50条/页</option></select></label>
        </div>
      </footer>
    </section>
  </div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import * as echarts from 'echarts/core'
import { BarChart, LineChart } from 'echarts/charts'
import { AriaComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([BarChart, LineChart, AriaComponent, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer])
const route = useRoute()
const historyMode = computed(() => route.name === 'CollectorTasks')
const data = ref(null)
const loading = ref(false)
const error = ref('')
const hours = ref(24)
const page = ref(1)
const pageSize = ref(10)
const searchInput = ref('')
const query = ref('')
const state = ref('all')
const attentionFirst = ref(false)
const site = ref(typeof route.query.site === 'string' ? route.query.site : '')
const taskState = ref('')
const expanded = ref('')
const chartMode = ref('production')
const chartElement = ref(null)
const chartTabs = [{ key: 'production', label: '产出趋势' }, { key: 'throughput', label: '任务吞吐' }, { key: 'backlog', label: '积压变化' }]
const taskStates = { running: '执行中', enqueued: '等待执行', succeeded: '成功', partial: '部分完成', failed: '失败', skipped: '跳过', stale: '待恢复' }
const colors = { blue: '#1681f9', green: '#06a366', orange: '#e49620', red: '#f26d72' }
let chart = null
let resizeObserver = null
let requestController = null
let requestVersion = 0
let pollTimer = null
let searchTimer = null
let mounted = false
let previousBodyClass = ''
const legendSelections = {}
const rows = computed(() => historyMode.value ? data.value?.items || [] : data.value?.sites?.items || [])
const total = computed(() => Number(historyMode.value ? data.value?.total || 0 : data.value?.sites?.total || 0))
const pageCount = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))
const firstRow = computed(() => (page.value - 1) * pageSize.value + 1)
const lastRow = computed(() => Math.min(total.value, firstRow.value + rows.value.length - 1))
const rangeLabel = computed(() => ({ 1: '1h', 24: '24h', 168: '7天' }[hours.value]))
const siteOptions = computed(() => {
  const options = Array.isArray(data.value?.sites) ? [...data.value.sites] : []
  if (site.value && !options.some((item) => item.site_name === site.value)) options.unshift({ site_name: site.value, display_name: site.value })
  return options
})
const seriesRows = computed(() => Array.isArray(data.value?.series) ? data.value.series : [])
const chartMetrics = computed(() => chartMode.value === 'production'
  ? [{ key: 'raw_new', name: '新增正文', color: colors.blue }, { key: 'visible_new', name: '新增可见情报', color: colors.green }]
  : chartMode.value === 'throughput'
    ? [{ key: 'success', name: '成功', color: colors.blue }, { key: 'failed', name: '失败', color: colors.red }, { key: 'partial', name: '部分完成', color: colors.orange }]
    : [{ key: 'pending_recent', name: '新帖', color: colors.blue }, { key: 'pending_backfill', name: '历史回补', color: colors.orange }])
const finite = (value) => typeof value === 'number' && Number.isFinite(value)
const hasChartData = computed(() => chartMetrics.value.some((metric) => seriesRows.value.some((item) => finite(item[metric.key]))))
const intervalLabel = computed(() => {
  const seconds = Number(data.value?.interval_seconds || 3600)
  return seconds < 3600 ? Math.round(seconds / 60) + '分钟' : (seconds / 3600 === 1 ? '' : seconds / 3600) + '小时'
})
const chartDescription = computed(() => (chartTabs.find((item) => item.key === chartMode.value)?.label || '') + '，' + (chartMode.value === 'backlog' ? '按采样时点查看待处理条目' : '每' + intervalLabel.value + '统计'))
const chartCaption = computed(() => ({
  production: '按每' + intervalLabel.value + '统计新增正文与首次可见情报，已有内容更新不会重复计为新增。',
  throughput: '按每' + intervalLabel.value + '结束的任务统计；重试、等待与跳过单独保留，不计入成功量。',
  backlog: '按时段最后一次采样展示；上涨表示积压增加，下降表示正在消化，未采样时段留空。',
}[chartMode.value]))
const coverageNote = computed(() => {
  if (!data.value || chartMode.value === 'throughput') return ''
  const coverage = data.value.coverage || {}
  if (chartMode.value === 'backlog') return coverage.backlog_since ? '积压快照自 ' + time(coverage.backlog_since, true) + ' 开始记录。' : '积压快照尚未开始记录。'
  const incomplete = []
  if (coverage.raw_complete === false) incomplete.push(coverage.raw_since ? '正文自 ' + time(coverage.raw_since, true) + ' 开始记录' : '正文尚无历史统计')
  if (coverage.visible_complete === false || !coverage.visible_since) incomplete.push(coverage.visible_since ? '可见情报自 ' + time(coverage.visible_since, true) + ' 开始记录' : '可见情报尚无历史统计')
  return incomplete.length ? incomplete.join('；') + '，所选时段历史不完整。' : '可见情报统计自 ' + time(coverage.visible_since, true) + ' 开始。'
})
const requestUrl = computed(() => {
  const params = new URLSearchParams({ hours: String(hours.value), page: String(page.value), page_size: String(pageSize.value), q: query.value })
  if (historyMode.value) { params.set('site', site.value); params.set('status', taskState.value) }
  else { params.set('state', state.value); params.set('attention_first', String(attentionFirst.value)) }
  return '/api/collector/' + (historyMode.value ? 'tasks' : 'overview') + '?' + params
})

function number(value) { return finite(value) ? value.toLocaleString('zh-CN') : '—' }
function time(value, withDate = false) {
  if (!value) return '—'
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '—'
  return new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', ...(withDate ? { month: '2-digit', day: '2-digit' } : {}), hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(date)
}
function tone(value) {
  if (['running', '运行中', '执行中'].includes(value)) return 'is-running'
  if (['succeeded', '成功', '正常'].includes(value)) return 'is-success'
  if (['failed', '异常', '失败', '解析异常', '页面识别异常', '源站关闭', '会话失效'].includes(value)) return 'is-error'
  if (['partial', 'stale', '资源等待', '需要验证', '退避中', '入口迁移', '待登录', '熔断中', '恢复中', '待恢复', '证据待补'].includes(value)) return 'is-warning'
  return 'is-neutral'
}
function duration(value) { return !finite(value) ? '—' : value < 1000 ? '<1秒' : value < 60000 ? Math.round(value / 1000) + '秒' : (value / 60000).toFixed(1) + '分钟' }
function taskType(value) { return { seed: '列表检查', detail: '正文采集', ransomware_sync: '外部情报同步' }[value] || value || '采集任务' }
function resultText(item) {
  if (item.error_message) return item.error_message
  const result = item.result || {}
  const parts = []
  if (result.new_count) parts.push('新增正文 ' + result.new_count)
  if (result.updated_count) parts.push('更新正文 ' + result.updated_count)
  if (result.unchanged_count) parts.push('正文无变化 ' + result.unchanged_count)
  return parts.join(' · ') || (item.status === 'succeeded' ? taskType(item.job_type) + '完成' : taskStates[item.status] || '—')
}
function safeTarget(value) {
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url.href : '' } catch { return '' }
}
function toggleDetails(id) { expanded.value = expanded.value === id ? '' : id }
function jumpPage(event) {
  const target = Number(event.target.value)
  page.value = Math.min(pageCount.value, Math.max(1, Number.isFinite(target) ? Math.floor(target) : 1))
  event.target.value = page.value
}
function showAttention() { state.value = 'attention'; page.value = 1 }

async function refresh(replace = true) {
  if (!mounted || document.visibilityState === 'hidden' || (loading.value && !replace)) return
  requestController?.abort()
  const controller = new AbortController()
  requestController = controller
  const version = ++requestVersion
  loading.value = true
  error.value = ''
  let timedOut = false
  const timeout = window.setTimeout(() => { timedOut = true; controller.abort() }, 20000)
  try {
    // main.js installs the shared authenticated fetch and expired-session handler.
    const response = await window.fetch(requestUrl.value, { signal: controller.signal })
    if (!response.ok) throw new Error(response.status === 401 ? '登录已过期，请重新登录' : response.status === 403 ? '没有查看采集数据的权限' : '采集数据加载失败（' + response.status + '）')
    const payload = await response.json()
    if (version !== requestVersion || !mounted) return
    data.value = payload
    const responsePage = Number(historyMode.value ? payload.page : payload.sites?.page)
    if (responsePage && responsePage !== page.value) page.value = responsePage
  } catch (requestError) {
    if (version !== requestVersion || !mounted) return
    if (timedOut) error.value = '采集数据加载超时，请稍后刷新'
    else if (!controller.signal.aborted) error.value = requestError.message || '采集数据加载失败'
  } finally {
    window.clearTimeout(timeout)
    if (version === requestVersion) { loading.value = false; requestController = null }
  }
}
function renderChart() {
  if (!chart || historyMode.value) return
  const stacked = chartMode.value === 'throughput'
  chart.setOption({
    animation: false, aria: { enabled: true, description: chartDescription.value },
    textStyle: { fontFamily: 'inherit', color: '#64748b' },
    grid: { top: 60, left: 60, right: 25, bottom: 35 },
    legend: { top: 10, right: 18, itemWidth: 15, itemHeight: 8, textStyle: { color: '#52647d', fontSize: 12 }, selected: legendSelections[chartMode.value] || {} },
    tooltip: {
      trigger: 'axis', renderMode: 'richText', confine: true,
      formatter: (items) => {
        const entries = Array.isArray(items) ? items : [items]
        const point = seriesRows.value[entries[0]?.dataIndex]
        const lines = [time(point?.at, true)]
        if (chartMode.value === 'backlog' && point?.backlog_at) lines.push('采样时间 ' + time(point.backlog_at, true))
        return [...lines, ...entries.map((item) => item.seriesName + '：' + number(item.value))].join('\n')
      },
    },
    xAxis: { type: 'category', data: seriesRows.value.map((item) => time(item.at, hours.value === 168)), boundaryGap: stacked, axisLine: { lineStyle: { color: '#cedae8' } }, axisTick: { show: false }, axisLabel: { hideOverlap: true, color: '#52647d', fontSize: 11 } },
    yAxis: { type: 'value', min: 0, minInterval: 1, name: chartMode.value === 'backlog' ? '待处理条目 / 条' : (stacked ? '任务' : '条') + ' / ' + intervalLabel.value, nameTextStyle: { align: 'left', padding: [0, 0, 0, -42], color: '#63748b' }, axisLabel: { color: '#63748b', fontSize: 11 }, splitLine: { lineStyle: { color: '#e8eff6' } } },
    series: chartMetrics.value.map((metric) => ({
      name: metric.name, type: stacked ? 'bar' : 'line', stack: stacked ? 'completed' : undefined, barMaxWidth: 24,
      data: seriesRows.value.map((item) => finite(item[metric.key]) ? item[metric.key] : null),
      connectNulls: false, showSymbol: seriesRows.value.length <= 48, symbolSize: 5, lineStyle: { width: 2 },
      itemStyle: { color: metric.color }, emphasis: { focus: 'series' },
    })),
  }, { notMerge: true })
}
function visibilityChanged() {
  if (document.visibilityState === 'hidden') { ++requestVersion; requestController?.abort(); requestController = null; loading.value = false }
  else refresh()
}
watch(searchInput, (value) => {
  window.clearTimeout(searchTimer)
  searchTimer = window.setTimeout(() => { query.value = value.trim() }, 300)
})
watch(() => route.query.site, (value) => { site.value = typeof value === 'string' ? value : '' })
watch([hours, pageSize, query, state, attentionFirst, site, taskState], () => { page.value = 1 }, { flush: 'sync' })
watch(requestUrl, () => { expanded.value = ''; refresh() }, { flush: 'post' })
watch([chartMode, seriesRows], () => nextTick(renderChart), { flush: 'post' })
onMounted(async () => {
  mounted = true
  previousBodyClass = document.body.className
  document.body.className = 'page-collector-dashboard'
  document.title = (historyMode.value ? '任务历史' : '采集总览') + ' · 玄鉴'
  if (chartElement.value) {
    chart = echarts.init(chartElement.value)
    chart.on('legendselectchanged', (event) => { legendSelections[chartMode.value] = event.selected })
    resizeObserver = new ResizeObserver(() => chart?.resize())
    resizeObserver.observe(chartElement.value)
    renderChart()
  }
  document.addEventListener('visibilitychange', visibilityChanged)
  pollTimer = window.setInterval(() => refresh(false), 30000)
  await refresh()
})
onBeforeUnmount(() => {
  mounted = false
  if (document.body.className === 'page-collector-dashboard') document.body.className = previousBodyClass
  ++requestVersion
  requestController?.abort()
  window.clearInterval(pollTimer)
  window.clearTimeout(searchTimer)
  document.removeEventListener('visibilitychange', visibilityChanged)
  resizeObserver?.disconnect()
  chart?.dispose()
  chart = null
})
</script>

<style scoped>
.collector-dashboard { color: #142235; min-width: 0; }
.collector-dashboard-head { display: flex; align-items: center; justify-content: space-between; gap: 18px; margin-bottom: 6px; }
.collector-dashboard-head h1 { margin: 0; font-size: clamp(25px, 2.1vw, 34px); line-height: 1.3; letter-spacing: -.6px; }
.collector-dashboard-head p { margin: 4px 0 0; color: #53667f; font-size: 13px; }
.collector-dashboard-head p span { padding: 0 5px; }
.collector-dashboard-controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }
.collector-dashboard-controls .select { min-width: 112px; }
.collector-updated { color: #738198; font-size: 12px; white-space: nowrap; }
.collector-page-links { display: flex; gap: 25px; border-bottom: 1px solid #d8e3ef; margin-bottom: 10px; }
.collector-page-links a { padding: 7px 1px 8px; color: #50627c; text-decoration: none; border-bottom: 2px solid transparent; font-size: 14px; }
.collector-page-links a.active { color: #087bff; border-color: #087bff; font-weight: 700; }
.collector-trend-panel, .collector-record-panel { background: #fff; border: 1px solid #d9e5f1; border-radius: 6px; overflow: hidden; }
.collector-trend-panel { margin-bottom: 12px; }
.collector-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border-bottom: 1px solid #e4ecf4; padding: 12px 0 16px; }
.collector-summary > div, .collector-summary > button { position: relative; display: flex; flex-direction: column; align-items: center; gap: 5px; min-width: 0; border: 0; border-left: 1px solid #dce6f0; padding: 0 15px; background: transparent; color: inherit; font: inherit; }
.collector-summary > :first-child { border-left: 0; }
.collector-summary span { font-size: 13px; font-weight: 600; }
.collector-summary strong { font-size: 31px; line-height: 1.15; font-variant-numeric: tabular-nums; letter-spacing: -.4px; }
.collector-summary strong small { font-size: .75em; padding: 0 7px; font-weight: 400; }
.collector-summary .collector-green { color: #06a366; }
.collector-summary .collector-incomplete { position: absolute; bottom: -13px; color: #987130; font-size: 10px; }
.collector-summary .collector-attention-metric { cursor: pointer; }
.collector-attention-metric strong { color: #df8d06; text-decoration: underline; text-decoration-thickness: 1px; text-underline-offset: 5px; }
.collector-trend-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 0 18px; }
.collector-chart-tabs { display: flex; gap: 23px; }
.collector-chart-tabs button { border: 0; border-bottom: 2px solid transparent; background: transparent; padding: 10px 0 8px; color: #5b6d86; font: inherit; font-size: 13px; cursor: pointer; }
.collector-chart-tabs button.active { border-color: #087bff; color: #087bff; font-weight: 700; }
.collector-chart-help { color: #8896a9; font-size: 11px; }
.collector-chart-container { position: relative; }
.collector-chart { height: 220px; width: 100%; }
.collector-chart-empty { position: absolute; top: 54px; left: 60px; right: 25px; bottom: 35px; display: flex; align-items: center; justify-content: center; color: #8492a6; font-size: 13px; pointer-events: none; background: #ffffffb8; }
.collector-chart-caption { margin: 0; padding: 0 19px 8px; font-size: 11px; line-height: 1.6; color: #718198; }
.collector-coverage-note { margin-left: 12px; color: #8a6d32; }
.collector-record-toolbar { display: flex; justify-content: space-between; align-items: center; gap: 18px; padding: 8px 18px; }
.collector-record-toolbar h2 { margin: 0; font-size: 16px; line-height: 1.4; white-space: nowrap; }
.collector-record-filters { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 10px; }
.collector-search { width: clamp(180px, 18vw, 290px); }
.collector-search input { width: 100%; }
.collector-record-filters .select { min-width: 130px; max-width: 220px; }
.collector-attention-toggle { display: inline-flex; align-items: center; gap: 6px; color: #52657e; font-size: 12px; white-space: nowrap; cursor: pointer; }
.collector-attention-toggle input { accent-color: #1681f9; }
.collector-table-scroll { position: relative; overflow-x: auto; padding: 0 16px; }
.collector-data-table { border-collapse: collapse; width: 100%; min-width: 690px; font-size: 12px; line-height: 1.5; text-align: left; }
.collector-data-table thead { background: #edf4fb; color: #354d6f; }
.collector-data-table th, .collector-data-table td { border-bottom: 1px solid #e5edf5; padding: 5px 13px; text-align: left; vertical-align: middle; }
.collector-data-table thead th { font-weight: 600; padding-top: 7px; padding-bottom: 7px; }
.collector-data-table tbody th { font-weight: 500; }
.collector-data-table tbody > tr:hover:not(.collector-detail-row) { background: #f8fbfe; }
.collector-date, .collector-num { font-variant-numeric: tabular-nums; white-space: nowrap; }
.collector-status { display: inline-block; border-radius: 4px; padding: 2px 8px; font-size: 11px; line-height: 1.5; white-space: nowrap; }
.collector-status.is-running { background: #e4f1ff; color: #087bf3; }
.collector-status.is-success { background: #e4f8ee; color: #078f5d; }
.collector-status.is-warning { background: #fff2d8; color: #a66803; }
.collector-status.is-error { background: #ffebed; color: #d83a4d; }
.collector-status.is-neutral { background: #edf1f6; color: #5b6d86; }
.collector-row-action { width: 40px; text-align: center !important; }
.collector-row-action button { width: 30px; height: 22px; border: 0; background: transparent; font-size: 20px; line-height: 1; color: #4d6e98; cursor: pointer; }
.collector-selected-row { background: #f0f7ff !important; }
.collector-detail-row > td { background: #f7fafe; padding: 15px 17px; }
.collector-site-detail dl, .collector-task-detail dl { display: flex; flex-wrap: wrap; gap: 12px 28px; margin: 0; }
.collector-site-detail dl > div, .collector-task-detail dl > div { min-width: 120px; }
.collector-task-detail dl > div:first-child { flex-basis: 100%; }
.collector-detail-row dt { color: #6d809b; margin-bottom: 4px; font-size: 11px; }
.collector-detail-row dd { margin: 0; overflow-wrap: anywhere; font-variant-numeric: tabular-nums; }
.collector-detail-links { display: flex; flex-wrap: wrap; gap: 20px; margin-top: 12px; }
.collector-detail-links a, .collector-target a { color: #087bf3; }
.collector-error-text { margin: 11px 0 0; color: #b74d42; overflow-wrap: anywhere; white-space: pre-wrap; }
.collector-result { max-width: 360px; }
.collector-result > span { display: block; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; max-width: 32vw; }
.collector-target { margin: 12px 0 0; color: #6d809b; overflow-wrap: anywhere; }
.collector-pagination { display: flex; justify-content: space-between; align-items: center; gap: 14px; padding: 6px 18px; color: #647995; font-size: 12px; }
.collector-pagination-controls { display: flex; align-items: center; gap: 9px; }
.collector-pagination-controls .btn { min-width: 30px; height: 30px; min-height: 30px; padding: 3px 8px; font-size: 20px; }
.collector-pagination-controls .select { height: 32px; min-height: 32px; padding-top: 4px; padding-bottom: 4px; font-size: 12px; }
.collector-pagination-controls > label { display: flex; align-items: center; }
.collector-page-number input { width: 48px; height: 31px; border: 1px solid #cbdbea; border-radius: 4px; text-align: center; color: #086cdf; font: inherit; }
.collector-empty-row { height: 180px; text-align: center !important; color: #8290a2; }
.collector-load-error { margin: 0 0 14px; padding: 10px 13px; background: #fff1f0; border: 1px solid #f3c8c1; border-radius: 4px; color: #b34b40; font-size: 13px; }
@media (max-width: 850px) {
  .collector-dashboard-head { align-items: flex-start; }
  .collector-dashboard-controls { gap: 7px; }
  .collector-updated { flex-basis: 100%; text-align: right; }
  .collector-record-toolbar { align-items: flex-start; flex-direction: column; gap: 10px; }
  .collector-record-filters { width: 100%; justify-content: flex-start; }
  .collector-search { flex: 1; min-width: 180px; }
  .collector-summary strong { font-size: 26px; }
  .collector-summary span { font-size: 11px; }
  .collector-chart-help { display: none; }
  .collector-data-table th, .collector-data-table td { padding-top: 8px; padding-bottom: 8px; }
  .collector-row-action button { height: 25px; }
  .collector-coverage-note { display: block; margin-left: 0; margin-top: 4px; }
}
@media (max-width: 520px) {
  .collector-dashboard-head { flex-direction: column; gap: 12px; }
  .collector-dashboard-controls { justify-content: flex-start; width: 100%; }
  .collector-updated { flex-basis: auto; text-align: left; font-size: 11px; }
  .collector-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px 0; padding: 17px 0; }
  .collector-summary > :nth-child(3) { border-left: 0; }
  .collector-summary strong { font-size: 27px; }
  .collector-chart-tabs { gap: 18px; }
  .collector-chart { height: 245px; }
  .collector-pagination { align-items: flex-start; flex-direction: column; }
  .collector-record-filters .select { min-width: 125px; max-width: 100%; }
  .collector-page-links { gap: 25px; }
}
</style>
