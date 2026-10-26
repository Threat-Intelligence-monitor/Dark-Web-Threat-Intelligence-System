<template>
  <div class="scan-workbench">
    <Teleport v-if="headerReady" to=".prototype-vue-shell .app-header">
      <nav class="scan-header-crumb" aria-label="面包屑"><a :href="resultsHref">玄鉴</a><el-icon><ArrowRight /></el-icon><strong>扫描任务</strong></nav>
    </Teleport>

    <aside class="scan-scope" aria-labelledby="scan-scope-heading">
      <h1 id="scan-scope-heading">扫描范围</h1>
      <section class="scope-object">
        <div class="scope-heading"><label for="scan-watchlist">监测对象</label><a href="/settings?tab=objects" aria-label="管理监测对象" title="管理监测对象"><el-icon><Setting /></el-icon></a></div>
        <el-select id="scan-watchlist" v-model="scanForm.watchlistId" aria-label="监测对象" placeholder="选择监测对象" :loading="loadingWatchlists" :disabled="scanLoading">
          <el-option v-for="item in watchlists" :key="item.id" :label="item.name" :value="item.id" />
        </el-select>
        <a v-if="selectedWatchlist && !enabledTermCount" class="scope-warning" href="/settings?tab=objects">尚未配置检索词 <el-icon><ArrowRight /></el-icon></a>
      </section>

      <fieldset class="scope-sources" :disabled="scanLoading || continuousLoading || continuousScopeLocked" :title="continuousScopeLocked ? '修改持续监测范围前请先停止任务' : ''">
        <legend>数据来源</legend>
        <label><input v-model="scanForm.sourceFamilies" type="checkbox" value="netdisk_aggregator"><el-icon><Cloudy /></el-icon><span>网盘监测</span></label>
        <label><input v-model="scanForm.sourceFamilies" type="checkbox" value="document_library"><el-icon><Document /></el-icon><span>文库监测</span></label>
      </fieldset>

      <fieldset class="scope-file-types" :disabled="scanLoading || continuousLoading || continuousScopeLocked" :title="continuousScopeLocked ? '修改持续监测范围前请先停止任务' : ''">
        <legend>文件类型</legend>
        <div class="file-type-grid"><label v-for="type in fileTypeOptions" :key="type" class="file-type-chip"><input v-model="scanForm.fileTypes" type="checkbox" :value="type" :aria-label="type"><span>{{ type }}</span></label></div>
      </fieldset>

      <details class="scope-advanced">
        <summary><el-icon><ArrowDown /></el-icon>高级设置</summary>
        <div class="advanced-fields">
          <label for="scan-candidate-limit">文库候选上限</label>
          <input id="scan-candidate-limit" v-model.number="scanForm.pageLimit" type="number" aria-label="文库候选上限" min="1" max="200" step="1" :disabled="!hasLibrarySource || scanLoading || continuousLoading || continuousScopeLocked" @change="normalizeCandidateLimit">
          <label class="advanced-switch" for="scan-library-detail"><span>文库详情抓取</span><input id="scan-library-detail" v-model="scanForm.detailFetch" type="checkbox" role="switch" aria-label="文库详情抓取" :disabled="!hasLibrarySource || scanLoading || continuousLoading || continuousScopeLocked"></label>
        </div>
      </details>
    </aside>

    <section class="scan-main" aria-label="扫描工作区">
      <header class="workbench-toolbar">
        <div class="scan-mode-tabs" role="tablist" aria-label="扫描模式">
          <button id="single-scan-tab" role="tab" :aria-selected="activeMode === 'single'" aria-controls="scan-mode-panel" :class="{ active: activeMode === 'single' }" @click="activeMode = 'single'">单次扫描</button>
          <button id="continuous-scan-tab" role="tab" :aria-selected="activeMode === 'continuous'" aria-controls="scan-mode-panel" :class="{ active: activeMode === 'continuous' }" title="按当前对象启用的来源执行定时扫描" @click="activeMode = 'continuous'">持续监测</button>
        </div>
        <el-button v-if="activeMode === 'single'" class="scan-primary-action" :loading="scanLoading" :disabled="!scanReady" @click="runScan"><el-icon><CaretRight /></el-icon>立即扫描</el-button>
        <el-button v-else-if="!continuousActive" class="scan-primary-action" :loading="continuousLoading" :disabled="continuousStartDisabled" @click="startContinuousScan()"><el-icon><CaretRight /></el-icon>开启监测</el-button>
        <el-button v-else class="scan-primary-action stop" :loading="continuousLoading" :disabled="continuousStopDisabled" @click="stopContinuousScan"><el-icon><VideoPause /></el-icon>{{ continuousStopping ? '停止中' : '停止监测' }}</el-button>
      </header>

      <div class="workbench-content">
        <section id="scan-mode-panel" class="scan-readiness" :class="{ busy: scanLoading || continuousStatus.running }" role="tabpanel" :aria-labelledby="activeMode === 'single' ? 'single-scan-tab' : 'continuous-scan-tab'">
          <div class="readiness-label" role="status"><i></i><strong>{{ readyLabel }}</strong></div>
          <div class="scan-plan"><span><el-icon><Clock /></el-icon>计划任务</span><el-select :model-value="continuousStatus.enabled ? continuousIntervalHours : 0" aria-label="计划任务" :disabled="continuousPlanDisabled" @change="changeSchedule"><el-option label="关闭" :value="0" /><el-option label="每 1 小时" :value="1" /><el-option label="每 4 小时" :value="4" /><el-option label="每 8 小时" :value="8" /></el-select></div>
        </section>

        <div v-if="lastRunMessage || lastRunErrors.length || continuousStatus.last_error || continuousError" class="scan-feedback" role="status">
          <p v-if="lastRunMessage"><el-icon><CircleCheck /></el-icon>{{ lastRunMessage }}</p>
          <p v-if="lastRunErrors.length" class="scan-error">{{ lastRunErrors.slice(0, 3).join('；') }}</p>
          <p v-if="continuousStatus.last_error" class="scan-error">{{ continuousStatus.last_error }}</p>
          <p v-if="continuousError" class="scan-error">{{ continuousError }}</p>
        </div>

        <section class="scan-history" aria-labelledby="scan-history-heading">
          <header class="history-toolbar">
            <h2 id="scan-history-heading">扫描记录</h2>
            <div class="history-filters"><el-button class="history-refresh" :loading="loadingScans" @click="loadScans"><el-icon><Refresh /></el-icon>刷新</el-button><el-date-picker v-model="dateRange" type="daterange" aria-label="扫描日期" start-placeholder="开始日期" end-placeholder="结束日期" range-separator="至" value-format="YYYY-MM-DD" :editable="false" :clearable="true" /></div>
          </header>
          <div v-loading="loadingScans" class="scan-table-wrap">
            <table class="scan-records">
              <thead><tr><th scope="col">时间</th><th scope="col">监测对象</th><th scope="col">来源</th><th scope="col" class="number-column">候选</th><th scope="col" class="number-column">命中</th><th scope="col">状态</th><th scope="col" class="action-column">操作</th></tr></thead>
              <tbody>
                <tr v-for="row in filteredScanRuns" :key="row.id" :class="{ selected: detailsOpen && selectedRun?.id === row.id }">
                  <td class="time-cell">{{ formatDateTime(row.finishedAt) || '—' }}</td><td class="object-cell"><span :title="row.watchlistName">{{ row.watchlistName || '—' }}</span></td>
                  <td><span v-for="family in row.sourceFamilies || []" :key="family" class="source-label"><el-icon><Cloudy v-if="family === 'netdisk_aggregator'" /><Document v-else /></el-icon>{{ family === 'netdisk_aggregator' ? '网盘监测' : family === 'document_library' ? '文库监测' : family }}</span></td>
                  <td class="number-column">{{ row.candidateCount || 0 }}</td><td class="number-column">{{ row.hitCount || 0 }}</td><td><span class="scan-status" :class="row.status"><i></i>{{ statusLabelMap[row.status] || row.status || '未知' }}</span></td><td class="action-column"><button class="record-action" :aria-label="`查看 ${formatDateTime(row.finishedAt)} 扫描详情`" @click="viewRun(row)">查看</button></td>
                </tr>
                <tr v-if="!filteredScanRuns.length && !loadingScans"><td colspan="7" class="records-empty">{{ dateRange?.length ? '当前日期无扫描记录' : '暂无扫描记录' }}</td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <footer v-if="latestRun" class="latest-scan"><strong>最近一次</strong><span class="scan-status" :class="latestRun.status"><i></i>{{ statusLabelMap[latestRun.status] || latestRun.status }}</span><time>{{ formatDateTime(latestRun.finishedAt) }}</time><button class="record-action latest-action" @click="viewRun(latestRun)">查看详情 <el-icon><ArrowRight /></el-icon></button></footer>
      </div>
    </section>

    <el-drawer v-model="detailsOpen" title="扫描详情" size="min(680px, 100vw)">
      <div v-if="selectedRun" class="scan-detail-content">
        <dl class="scan-detail-meta"><div><dt>监测对象</dt><dd>{{ selectedRun.watchlistName }}</dd></div><div><dt>完成时间</dt><dd>{{ formatDateTime(selectedRun.finishedAt) }}</dd></div><div><dt>来源</dt><dd>{{ formatSourceFamilies(selectedRun.sourceFamilies) }}</dd></div><div><dt>结果</dt><dd><span class="scan-status" :class="selectedRun.status"><i></i>{{ statusLabelMap[selectedRun.status] || selectedRun.status }}</span></dd></div></dl>
        <h3>来源执行情况</h3>
        <p v-if="!sourceStatsRows(selectedRun).length" class="empty-source-detail">暂无来源统计</p>
        <section v-for="source in sourceStatsRows(selectedRun)" :key="source.source" class="source-run-detail"><h4>{{ source.sourceLabel || source.source }}</h4><dl><div><dt>搜索页</dt><dd>{{ source.pagesScanned || 0 }}</dd></div><div><dt>候选</dt><dd>{{ source.candidateCount || 0 }}</dd></div><div><dt>命中</dt><dd>{{ source.hitCount || 0 }}</dd></div><div><dt>异常</dt><dd>{{ source.errorCount || 0 }}</dd></div></dl><a v-if="sourceLink(source.lastUrl)" :href="sourceLink(source.lastUrl)" target="_blank" rel="noopener noreferrer">搜索结果第 {{ source.lastPage || 1 }} 页 <el-icon><TopRight /></el-icon></a></section>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useDocumentExposureApi } from '@/composables/useDocumentExposureApi'
import { formatShanghaiDateTime } from '@/composables/useShanghaiTime'

const api = useDocumentExposureApi()
const loadingWatchlists = ref(false)
const loadingScans = ref(false)
const scanLoading = ref(false)
const continuousLoading = ref(false)
const watchlists = ref([])
const scanRuns = ref([])
const dateRange = ref(null)
const activeMode = ref('single')
const detailsOpen = ref(false)
const selectedRun = ref(null)
const loadingContinuousStatus = ref(false)
const continuousStatusLoaded = ref(false)
const continuousError = ref('')
const headerReady = ref(false)
const lastRunMessage = ref('')
const lastRunErrors = ref([])
const continuousIntervalHours = ref(1)
const initialContinuousStatus = {
  enabled: false,
  running: false,
  stopping: false,
  source_families: [],
  file_types: null,
  detail_fetch: null,
  document_library_candidate_limit: null,
  started_at: '',
  last_tick_at: '',
  last_success_at: '',
  last_error: '',
  interval_seconds: 3600,
  watchlist_count: 0,
  candidate_count: 0,
  hit_count: 0,
  error_count: 0,
  target_watchlist_id: 0,
  target_watchlist_name: '',
  active_watchlist_count: 0,
}
const continuousStatus = ref({ ...initialContinuousStatus })
let continuousTimer = null
let objectVersion = 0
let singleDraft = null
const fileTypeOptions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z', 'txt', 'csv']

const statusLabelMap = {
  succeeded: '成功',
  partial: '部分成功',
  failed: '失败',
}

const sourceFamilyLabelMap = {
  netdisk_aggregator: '网盘聚合',
  document_library: '文档平台',
}

const scanForm = reactive({
  watchlistId: null,
  sourceFamilies: [],
  fileTypes: [],
  pageLimit: 4,
  detailFetch: true,
})

const selectedWatchlist = computed(() => {
  const selectedId = Number(scanForm.watchlistId || 0)
  return watchlists.value.find((item) => Number(item.id || 0) === selectedId) || null
})

const latestRun = computed(() => scanRuns.value[0] || null)
const filteredScanRuns = computed(() => {
  if (!dateRange.value?.length) return scanRuns.value
  const start = new Date(`${dateRange.value[0]}T00:00:00+08:00`).getTime()
  const end = new Date(`${dateRange.value[1]}T23:59:59.999+08:00`).getTime()
  return scanRuns.value.filter((row) => {
    const finished = new Date(row.finishedAt).getTime()
    return finished >= start && finished <= end
  })
})
const enabledTermCount = computed(() => {
  const watchlist = selectedWatchlist.value || {}
  const terms = 'effective_terms' in watchlist
    ? watchlist.effective_terms
    : [...(watchlist.derived_terms || []), ...(watchlist.terms || [])]
  return (Array.isArray(terms) ? terms : [])
    .filter((term) => String(term.term || '').trim() && (term.enabled == null || Boolean(term.enabled))).length
})
const resultsHref = computed(() => isDocumentLibraryOnly(scanForm.sourceFamilies)
  ? '/document-exposure/document-library'
  : '/document-exposure/netdisk')
const hasLibrarySource = computed(() => scanForm.sourceFamilies.includes('document_library'))
const scanReady = computed(() => Boolean(selectedWatchlist.value?.enabled)
  && enabledTermCount.value > 0 && scanForm.sourceFamilies.length > 0 && scanForm.fileTypes.length > 0)
const unsupportedSources = computed(() => scanForm.sourceFamilies
  .filter((family) => !selectedWatchlist.value?.source_families?.includes(family)))
const continuousActive = computed(() => continuousStatus.value.enabled || continuousStatus.value.running || continuousStatus.value.stopping)
const continuousStopping = computed(() => continuousStatus.value.stopping
  || (continuousStatus.value.running && !continuousStatus.value.enabled))
const continuousSourceFamilies = computed(() => {
  const status = continuousStatus.value
  if (status.running && status.running_source_families?.length) return status.running_source_families
  return status.source_families?.length ? status.source_families : status.running_source_families || []
})
const continuousScopeLocked = computed(() => activeMode.value === 'continuous'
  && (continuousActive.value || loadingContinuousStatus.value))
const canSchedule = computed(() => scanReady.value && !unsupportedSources.value.length)
const continuousPlanDisabled = computed(() => !continuousStatusLoaded.value || loadingContinuousStatus.value
  || continuousLoading.value || continuousStopping.value || (!continuousStatus.value.enabled && !canSchedule.value))
const readyLabel = computed(() => {
  if (scanLoading.value) return '正在扫描'
  if (loadingWatchlists.value) return '正在加载配置'
  if (activeMode.value === 'continuous') {
    if (loadingContinuousStatus.value) return '正在加载持续监测状态'
    if (!continuousStatusLoaded.value && continuousError.value) return '持续监测状态加载失败'
    if (continuousActive.value) {
      const label = monitoringSourceLabel(continuousSourceFamilies.value)
      if (continuousStopping.value) return `${label}持续监测停止中`
      return `${label}持续监测${continuousStatus.value.running ? '执行中' : '已启用'}`
    }
  }
  if (!scanForm.watchlistId) return '请选择监测对象'
  if (!selectedWatchlist.value?.enabled) return '监测对象已停用'
  if (!enabledTermCount.value) return '请配置检索词'
  if (!scanForm.sourceFamilies.length) return '请选择数据来源'
  if (!scanForm.fileTypes.length) return '请选择文件类型'
  if (activeMode.value === 'continuous') {
    if (unsupportedSources.value.length) return `当前对象未启用${monitoringSourceLabel(unsupportedSources.value)}来源，请先保存配置`
    return `${monitoringSourceLabel(scanForm.sourceFamilies)}持续监测未启用`
  }
  return '扫描范围已就绪'
})

function viewRun(row) {
  if (!row) return
  selectedRun.value = row
  detailsOpen.value = true
}

function normalizeCandidateLimit() {
  scanForm.pageLimit = Math.min(200, Math.max(1, Math.floor(Number(scanForm.pageLimit) || 10)))
}

async function changeSchedule(value) {
  if (Number(value) === 0) {
    await stopContinuousScan()
  } else {
    await startContinuousScan(Number(value))
  }
}

function sourceLink(value) {
  try {
    const url = new URL(value)
    return ['http:', 'https:'].includes(url.protocol) ? url.href : null
  } catch {
    return null
  }
}

const continuousStartDisabled = computed(() => {
  return !canSchedule.value || !continuousStatusLoaded.value || loadingContinuousStatus.value
    || continuousLoading.value || continuousActive.value
})

const continuousStopDisabled = computed(() => !continuousActive.value || loadingContinuousStatus.value
  || continuousLoading.value || continuousStopping.value)

function monitoringSourceLabel(families) {
  if (families.includes('netdisk_aggregator') && families.includes('document_library')) return '网盘与文库'
  if (families.includes('document_library')) return '文库'
  if (families.includes('netdisk_aggregator')) return '网盘'
  return ''
}

function isCurrentObject(id, version) {
  return scanForm.watchlistId === id && objectVersion === version
}

function captureSingleDraft() {
  singleDraft = { sourceFamilies: [...scanForm.sourceFamilies], fileTypes: [...scanForm.fileTypes],
    pageLimit: scanForm.pageLimit, detailFetch: scanForm.detailFetch }
}

function syncContinuousScope() {
  if (activeMode.value !== 'continuous' || !continuousActive.value) return
  const status = continuousStatus.value
  scanForm.sourceFamilies = [...continuousSourceFamilies.value]
  scanForm.fileTypes = [...(status.file_types ?? selectedWatchlist.value?.file_types ?? [])]
  scanForm.pageLimit = Number(status.document_library_candidate_limit
    ?? selectedWatchlist.value?.source_policies?.document_library?.candidate_limit
    ?? selectedWatchlist.value?.page_limit ?? defaultPageLimit(scanForm.sourceFamilies))
  scanForm.detailFetch = Boolean(status.detail_fetch
    ?? selectedWatchlist.value?.source_policies?.document_library?.detail_fetch
    ?? selectedWatchlist.value?.detail_fetch ?? true)
}

function applyContinuousStatus(payload) {
  continuousStatus.value = { ...initialContinuousStatus, ...payload }
  continuousStatusLoaded.value = true
  continuousError.value = ''
  if (payload.interval_seconds) continuousIntervalHours.value = Number(payload.interval_seconds) / 3600
  syncContinuousScope()
}

function formatDateTime(value) {
  return formatShanghaiDateTime(value)
}

function formatSourceFamilies(value) {
  const rows = Array.isArray(value) ? value : []
  if (!rows.length) return '全部'
  return rows.map((item) => sourceFamilyLabelMap[item] || item).join(' / ')
}

function sourceStatsRows(row) {
  return Array.isArray(row?.sourceStats) ? row.sourceStats : []
}

function isDocumentLibraryOnly(sourceFamilies) {
  return Array.isArray(sourceFamilies) && sourceFamilies.length === 1 && sourceFamilies[0] === 'document_library'
}

function defaultPageLimit(sourceFamilies) {
  return isDocumentLibraryOnly(sourceFamilies) ? 10 : 4
}

function applyWatchlist(payload) {
  if (!payload) return
  scanForm.watchlistId = payload.id
  scanForm.sourceFamilies = Array.isArray(payload.source_families)
    ? payload.source_families.filter((item) => item === 'netdisk_aggregator' || item === 'document_library')
    : []
  scanForm.fileTypes = Array.isArray(payload.file_types) ? [...payload.file_types] : []
  scanForm.pageLimit = Number(payload.source_policies?.document_library?.candidate_limit || payload.page_limit || defaultPageLimit(scanForm.sourceFamilies))
  scanForm.detailFetch = Boolean(payload.source_policies?.document_library?.detail_fetch ?? payload.detail_fetch ?? true)
}

async function loadWatchlists() {
  loadingWatchlists.value = true
  try {
    watchlists.value = await api.loadWatchlists()
    if (!scanForm.watchlistId) {
      applyWatchlist(watchlists.value[0] || null)
      return
    }
    const current = watchlists.value.find((item) => item.id === scanForm.watchlistId)
    if (current) applyWatchlist(current)
  } catch (error) {
    ElMessage.error(error.message || '加载监测对象失败')
  } finally {
    loadingWatchlists.value = false
  }
}

async function loadScans() {
  const targetId = scanForm.watchlistId
  const version = objectVersion
  if (!targetId) return
  loadingScans.value = true
  try {
    const rows = await api.loadScans({ limit: 50, watchlistId: targetId || undefined })
    if (isCurrentObject(targetId, version)) scanRuns.value = rows
  } catch (error) {
    if (isCurrentObject(targetId, version)) ElMessage.error(error.message || '加载扫描历史失败')
  } finally {
    if (isCurrentObject(targetId, version)) loadingScans.value = false
  }
}

async function loadContinuousStatus() {
  const targetId = scanForm.watchlistId
  const version = objectVersion
  if (!targetId || continuousLoading.value || loadingContinuousStatus.value) return
  loadingContinuousStatus.value = true
  try {
    const payload = await api.loadContinuousStatus({ watchlistId: targetId })
    if (!isCurrentObject(targetId, version)) return
    applyContinuousStatus(payload)
  } catch (error) {
    if (isCurrentObject(targetId, version)) {
      continuousStatusLoaded.value = false
      continuousError.value = error.message || '加载持续监测状态失败'
    }
  } finally {
    if (isCurrentObject(targetId, version)) loadingContinuousStatus.value = false
  }
}

async function runScan() {
  if (!scanReady.value) {
    ElMessage.warning(readyLabel.value)
    return
  }
  scanLoading.value = true
  const targetId = scanForm.watchlistId
  const version = objectVersion
  lastRunMessage.value = ''
  lastRunErrors.value = []
  try {
    const requestPayload = {
      source_families: scanForm.sourceFamilies,
      file_types: scanForm.fileTypes,
      detail_fetch: hasLibrarySource.value && scanForm.detailFetch,
    }
    if (hasLibrarySource.value) {
      requestPayload.document_library_candidate_limit = scanForm.pageLimit
    }
    const payload = await api.runScan(targetId, requestPayload)
    if (!isCurrentObject(targetId, version)) return
    lastRunMessage.value = `扫描完成 · 候选 ${payload.candidates || 0} · 命中 ${payload.hits || 0}`
    lastRunErrors.value = payload.errors || []
    await loadScans()
    ElMessage.success('扫描任务已执行')
  } catch (error) {
    if (isCurrentObject(targetId, version)) ElMessage.error(error.message || '执行扫描失败')
  } finally {
    if (isCurrentObject(targetId, version)) scanLoading.value = false
  }
}

async function startContinuousScan(intervalHours = continuousIntervalHours.value) {
  if (!scanForm.watchlistId) {
    ElMessage.error('请先选择监测对象')
    return
  }
  if (continuousLoading.value || loadingContinuousStatus.value || !continuousStatusLoaded.value || continuousStopping.value) return
  if (!continuousStatus.value.enabled && !canSchedule.value) {
    ElMessage.error(readyLabel.value)
    return
  }
  continuousLoading.value = true
  const targetId = scanForm.watchlistId
  const version = objectVersion
  const scope = continuousStatus.value.enabled ? {
    source_families: [...(continuousStatus.value.source_families || [])],
    file_types: continuousStatus.value.file_types == null ? null : [...continuousStatus.value.file_types],
    detail_fetch: continuousStatus.value.detail_fetch,
    document_library_candidate_limit: continuousStatus.value.document_library_candidate_limit,
  } : {
    source_families: [...scanForm.sourceFamilies], file_types: [...scanForm.fileTypes],
    detail_fetch: hasLibrarySource.value && scanForm.detailFetch,
    document_library_candidate_limit: scanForm.pageLimit,
  }
  try {
    const payload = await api.startContinuous({
      ...scope, interval_seconds: Number(intervalHours || 1) * 3600, watchlist_id: targetId,
    })
    if (!isCurrentObject(targetId, version)) return
    applyContinuousStatus(payload)
    ElMessage.success(payload.message || '持续监测已启用')
  } catch (error) {
    if (isCurrentObject(targetId, version)) {
      continuousError.value = error.message || '开启持续监测失败'
      ElMessage.error(continuousError.value)
    }
  } finally {
    if (isCurrentObject(targetId, version)) continuousLoading.value = false
  }
}

async function stopContinuousScan() {
  if (!scanForm.watchlistId) {
    ElMessage.error('请先选择监测对象')
    return
  }
  if (continuousLoading.value || loadingContinuousStatus.value || continuousStopping.value) return
  continuousLoading.value = true
  const targetId = scanForm.watchlistId
  const version = objectVersion
  try {
    const payload = await api.stopContinuous({ watchlist_id: targetId })
    if (!isCurrentObject(targetId, version)) return
    applyContinuousStatus(payload)
    ElMessage.success(payload.message || (continuousStopping.value ? '持续监测停止中' : '持续监测已停止'))
  } catch (error) {
    if (isCurrentObject(targetId, version)) {
      continuousError.value = error.message || '停止持续监测失败'
      ElMessage.error(continuousError.value)
    }
  } finally {
    if (isCurrentObject(targetId, version)) continuousLoading.value = false
  }
}

watch(
  () => scanForm.watchlistId,
  async (watchlistId) => {
    objectVersion++
    continuousStatus.value = { ...initialContinuousStatus }
    continuousStatusLoaded.value = false
    continuousLoading.value = false
    loadingContinuousStatus.value = false
    continuousIntervalHours.value = 1
    continuousError.value = ''
    singleDraft = null
    if (!watchlistId) return
    const target = watchlists.value.find((item) => item.id === watchlistId)
    if (target) applyWatchlist(target)
    if (activeMode.value === 'continuous') captureSingleDraft()
    dateRange.value = null
    lastRunMessage.value = ''
    lastRunErrors.value = []
    detailsOpen.value = false
    scanRuns.value = []
    await Promise.all([loadScans(), loadContinuousStatus()])
  }
)

watch(activeMode, (mode) => {
  if (mode === 'continuous') {
    captureSingleDraft()
    syncContinuousScope()
  }
  else if (singleDraft) {
    Object.assign(scanForm, singleDraft)
    singleDraft = null
  }
})

onMounted(async () => {
  headerReady.value = true
  document.title = '扫描任务 · 玄鉴'
  await loadWatchlists()
  continuousTimer = window.setInterval(() => {
    loadContinuousStatus()
    loadScans()
  }, 15000)
})

onUnmounted(() => {
  objectVersion++
  if (continuousTimer) {
    window.clearInterval(continuousTimer)
    continuousTimer = null
  }
})
</script>

<style scoped>
.scan-workbench {
  --scan-accent: #ba7b23;
  --el-color-primary: #ba7b23;
  --el-border-radius-base: 4px;
  --el-border-color: var(--border);
  --el-text-color-primary: var(--fg);
  --el-text-color-regular: var(--fg);
  --el-font-family: var(--font-body);
  display: grid; grid-template-columns: clamp(276px, 23vw, 350px) minmax(0, 1fr);
  min-height: calc(100dvh - 54px); margin: -10px -12px -28px; background: var(--surface); color: var(--fg); font-size: 14px;
}
.scan-header-crumb { position: absolute; left: 24px; top: 0; height: 100%; display: flex; align-items: center; gap: 13px; color: var(--fg); font-size: 14px; }
.scan-header-crumb > .el-icon { color: var(--muted); font-size: 12px; }
.scan-header-crumb a:hover { color: var(--scan-accent); }
.scan-scope { display: flex; flex-direction: column; gap: 34px; min-width: 0; padding: 28px 24px 30px; border-right: 1px solid var(--border); background: #fbfcfd; }
.scan-scope h1 { margin: 0 0 3px; font-family: var(--font-body); font-size: 22px; font-weight: 650; }
.scope-heading { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
.scope-heading > label, .scan-scope legend { padding: 0; font-size: 15px; font-weight: 650; }
.scope-heading > a { display: grid; place-items: center; width: 24px; height: 24px; color: var(--muted); font-size: 16px; }
.scope-heading > a:hover { color: var(--scan-accent); }
.scan-scope fieldset { min-width: 0; margin: 0; padding: 0; border: 0; }
.scan-scope legend { margin-bottom: 16px; }
.scope-sources > label { display: flex; align-items: center; gap: 12px; width: fit-content; margin: 0 0 19px; cursor: pointer; font-size: 15px; }
.scope-sources > label:last-child { margin-bottom: 0; }
.scope-sources input { width: 17px; height: 17px; margin: 0; accent-color: var(--scan-accent); }
.scope-sources .el-icon { width: 23px; color: var(--fg); font-size: 22px; }
.file-type-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 7px; }
.file-type-chip { position: relative; cursor: pointer; }
.file-type-chip input { position: absolute; width: 1px; height: 1px; opacity: 0; }
.file-type-chip span { display: grid; place-items: center; min-height: 34px; border: 1px solid var(--border); border-radius: 4px; background: var(--surface); font: 13px var(--font-body); transition: border-color .15s, background .15s; }
.file-type-chip input:checked + span { border-color: #d2a65f; background: #fcf1dd; color: #79501a; }
.file-type-chip input:focus-visible + span { outline: 2px solid var(--scan-accent); outline-offset: 2px; }
.file-type-chip input:disabled + span { cursor: default; opacity: .6; }
.scope-warning { display: flex; align-items: center; gap: 5px; margin-top: 12px; color: #9b661c; font-size: 13px; }
.scope-advanced { margin-top: auto; padding-top: 30px; }
.scope-advanced summary { display: flex; align-items: center; gap: 10px; min-height: 42px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 4px; font-size: 14px; cursor: pointer; list-style: none; }
.scope-advanced summary::-webkit-details-marker { display: none; }
.scope-advanced summary .el-icon { font-size: 13px; transition: transform .15s; }
.scope-advanced[open] summary .el-icon { transform: rotate(180deg); }
.advanced-fields { display: grid; gap: 11px; padding: 18px 2px 0; font-size: 13px; }
.advanced-fields > input { width: 100%; min-height: 38px; padding: 8px 10px; border: 1px solid var(--border); border-radius: 4px; color: var(--fg); font: inherit; }
.advanced-fields > input:disabled { background: #f2f4f6; color: #96a0aa; }
.advanced-switch { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding-top: 8px; }
.advanced-switch > input { position: relative; width: 36px; height: 20px; margin: 0; appearance: none; border-radius: 10px; background: #c6cdd4; cursor: pointer; }
.advanced-switch > input::after { position: absolute; top: 3px; left: 3px; width: 14px; height: 14px; border-radius: 50%; background: white; content: ''; transition: transform .15s; }
.advanced-switch > input:checked { background: var(--scan-accent); }
.advanced-switch > input:checked::after { transform: translateX(16px); }
.advanced-switch > input:disabled { opacity: .5; cursor: default; }
.advanced-switch > input:focus-visible { outline: 2px solid var(--scan-accent); outline-offset: 2px; }
.scan-main { min-width: 0; display: flex; flex-direction: column; }
.workbench-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 20px; min-height: 78px; padding: 0 24px; border-bottom: 1px solid var(--border); }
.scan-mode-tabs { display: flex; align-self: stretch; gap: 30px; }
.scan-mode-tabs > button { position: relative; display: flex; align-items: center; padding: 0 5px; border: 0; background: transparent; color: var(--fg); font-size: 18px; white-space: nowrap; }
.scan-mode-tabs > button.active { font-weight: 650; }
.scan-mode-tabs > button.active::after { position: absolute; right: 0; bottom: 0; left: 0; height: 2px; background: var(--scan-accent); content: ''; }
.scan-primary-action { min-width: 130px; min-height: 41px; border: 1px solid #1b242a; border-radius: 4px; background: #1b242a; color: #edba60; font-size: 14px; }
.scan-primary-action:hover, .scan-primary-action:focus-visible { border-color: #38454e; background: #2d3840; color: #f6cb7b; }
.scan-primary-action.stop { color: #f2b2a8; }
.scan-primary-action.is-disabled { background: #e9ecef; border-color: #dce1e6; color: #96a0aa; }
.workbench-content { display: flex; flex: 1; flex-direction: column; gap: 27px; min-width: 0; padding: 24px; }
.scan-readiness { display: flex; align-items: center; justify-content: space-between; gap: 20px; min-height: 76px; padding: 17px 19px; border: 1px solid #ebe4d9; border-radius: 5px; background: #fefbf5; }
.readiness-label { display: flex; align-items: center; gap: 12px; min-width: 0; }
.readiness-label > i { width: 13px; height: 13px; flex-shrink: 0; border-radius: 50%; background: #e8a12a; }
.readiness-label > strong { font-size: 16px; font-weight: 650; }
.scan-readiness.busy .readiness-label > i { animation: scan-pulse 1.1s ease-in-out infinite; }
.scan-plan { display: flex; align-items: center; gap: 13px; padding-left: 22px; border-left: 1px solid #e9e2d7; }
.scan-plan > span { display: flex; align-items: center; gap: 8px; color: #606a73; white-space: nowrap; }
.scan-plan > span .el-icon { color: var(--scan-accent); font-size: 19px; }
.scan-plan :deep(.el-select) { width: 115px; }
.scan-history { min-width: 0; }
.history-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 18px; margin: 4px 0 18px; }
.history-toolbar h2 { font-family: var(--font-body); font-size: 23px; font-weight: 650; }
.history-filters { display: flex; align-items: center; gap: 10px; }
.history-filters :deep(.el-date-editor) { width: 250px; min-height: 37px; }
.history-refresh { min-height: 37px; border-radius: 4px; font-size: 13px; }
.scan-table-wrap { max-width: 100%; min-width: 0; overflow-x: auto; }
.scan-records { width: 100%; min-width: 780px; border-collapse: collapse; text-align: left; font-size: 13px; }
.scan-records th { padding: 12px 13px; border-bottom: 1px solid var(--border); background: #f5f7f9; color: #677380; font-weight: 600; white-space: nowrap; }
.scan-records td { padding: 16px 13px; border-bottom: 1px solid #e9edf1; vertical-align: middle; }
.scan-records tbody tr:hover, .scan-records tbody tr.selected { background: #fcfaf5; }
.scan-records .time-cell { width: 174px; font: 12px var(--font-mono); white-space: nowrap; }
.object-cell { max-width: 175px; }
.object-cell > span { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.source-label { display: inline-flex; align-items: center; gap: 6px; margin: 2px 9px 2px 0; white-space: nowrap; }
.source-label .el-icon { font-size: 17px; }
.number-column { width: 72px; text-align: center; font-variant-numeric: tabular-nums; }
.scan-records td.number-column { font: 13px var(--font-mono); }
.action-column { width: 70px; text-align: center; }
.record-action { display: inline-flex; align-items: center; justify-content: center; gap: 6px; padding: 4px 0; border: 0; background: transparent; color: var(--fg); font-size: 13px; cursor: pointer; }
.record-action:hover { color: var(--scan-accent); }
.scan-status { display: inline-flex; align-items: center; gap: 7px; white-space: nowrap; font-size: 13px; }
.scan-status > i { width: 7px; height: 7px; flex-shrink: 0; border-radius: 50%; background: currentColor; }
.scan-status.succeeded { color: #429a3e; }
.scan-status.partial { color: #b67a19; }
.scan-status.failed, .scan-error { color: #c4493c; }
.scan-records td.records-empty { height: 200px; text-align: center; color: var(--muted); font-size: 14px; }
.latest-scan { display: flex; align-items: center; gap: 19px; margin-top: auto; padding: 19px 20px; border-radius: 4px; background: #f5f7f9; }
.latest-scan > strong { font-size: 15px; white-space: nowrap; }
.latest-scan > .scan-status { padding-left: 18px; border-left: 1px solid var(--border); }
.latest-scan > time { color: var(--fg); font-size: 13px; font-variant-numeric: tabular-nums; }
.latest-action { margin-left: auto; white-space: nowrap; }
.scan-feedback { padding: 11px 16px; border-left: 2px solid var(--scan-accent); background: #fcfaf5; font-size: 13px; }
.scan-feedback p { display: flex; align-items: baseline; gap: 8px; margin: 3px 0; }
.scan-feedback .el-icon { color: #429a3e; }
.scan-detail-content { color: var(--fg); font-family: var(--font-body); font-size: 14px; }
.scan-detail-meta { display: grid; gap: 15px; margin: 0 0 30px; }
.scan-detail-meta > div { display: grid; grid-template-columns: 85px minmax(0, 1fr); gap: 15px; }
.scan-detail-meta dt { color: var(--muted); }
.scan-detail-meta dd { margin: 0; }
.scan-detail-content h3 { margin-bottom: 17px; font-size: 17px; }
.source-run-detail { margin-bottom: 14px; padding: 15px 17px; border: 1px solid var(--border); border-radius: 4px; }
.source-run-detail h4 { margin-bottom: 15px; font-size: 14px; }
.source-run-detail dl { display: grid; grid-template-columns: repeat(4, 1fr); margin: 0 0 12px; }
.source-run-detail dt { color: var(--muted); font-size: 12px; }
.source-run-detail dd { margin: 4px 0 0; font: 15px var(--font-mono); }
.source-run-detail a { display: inline-flex; align-items: center; gap: 5px; color: #9b681f; font-size: 13px; }
.empty-source-detail { color: var(--muted); }
:deep(.el-button > span) { gap: 7px; }
:deep(.el-button + .el-button) { margin-left: 0; }
.scan-scope :deep(.el-select) { width: 100%; }
:deep(.el-select__wrapper), :deep(.el-input__wrapper) { min-height: 38px; border-radius: 4px; box-shadow: 0 0 0 1px var(--border) inset; font-size: 13px; }
:deep(.el-range-input) { font-size: 12px; }
@keyframes scan-pulse { 50% { opacity: .4; } }
@media (prefers-reduced-motion: reduce) { .scan-readiness.busy .readiness-label > i { animation: none; } }
@media (max-width: 1150px) { .scan-workbench { grid-template-columns: 258px minmax(0, 1fr); } .scan-scope { padding-inline: 19px; } .workbench-content { padding: 20px; } .workbench-toolbar { padding-inline: 20px; } .scan-readiness { gap: 12px; padding-inline: 14px; } .scan-plan { gap: 8px; padding-left: 12px; } .readiness-label > strong { font-size: 15px; } .history-filters :deep(.el-date-editor) { width: 225px; } .latest-scan { flex-wrap: wrap; gap: 12px; padding: 16px; } }
@media (max-width: 900px) { .scan-workbench { margin: -8px -9px -22px; } .scan-header-crumb { left: 64px; } }
@media (max-width: 800px) { .scan-workbench { grid-template-columns: 1fr; } .scan-scope { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 24px; padding: 22px; border-right: 0; border-bottom: 1px solid var(--border); } .scan-scope h1, .scope-file-types, .scope-advanced { grid-column: 1 / -1; } .scan-scope h1 { font-size: 21px; } .scope-advanced { margin-top: 0; padding-top: 0; } .scope-sources > label { font-size: 14px; } .file-type-grid { grid-template-columns: repeat(6, minmax(0, 1fr)); } .scan-header-crumb { left: 64px; gap: 8px; font-size: 13px; } .scan-header-crumb > a { display: none; } .scan-header-crumb > .el-icon { display: none; } .workbench-toolbar { min-height: 68px; } .scan-readiness { flex-wrap: wrap; gap: 18px; } .scan-plan { margin-left: auto; padding-left: 0; border-left: 0; } .history-toolbar { flex-wrap: wrap; gap: 15px; } .history-filters { margin-left: auto; } }
@media (max-width: 480px) { .scan-scope { padding: 20px 16px; gap: 24px 16px; } .scope-heading > label, .scan-scope legend { font-size: 14px; } .scope-sources > label { gap: 8px; } .scope-sources .el-icon { width: 19px; font-size: 19px; } .scope-sources input { width: 16px; height: 16px; } .workbench-toolbar { gap: 12px; padding-inline: 16px; } .scan-mode-tabs { gap: 18px; } .scan-mode-tabs > button { padding-inline: 0; font-size: 15px; } .scan-primary-action { min-width: 108px; min-height: 38px; padding-inline: 10px; font-size: 13px; } .workbench-content { gap: 23px; padding: 18px 16px; } .scan-readiness { align-items: stretch; padding: 15px; } .readiness-label { width: 100%; } .scan-plan { width: 100%; justify-content: space-between; margin-left: 0; } .history-toolbar h2 { font-size: 21px; } .history-filters { width: 100%; margin: 0; } .history-filters :deep(.el-date-editor) { flex: 1; width: 0; } .latest-scan { gap: 12px; padding: 15px; } .latest-scan > time { width: 100%; order: 2; } .latest-scan > .scan-status { padding-left: 12px; } .latest-action { font-size: 12px; } }
</style>
