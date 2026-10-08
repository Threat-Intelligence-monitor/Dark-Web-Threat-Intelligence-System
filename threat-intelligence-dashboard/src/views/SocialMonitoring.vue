<template>
  <div class="sm-page">
    <header class="sm-heading">
      <div>
        <h1>社交平台监测</h1>
      </div>
      <el-button v-if="isAdmin" type="primary" @click="newWatchlist">新建监测对象</el-button>
    </header>

    <div class="sm-scope" role="note">
      <el-icon><InfoFilled /></el-icon>
      <span>{{ coverage.message || '仅覆盖公开搜索引擎已收录的帖子，扫描结果需进一步核验。' }}</span>
    </div>

    <section class="sm-card sm-control" aria-label="监测对象选择与扫描">
      <div class="sm-control__select">
        <span class="sm-label">当前监测对象</span>
        <el-select v-model="selectedId" placeholder="选择监测对象" :disabled="creating" @change="selectWatchlist">
          <el-option v-for="item in watchlists" :key="item.id" :label="item.name" :value="item.id" />
        </el-select>
        <el-tag v-if="selectedWatchlist" :type="selectedWatchlist.enabled ? 'success' : 'info'" effect="plain">
          {{ selectedWatchlist.enabled ? '监测中' : '已停用' }}
        </el-tag>
        <el-tag v-else-if="creating" type="primary" effect="plain">新建中</el-tag>
      </div>
      <div class="sm-control__actions">
        <span v-if="selectedWatchlist" class="sm-muted">下次扫描 {{ nextScanLabel(selectedWatchlist.next_scan_at) }}</span>
        <el-button :loading="loading" @click="refresh(false)">刷新</el-button>
        <el-button
          v-if="isAdmin"
          type="primary"
          :loading="scanning"
          :disabled="!selectedWatchlist?.enabled || latestScan?.status === 'running'"
          @click="startScan"
        >立即扫描</el-button>
      </div>
    </section>

    <div v-if="loadError" class="sm-error" role="alert">{{ loadError }}</div>

    <section v-if="selectedId && activeTab !== 'settings'" class="sm-metrics" aria-label="监测概况">
      <div class="sm-metric sm-card">
        <span>待核验线索</span>
        <strong>{{ pendingCount }}</strong>
        <small>最近 100 条扫描结果</small>
      </div>
      <div class="sm-metric sm-card">
        <span>本轮发现</span>
        <strong>{{ latestScan?.stats?.discovered_unique ?? '—' }}</strong>
        <small>去重后的单帖链接</small>
      </div>
      <div class="sm-metric sm-card">
        <span>本轮尝试读取</span>
        <strong>{{ latestScan?.stats?.checked ?? '—' }}</strong>
        <small>不等于取得完整正文</small>
      </div>
      <div class="sm-metric sm-card">
        <span>最近扫描</span>
        <strong class="sm-metric__status">{{ scanStatusLabel(latestScan?.status || selectedWatchlist?.last_scan_status) }}</strong>
        <small>{{ timeLabel(latestScan?.finished_at || latestScan?.started_at || selectedWatchlist?.last_scan_at) }}</small>
      </div>
    </section>

    <section v-if="activeTab !== 'settings'" class="sm-card sm-sources" aria-label="当前采集源">
      <div class="sm-section-title">
        <div>
          <h2>当前采集源</h2>
          <p>三个入口使用同一搜索索引，不能当作独立佐证。</p>
        </div>
        <el-tag type="warning" effect="plain">覆盖受限</el-tag>
      </div>
      <div class="sm-source-grid">
        <div v-for="source in coverage.sources || []" :key="source.key" class="sm-source">
          <div class="sm-source__head">
            <span class="sm-source__platform">{{ source.platform === 'x' ? 'X' : 'Facebook' }}</span>
            <el-tag :type="sourceError(source.key) || latestScan?.status === 'failed' ? 'danger' : 'info'" size="small" effect="plain">
              {{ sourceStatusLabel(source.key) }}
            </el-tag>
          </div>
          <strong>{{ sourceLabel(source.key) }}</strong>
          <el-link :href="source.url" target="_blank" rel="noopener noreferrer" type="primary">打开搜索入口</el-link>
        </div>
      </div>
    </section>

    <section class="sm-card sm-workspace">
      <el-tabs v-model="activeTab">
        <el-tab-pane name="leads" :label="`监测线索${pendingCount ? ` (${pendingCount})` : ''}`">
          <div class="sm-list-toolbar">
            <el-radio-group v-model="hitFilter" size="small">
              <el-radio-button value="pending">待核验</el-radio-button>
              <el-radio-button value="all">全部结果</el-radio-button>
            </el-radio-group>
            <el-input v-model.trim="hitSearch" clearable placeholder="筛选标题或链接" class="sm-hit-search" />
            <span class="sm-muted">显示最近 {{ hits.length }} 条，上限 100 条</span>
          </div>
          <el-empty v-if="!selectedId" description="选择监测对象后查看线索" />
          <div v-else class="sm-table-wrap">
            <el-table v-loading="loading" :data="visibleHits" table-layout="fixed" empty-text="当前没有符合条件的线索">
              <el-table-column label="平台" width="92">
                <template #default="{ row }"><span class="sm-platform" :class="`sm-platform--${row.platform}`">{{ row.platform === 'x' ? 'X' : 'FB' }}</span></template>
              </el-table-column>
              <el-table-column prop="title" label="搜索标题" min-width="270" show-overflow-tooltip>
                <template #default="{ row }"><span class="sm-title">{{ row.title || '未提供标题' }}</span></template>
              </el-table-column>
              <el-table-column label="内容可见性" width="126">
                <template #default="{ row }">{{ contentStatusLabel(row.source_status) }}</template>
              </el-table-column>
              <el-table-column label="筛选结果" width="130">
                <template #default="{ row }"><el-tag :type="classificationTone(row.classification)" size="small" effect="plain">{{ classificationLabel(row.classification) }}</el-tag></template>
              </el-table-column>
              <el-table-column label="人工判断" width="116">
                <template #default="{ row }">{{ reviewLabel(row) }}</template>
              </el-table-column>
              <el-table-column label="首次发现" width="158">
                <template #default="{ row }">{{ timeLabel(row.first_seen_at) }}</template>
              </el-table-column>
              <el-table-column label="操作" width="80" fixed="right">
                <template #default="{ row }"><el-button link type="primary" @click="openHit(row)">查看</el-button></template>
              </el-table-column>
            </el-table>
          </div>
        </el-tab-pane>

        <el-tab-pane name="scans" label="扫描记录">
          <el-empty v-if="!selectedId" description="选择监测对象后查看扫描记录" />
          <div v-else class="sm-table-wrap">
            <el-table v-loading="loading" :data="scans" table-layout="fixed" empty-text="尚无扫描记录">
              <el-table-column type="expand" width="44">
                <template #default="{ row }">
                  <div class="sm-scan-detail">
                    <span>索引范围：公开搜索结果第一页</span>
                    <span>因轮次上限未补全：{{ row.stats?.skipped_due_limit ?? 0 }} 条</span>
                    <span>原帖不可访问：{{ row.stats?.unavailable_count ?? 0 }} 条</span>
                    <div v-if="row.stats?.source_errors?.length" class="sm-scan-errors">
                      <strong>来源异常</strong>
                      <p v-for="(error, index) in row.stats.source_errors" :key="index">{{ error }}</p>
                    </div>
                    <p v-if="row.stats?.error" class="sm-scan-errors">{{ row.stats.error }}</p>
                  </div>
                </template>
              </el-table-column>
              <el-table-column label="开始时间" min-width="160">
                <template #default="{ row }">{{ timeLabel(row.started_at) }}</template>
              </el-table-column>
              <el-table-column label="状态" width="150">
                <template #default="{ row }">{{ scanStatusLabel(row.status) }}</template>
              </el-table-column>
              <el-table-column label="发现 / 尝试读取" width="145">
                <template #default="{ row }">{{ row.stats?.discovered_unique ?? 0 }} / {{ row.stats?.checked ?? 0 }}</template>
              </el-table-column>
              <el-table-column label="新增" width="82">
                <template #default="{ row }">{{ row.stats?.new_hits ?? 0 }}</template>
              </el-table-column>
              <el-table-column label="候选 / 待核实" width="138">
                <template #default="{ row }">{{ row.stats?.candidate_count ?? 0 }} / {{ row.stats?.unverified_count ?? 0 }}</template>
              </el-table-column>
              <el-table-column label="来源异常" width="95">
                <template #default="{ row }">{{ row.stats?.source_errors?.length ?? 0 }}</template>
              </el-table-column>
              <el-table-column label="完成时间" min-width="160">
                <template #default="{ row }">{{ timeLabel(row.finished_at) }}</template>
              </el-table-column>
            </el-table>
          </div>
        </el-tab-pane>

        <el-tab-pane v-if="isAdmin" name="settings" :label="creating ? '新建监测对象' : '监测配置'">
          <el-form label-position="top" class="sm-config-form">
            <div class="sm-config-grid">
              <section class="sm-config-card" aria-label="监测对象配置">
                <div class="sm-config-card__head">
                  <h3>监测对象</h3>
                </div>
                <el-form-item label="对象名称"><el-input v-model.trim="form.name" maxlength="80" placeholder="如：宁德时代" /></el-form-item>
                <el-form-item label="运行状态">
                  <div class="sm-config-toggle"><el-switch v-model="form.enabled" /><span>{{ form.enabled ? '启用定时扫描' : '停用定时扫描' }}</span></div>
                </el-form-item>
              </section>
              <section class="sm-config-card" aria-label="执行计划配置">
                <div class="sm-config-card__head">
                  <h3>执行计划</h3>
                </div>
                <div class="sm-config-card__fields">
                  <el-form-item label="扫描间隔"><el-input-number v-model="form.interval_minutes" :min="60" :max="1440" :step="30" /><span class="sm-config-hint">分钟，至少 60 分钟</span></el-form-item>
                  <el-form-item label="每平台每轮尝试读取"><el-input-number v-model="form.max_posts_per_platform" :min="1" :max="30" /><span class="sm-config-hint">条公开帖子，上限 30 条</span></el-form-item>
                </div>
              </section>
              <section class="sm-config-card sm-config-card--wide" aria-label="搜索发现配置">
                <div class="sm-config-card__head">
                  <h3>搜索发现</h3>
                </div>
                <el-form-item label="搜索词组合（最多 4 行）"><el-input v-model="form.queries" type="textarea" :rows="4" placeholder="宁德时代 数据泄露&#10;宁德时代 勒索软件" /></el-form-item>
              </section>
              <section class="sm-config-card sm-config-card--wide" aria-label="本地筛选配置">
                <div class="sm-config-card__head">
                  <h3>本地筛选</h3>
                </div>
                <div class="sm-config-card__fields">
                  <el-form-item label="企业名称与别名（每行一个）"><el-input v-model="form.aliases" type="textarea" :rows="4" placeholder="宁德时代&#10;宁德时代新能源" /></el-form-item>
                  <el-form-item label="网络安全风险词（每行一个）"><el-input v-model="form.risk_terms" type="textarea" :rows="4" placeholder="数据泄露&#10;勒索软件" /></el-form-item>
                </div>
                <p class="sm-config-hint">同一条内容需同时命中别名和风险词；候选线索仍需人工核验。</p>
              </section>
            </div>
          </el-form>
          <div class="sm-config-actions">
            <el-button link type="primary" @click="fillCatlExample">填入宁德时代示例</el-button>
            <el-button type="primary" :loading="saving" @click="saveWatchlist">{{ selectedId ? '保存配置' : '创建监测对象' }}</el-button>
          </div>
        </el-tab-pane>
      </el-tabs>
    </section>

    <el-drawer v-model="hitOpen" title="帖子线索" size="min(520px, 100%)" destroy-on-close>
      <template v-if="selectedHit">
        <div class="sm-drawer-title">{{ selectedHit.title || '未提供标题' }}</div>
        <div class="sm-drawer-status">
          <el-tag :type="classificationTone(selectedHit.classification)" effect="plain">{{ classificationLabel(selectedHit.classification) }}</el-tag>
          <span>上次扫描：{{ contentStatusLabel(selectedHit.source_status) }}</span>
        </div>
        <section class="sm-preview" aria-label="公开内容预览">
          <h3>公开内容预览</h3>
          <p class="sm-muted">打开详情时重新读取公开页面；仅临时展示脱敏预览，不保存原文。</p>
          <div v-loading="previewLoading" class="sm-preview__body">
            <template v-if="preview?.text">
              <strong>{{ preview.source_status === 'source_text' ? '公开可见帖文文本' : '公开页面元数据（非全文）' }}</strong>
              <p>{{ preview.text }}</p>
              <small v-if="preview.truncated">内容较长，仅展示前 600 字符；可打开原帖核对。</small>
            </template>
            <span v-else-if="!previewLoading" class="sm-muted">{{ previewError || '原帖当前无法匿名读取，请打开原帖核对。' }}</span>
          </div>
        </section>
        <dl class="sm-details">
          <dt>平台</dt><dd>{{ selectedHit.platform === 'x' ? 'X' : 'Facebook' }}</dd>
          <dt>公开链接</dt><dd><el-link :href="selectedHit.source_url" target="_blank" rel="noopener noreferrer" type="primary">打开原帖</el-link></dd>
          <dt>发现入口</dt><dd>{{ (selectedHit.found_via || []).map(sourceLabel).join('、') || '—' }}</dd>
          <dt>命中别名</dt><dd>{{ (selectedHit.matched_aliases || []).join('、') || '—' }}</dd>
          <dt>命中风险词</dt><dd>{{ (selectedHit.matched_risks || []).join('、') || '—' }}</dd>
          <dt>首次发现</dt><dd>{{ timeLabel(selectedHit.first_seen_at) }}</dd>
          <dt>最近发现</dt><dd>{{ timeLabel(selectedHit.last_seen_at) }}</dd>
          <dt>人工判断</dt><dd>{{ reviewLabel(selectedHit) }}</dd>
          <template v-if="selectedHit.evidence_url">
            <dt>独立证据</dt><dd><el-link :href="selectedHit.evidence_url" target="_blank" rel="noopener noreferrer" type="primary">查看证据</el-link></dd>
          </template>
          <template v-if="selectedHit.review_note">
            <dt>核验备注</dt><dd>{{ selectedHit.review_note }}</dd>
          </template>
        </dl>
        <div v-if="isReviewable(selectedHit)" class="sm-review">
          <h3>人工核验</h3>
          <p>候选帖仅作为线索。选择“有独立佐证”需要提交另一来源的证据链接和核验依据。</p>
          <el-form label-position="top">
            <el-form-item label="判断">
              <el-select v-model="reviewForm.status" style="width: 100%">
                <el-option label="待核验" value="pending" />
                <el-option label="未确认关联" value="unconfirmed" />
                <el-option label="误报" value="false_positive" />
                <el-option label="有独立佐证" value="corroborated" :disabled="selectedHit.classification !== 'candidate'" />
              </el-select>
            </el-form-item>
            <el-form-item v-if="reviewForm.status === 'corroborated'" label="独立证据链接">
              <el-input v-model.trim="reviewForm.evidence_url" placeholder="企业、监管机构或可信研究来源" />
            </el-form-item>
            <el-form-item label="核验备注">
              <el-input v-model="reviewForm.note" type="textarea" :rows="3" placeholder="记录判断依据，勿粘贴凭据或敏感内容" />
            </el-form-item>
            <el-button type="primary" :loading="reviewing" @click="submitReview">保存核验</el-button>
          </el-form>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { isCurrentUserAdmin } from '@/composables/useAuth'
import { requestJson } from '@/composables/requestJson'

const isAdmin = computed(isCurrentUserAdmin)
const coverage = ref({ message: '', sources: [] })
const watchlists = ref([])
const selectedId = ref('')
const creating = ref(false)
const hits = ref([])
const scans = ref([])
const activeTab = ref('leads')
const hitFilter = ref('pending')
const hitSearch = ref('')
const loading = ref(false)
const saving = ref(false)
const scanning = ref(false)
const reviewing = ref(false)
const loadError = ref('')
const hitOpen = ref(false)
const selectedHit = ref(null)
const preview = ref(null)
const previewLoading = ref(false)
const previewError = ref('')
const form = reactive({ name: '', aliases: '', risk_terms: '', queries: '', enabled: true, interval_minutes: 120, max_posts_per_platform: 8 })
const reviewForm = reactive({ status: 'pending', evidence_url: '', note: '' })
let timer = null
let previewRequestId = 0
let selectedRequestId = 0

const sourceNames = { social_searcher_x: 'X 主搜索入口', awesome_x: 'X 补充搜索入口', awesome_facebook: 'Facebook 搜索入口' }
const selectedWatchlist = computed(() => watchlists.value.find((item) => item.id === selectedId.value) || null)
const latestScan = computed(() => scans.value[0] || null)
const pendingCount = computed(() => hits.value.filter((row) => isReviewable(row) && row.review_status === 'pending').length)
const visibleHits = computed(() => hits.value.filter((row) => {
  if (hitFilter.value === 'pending' && (!isReviewable(row) || row.review_status !== 'pending')) return false
  const needle = hitSearch.value.toLocaleLowerCase()
  return !needle || `${row.title} ${row.source_url}`.toLocaleLowerCase().includes(needle)
}))
const lines = (text) => [...new Set(String(text || '').split(/[\n,，]+/).map((item) => item.trim()).filter(Boolean))]
const isReviewable = (row) => ['candidate', 'unverified_search_hit'].includes(row?.classification)
const sourceLabel = (key) => sourceNames[key] || key
const contentStatusLabel = (value) => ({ source_text: '公开正文', public_metadata: '公开元数据', unavailable: '原帖不可访问' }[value] || '待确认')
const classificationLabel = (value) => ({ candidate: '风险候选', unverified_search_hit: '仅搜索命中', no_risk: '无风险词', not_target: '非本对象', unavailable: '无法核验' }[value] || value)
const classificationTone = (value) => ({ candidate: 'warning', unverified_search_hit: 'info', no_risk: 'success', not_target: 'info', unavailable: 'info' }[value] || 'info')
const scanStatusLabel = (value) => ({ running: '扫描中', completed_limited: '已完成 · 覆盖受限', failed: '扫描失败' }[value] || '尚未扫描')
function reviewLabel(row) {
  if (row.review_status === 'pending' && !isReviewable(row)) return '无需核验'
  return ({ pending: '待核验', unconfirmed: '未确认关联', false_positive: '误报', corroborated: '有独立佐证' }[row.review_status] || '待核验')
}
function timeLabel(value) {
  if (!value) return '—'
  const time = new Date(value)
  return Number.isNaN(time.getTime()) ? '—' : time.toLocaleString('zh-CN', { hour12: false })
}
function nextScanLabel(value) {
  if (!value) return '—'
  const time = new Date(value)
  if (Number.isNaN(time.getTime())) return '—'
  return time <= new Date() ? '已到期，等待调度' : timeLabel(value)
}
function sourceError(key) {
  return (latestScan.value?.stats?.source_errors || []).some((error) => String(error).startsWith(`${key}:`))
}
function sourceStatusLabel(key) {
  if (sourceError(key)) return '本轮异常'
  if (!latestScan.value) return '待扫描'
  if (latestScan.value.status === 'running') return '扫描中'
  return latestScan.value.status === 'failed' ? '扫描失败' : '本轮无报错'
}
function setForm(item) {
  Object.assign(form, {
    name: item?.name || '', aliases: (item?.aliases || []).join('\n'), risk_terms: (item?.risk_terms || []).join('\n'),
    queries: (item?.queries || []).join('\n'), enabled: item?.enabled ?? true,
    interval_minutes: item?.interval_minutes || 120, max_posts_per_platform: item?.max_posts_per_platform || 8,
  })
}
function fillCatlExample() {
  Object.assign(form, { name: '宁德时代', aliases: '宁德时代\nCATL', risk_terms: '数据泄露\ndata breach\n勒索软件\nransomware',
    queries: '宁德时代 数据泄露\nCATL data breach\n宁德时代 勒索软件\nCATL ransomware' })
}
function newWatchlist() {
  creating.value = true
  selectedId.value = ''
  hits.value = []
  scans.value = []
  setForm(null)
  activeTab.value = 'settings'
}
async function loadSelected() {
  const requestId = ++selectedRequestId
  const watchlistId = selectedId.value
  if (!watchlistId) return
  const base = `/api/social-monitoring/watchlists/${watchlistId}`
  const [nextHits, nextScans] = await Promise.all([requestJson(`${base}/hits`), requestJson(`${base}/scans`)])
  if (requestId !== selectedRequestId || watchlistId !== selectedId.value) return
  hits.value = nextHits
  scans.value = nextScans
}
async function refresh(silent = true) {
  if (loading.value) return
  loading.value = true
  try {
    const [items, status] = await Promise.all([
      requestJson('/api/social-monitoring/watchlists'), requestJson('/api/social-monitoring/status'),
    ])
    watchlists.value = items
    coverage.value = status
    if (!selectedId.value && items.length && !creating.value) {
      selectedId.value = items[0].id
      setForm(items[0])
    }
    if (selectedId.value && !selectedWatchlist.value) {
      selectedId.value = ''
      hits.value = []
      scans.value = []
    } else if (selectedId.value) {
      await loadSelected()
    }
    loadError.value = ''
  } catch (error) {
    loadError.value = error.message || '加载社交监测数据失败'
    if (!silent) ElMessage.error(loadError.value)
  } finally {
    loading.value = false
  }
}
async function selectWatchlist() {
  creating.value = false
  setForm(selectedWatchlist.value)
  hits.value = []
  scans.value = []
  try { await loadSelected() } catch (error) { ElMessage.error(error.message || '加载监测对象失败') }
}
async function saveWatchlist() {
  saving.value = true
  try {
    const payload = { name: form.name.trim(), aliases: lines(form.aliases), risk_terms: lines(form.risk_terms),
      queries: lines(form.queries), enabled: form.enabled, interval_minutes: form.interval_minutes,
      max_posts_per_platform: form.max_posts_per_platform }
    const item = await requestJson(selectedId.value ? `/api/social-monitoring/watchlists/${selectedId.value}` : '/api/social-monitoring/watchlists', {
      method: selectedId.value ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    })
    selectedId.value = item.id
    creating.value = false
    ElMessage.success('监测对象已保存')
    await refresh()
    activeTab.value = 'leads'
  } catch (error) {
    ElMessage.error(error.message || '保存配置失败')
  } finally {
    saving.value = false
  }
}
async function startScan() {
  scanning.value = true
  try {
    await requestJson(`/api/social-monitoring/watchlists/${selectedId.value}/scan`, { method: 'POST' })
    ElMessage.info('扫描已启动，可在扫描记录中查看进度')
    await refresh()
  } catch (error) {
    ElMessage.error(error.message || '启动扫描失败')
  } finally {
    scanning.value = false
  }
}
async function openHit(row) {
  selectedHit.value = row
  Object.assign(reviewForm, { status: row.review_status || 'pending', evidence_url: row.evidence_url || '', note: row.review_note || '' })
  hitOpen.value = true
  preview.value = null
  previewError.value = ''
  previewLoading.value = true
  const requestId = ++previewRequestId
  try {
    const result = await requestJson(`/api/social-monitoring/hits/${encodeURIComponent(row.id)}/preview`)
    if (requestId === previewRequestId) preview.value = result
  } catch (error) {
    if (requestId === previewRequestId) previewError.value = error.message || '公开内容读取失败'
  } finally {
    if (requestId === previewRequestId) previewLoading.value = false
  }
}
async function submitReview() {
  if (reviewForm.status === 'corroborated' && (!reviewForm.evidence_url.startsWith('https://') || !reviewForm.note.trim())) {
    ElMessage.warning('请填写独立的 HTTPS 证据链接和核验备注')
    return
  }
  reviewing.value = true
  try {
    const updated = await requestJson(`/api/social-monitoring/hits/${encodeURIComponent(selectedHit.value.id)}/review`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(reviewForm),
    })
    selectedHit.value = updated
    ElMessage.success('核验记录已保存')
    await refresh()
  } catch (error) {
    ElMessage.error(error.message || '保存核验失败')
  } finally {
    reviewing.value = false
  }
}
onMounted(() => {
  refresh(false)
  timer = window.setInterval(() => refresh(), 15_000)
})
onBeforeUnmount(() => { if (timer) window.clearInterval(timer) })
</script>

<style scoped>
.sm-page { display: grid; gap: 12px; min-width: 0; color: var(--fg); }
.sm-heading, .sm-control, .sm-section-title, .sm-list-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.sm-heading h1 { margin: 2px 0 3px; font-size: 23px; line-height: 1.25; }
.sm-section-title p, .sm-review p { margin: 0; color: var(--muted); font-size: 12px; line-height: 1.6; }
.sm-card { min-width: 0; border: 1px solid var(--border); border-radius: 5px; background: var(--surface); box-shadow: 0 1px 2px color-mix(in oklch, var(--fg) 5%, transparent); }
.sm-scope { display: flex; align-items: center; gap: 8px; padding: 10px 14px; border: 1px solid color-mix(in oklch, var(--warning) 25%, var(--border)); border-radius: 4px; background: color-mix(in oklch, var(--warning) 7%, var(--surface)); color: var(--muted); font-size: 12px; }
.sm-scope .el-icon { flex: none; color: var(--warning); }
.sm-control { min-height: 66px; padding: 10px 14px; }
.sm-control__select, .sm-control__actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.sm-control__select .el-select { width: 245px; }
.sm-label { color: var(--muted); font-size: 12px; font-weight: 600; }
.sm-muted { color: var(--muted); font-size: 11px; }
.sm-error { padding: 9px 12px; border: 1px solid var(--danger); border-radius: 4px; color: var(--danger); font-size: 12px; }
.sm-metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.sm-metric { display: grid; align-content: center; min-height: 99px; padding: 13px 15px; }
.sm-metric span { color: var(--muted); font-size: 11px; }
.sm-metric strong { margin: 3px 0; font-size: 25px; line-height: 1.2; font-variant-numeric: tabular-nums; }
.sm-metric strong.sm-metric__status { font-size: 15px; }
.sm-metric small { color: var(--muted); font-size: 10px; }
.sm-sources { padding: 13px 15px 15px; }
.sm-section-title { align-items: flex-start; margin-bottom: 12px; }
.sm-section-title h2 { margin: 0 0 3px; font-size: 14px; }
.sm-source-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 9px; }
.sm-source { display: grid; gap: 5px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 4px; background: var(--bg); }
.sm-source__head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.sm-source__platform { color: var(--accent); font-size: 10px; font-weight: 750; text-transform: uppercase; }
.sm-source strong { font-size: 12px; }
.sm-source .el-link { width: max-content; font-size: 11px; }
.sm-workspace { padding: 8px 14px 14px; }
.sm-workspace :deep(.el-tabs__header) { margin-bottom: 10px; }
.sm-list-toolbar { justify-content: flex-start; flex-wrap: wrap; margin-bottom: 10px; }
.sm-hit-search { width: 240px; }
.sm-list-toolbar > .sm-muted { margin-left: auto; }
.sm-table-wrap { min-width: 0; overflow-x: auto; }
.sm-table-wrap :deep(.el-table) { min-width: 800px; font-size: 11px; }
.sm-title { font-weight: 600; }
.sm-platform { display: inline-grid; min-width: 29px; height: 24px; place-items: center; border-radius: 4px; background: #1d2939; color: white; font-size: 11px; font-weight: 750; }
.sm-platform--facebook { background: #1877f2; }
.sm-scan-detail { display: grid; gap: 5px; padding: 5px 12px 10px; color: var(--muted); font-size: 11px; }
.sm-scan-errors { color: var(--danger); }
.sm-scan-errors p { margin: 3px 0; overflow-wrap: anywhere; }
.sm-config-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.sm-config-card { min-width: 0; padding: 14px; border: 1px solid var(--border); border-radius: 5px; background: var(--surface); }
.sm-config-card--wide { grid-column: 1 / -1; }
.sm-config-card__head { margin-bottom: 12px; }
.sm-config-card__head h3 { margin: 0; font-size: 14px; }
.sm-config-card__fields { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.sm-config-card :deep(.el-form-item) { min-width: 0; margin-bottom: 12px; }
.sm-config-card :deep(.el-form-item:last-child) { margin-bottom: 0; }
.sm-config-card :deep(.el-form-item__label) { font-size: 12px; font-weight: 600; }
.sm-config-card :deep(.el-input-number) { width: 100%; max-width: 185px; }
.sm-config-hint { flex: 0 0 100%; margin: 6px 0 0; color: var(--muted); font-size: 11px; line-height: 1.5; }
.sm-config-toggle { display: flex; align-items: center; gap: 10px; min-height: 32px; color: var(--muted); font-size: 11px; }
.sm-config-actions { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 14px; padding-top: 13px; border-top: 1px solid var(--border); }
.sm-drawer-title { margin-bottom: 10px; font-size: 16px; font-weight: 700; line-height: 1.5; overflow-wrap: anywhere; }
.sm-drawer-status { display: flex; align-items: center; gap: 9px; margin-bottom: 16px; color: var(--muted); font-size: 12px; }
.sm-preview { margin-bottom: 16px; }
.sm-preview h3 { margin: 0 0 5px; font-size: 14px; }
.sm-preview > p { margin: 0 0 9px; font-size: 12px; }
.sm-preview__body { min-height: 70px; padding: 12px 14px; border: 1px solid var(--border); border-radius: 5px; background: var(--bg); }
.sm-preview__body strong { font-size: 12px; }
.sm-preview__body p { margin: 8px 0; white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.6; }
.sm-preview__body small { color: var(--muted); }
.sm-details { display: grid; grid-template-columns: 88px minmax(0, 1fr); gap: 11px 12px; padding: 14px; border: 1px solid var(--border); border-radius: 4px; font-size: 12px; }
.sm-details dt { color: var(--muted); }
.sm-details dd { margin: 0; overflow-wrap: anywhere; }
.sm-review { margin-top: 22px; }
.sm-review h3 { margin: 0 0 5px; font-size: 15px; }
.sm-review p { margin-bottom: 14px; }
@media (max-width: 1050px) { .sm-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 680px) { .sm-heading, .sm-control { align-items: stretch; flex-direction: column; } .sm-control__select .el-select, .sm-hit-search { width: 100%; } .sm-metrics, .sm-source-grid, .sm-config-grid, .sm-config-card__fields { grid-template-columns: 1fr; } .sm-config-card--wide { grid-column: auto; } .sm-config-actions { align-items: stretch; flex-direction: column; } .sm-list-toolbar > .sm-muted { margin-left: 0; } }
</style>
