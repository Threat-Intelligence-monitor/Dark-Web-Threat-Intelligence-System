<template>
  <aside class="sidebar" :class="{ collapsed: shell.state.sidebarCollapsed }">
    <div class="sidebar__brand">
      <div class="sidebar__brand-mark">
        <el-icon><Monitor /></el-icon>
      </div>
      <div v-show="!shell.state.sidebarCollapsed" class="sidebar__brand-text">
        <strong>公网信息泄露监测平台</strong>
      </div>
    </div>

    <nav class="sidebar__nav">
      <template v-for="item in navTree" :key="item.key || item.path">
        <router-link
          v-if="item.type === 'item'"
          :to="item.path"
          class="sidebar__item"
          :class="{ active: isRouteActive(item.path) }"
        >
          <div class="sidebar__item-main">
            <el-icon class="sidebar__item-icon">
              <component :is="item.icon" />
            </el-icon>
            <div v-show="!shell.state.sidebarCollapsed" class="sidebar__item-text">
              <span class="sidebar__item-title">{{ item.title }}</span>
            </div>
          </div>
        </router-link>

        <div v-else class="sidebar__group" :class="{ active: isGroupActive(item) }">
          <button class="sidebar__item sidebar__item--button" type="button" @click="toggleGroup(item.key)">
            <div class="sidebar__item-main">
              <el-icon class="sidebar__item-icon">
                <component :is="item.icon" />
              </el-icon>
              <div v-show="!shell.state.sidebarCollapsed" class="sidebar__item-text">
                <span class="sidebar__item-title">{{ item.title }}</span>
              </div>
            </div>
            <div v-show="!shell.state.sidebarCollapsed" class="sidebar__group-meta">
              <el-icon class="sidebar__group-arrow">
                <component :is="isGroupOpen(item.key) ? 'ArrowDown' : 'ArrowRight'" />
              </el-icon>
            </div>
          </button>

          <div v-show="!shell.state.sidebarCollapsed && isGroupOpen(item.key)" class="sidebar__children">
            <router-link
              v-for="child in item.children"
              :key="child.path"
              :to="child.path"
              class="sidebar__child"
              :class="{ active: isRouteActive(child.path) }"
            >
              <el-icon class="sidebar__child-icon">
                <component :is="child.icon" />
              </el-icon>
              <span>{{ child.title }}</span>
            </router-link>
          </div>
        </div>
      </template>
    </nav>

    <div class="sidebar__footer">
      <div
        v-show="!shell.state.sidebarCollapsed"
        class="sidebar__version"
        :class="{ 'sidebar__version--update': versionStatus?.update_available }"
      >
        <div class="sidebar__version-head">
          <span class="sidebar__version-label">版本信息</span>
          <el-icon v-if="versionStatus?.update_available" class="sidebar__version-icon sidebar__version-icon--warning">
            <WarningFilled />
          </el-icon>
          <el-icon v-else class="sidebar__version-icon">
            <CircleCheck />
          </el-icon>
        </div>
        <strong>{{ versionTitle }}</strong>
        <p>{{ versionDescription }}</p>
        <el-button
          class="sidebar__update"
          size="small"
          :type="updateState?.status === 'failed' ? 'danger' : versionStatus?.update_available ? 'primary' : 'default'"
          :loading="updateRunning"
          :disabled="!canUpdate || versionLoading || updateRunning"
          @click="runUpdate"
        >
          <el-icon v-if="!updateRunning"><Download /></el-icon>
          <span>{{ updateButtonLabel }}</span>
        </el-button>
      </div>
      <button class="sidebar__collapse" @click="shell.toggleSidebar">
        <el-icon>
          <Fold v-if="!shell.state.sidebarCollapsed" />
          <Expand v-else />
        </el-icon>
      </button>
    </div>
  </aside>
</template>

<script setup>
import { ElMessage } from 'element-plus'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { clearAuthSession, isCurrentUserAdmin } from '@/composables/useAuth'
import { useShellLayout } from '@/composables/useShellLayout'

const route = useRoute()
const shell = useShellLayout()
const VERSION_CHECK_INTERVAL_MS = 5 * 60 * 1000
const UPDATE_POLL_INTERVAL_MS = 2000
const UPDATE_TIMEOUT_MS = 30 * 60 * 1000
const UPDATE_JOB_STORAGE_KEY = 'darkweb-update-job-id'
const versionStatus = ref(null)
const versionLoading = ref(false)
const versionError = ref('')
const updateState = ref(null)
const canUpdate = computed(isCurrentUserAdmin)
let versionTimer = null
let updatePollTimer = null
let updateStartedAt = 0
let updateRecovered = false

const navTree = [
  { type: 'item', path: '/', title: '总览', icon: 'DataLine' },
  { type: 'item', path: '/ransomware', title: '勒索情报', icon: 'Lock' },
  { type: 'item', path: '/data-leak', title: '数据泄露情报', icon: 'Document' },
  { type: 'item', path: '/vulnerability-alerts', title: '漏洞预警', icon: 'WarningFilled' },
  { type: 'item', path: '/threat-situation', title: '威胁态势', icon: 'TrendCharts' },
  { type: 'item', path: '/collector-control', title: '采集控制', icon: 'VideoPlay' },
  { type: 'item', path: '/social-monitoring', title: '社交平台监测', icon: 'ChatLineRound' },
  {
    type: 'group',
    key: 'document-exposure',
    title: '文件监测',
    icon: 'Files',
    children: [
      { path: '/document-exposure/netdisk', title: '网盘监测', icon: 'Share' },
      { path: '/document-exposure/document-library', title: '文库监测', icon: 'Files' },
      { path: '/document-exposure/code-monitoring', title: '代码监测', icon: 'Connection' },
    ],
  },
]

const expandedGroups = ref(['document-exposure'])

function isRouteActive(path) {
  if (path === '/') return route.path === '/'
  return route.path === path || route.path.startsWith(`${path}/`)
}

function isGroupActive(group) {
  if (group.key === 'document-exposure') {
    return route.path.startsWith('/document-exposure/')
  }
  return group.children?.some((child) => isRouteActive(child.path))
}

function isGroupOpen(groupKey) {
  return expandedGroups.value.includes(groupKey)
}

function toggleGroup(groupKey) {
  if (isGroupOpen(groupKey)) {
    expandedGroups.value = expandedGroups.value.filter((item) => item !== groupKey)
    return
  }
  expandedGroups.value = [...expandedGroups.value, groupKey]
}

watch(
  () => route.path,
  () => {
    for (const item of navTree) {
      if (item.type === 'group' && isGroupActive(item) && !isGroupOpen(item.key)) {
        expandedGroups.value = [...expandedGroups.value, item.key]
      }
    }
  },
  { immediate: true },
)

const versionTitle = computed(() => {
  if (updateRunning.value) return '正在更新系统'
  if (updateState.value?.status === 'failed') return '更新失败'
  if (versionLoading.value && !versionStatus.value) return '检查中'
  if (versionError.value) return '检查失败'
  if (versionStatus.value?.update_available) return '发现新版本'
  return `当前 ${currentVersionLabel.value}`
})

const versionDescription = computed(() => {
  if (updateRunning.value) return updateState.value?.message || '正在准备更新'
  if (updateState.value?.status === 'failed') return updateState.value.error || updateState.value.message || '自动更新失败'
  if (versionError.value) return versionError.value
  if (!versionStatus.value) return '正在检查版本信息'
  const channel = versionStatus.value.channel || versionStatus.value.current?.channel || 'stable'
  const latest = versionStatus.value.latest?.version || versionStatus.value.latest?.short_commit || ''
  if (versionStatus.value.update_available) {
    return `本地 ${currentVersionLabel.value} / 最新 ${latest || '-'}`
  }
  return latest ? `${channel} 通道已同步 · ${latest}` : `${channel} 通道已同步`
})

const currentVersionLabel = computed(() => (
  versionStatus.value?.current?.version
  || versionStatus.value?.current?.short_commit
  || 'local'
))

const updateRunning = computed(() => ['queued', 'running'].includes(updateState.value?.status))

const updateButtonLabel = computed(() => {
  if (!canUpdate.value) return '仅管理员可更新'
  if (updateRunning.value) return updateState.value?.message || '正在更新'
  if (updateState.value?.status === 'failed') return '重试更新'
  return versionStatus.value?.update_available ? '一键更新' : '检查并更新'
})

async function readResponseError(response) {
  try {
    const payload = await response.json()
    return payload?.detail || payload?.message || ''
  } catch {
    return ''
  }
}

async function loadVersionStatus() {
  if (versionLoading.value) return
  versionLoading.value = true
  versionError.value = ''
  try {
    const response = await fetch('/api/system/version')
    if (!response.ok) throw new Error(`版本检查失败：${response.status}`)
    const payload = await response.json()
    versionStatus.value = payload
    if (payload.status === 'error') {
      throw new Error(payload.error || payload.message || '无法检查更新服务')
    }
  } catch (error) {
    if (versionStatus.value) versionStatus.value = { ...versionStatus.value, update_available: false }
    versionError.value = error.message || '无法检查更新服务'
  } finally {
    versionLoading.value = false
  }
}

function stopUpdatePolling() {
  if (updatePollTimer) window.clearTimeout(updatePollTimer)
  updatePollTimer = null
}

function scheduleUpdatePoll(delay = UPDATE_POLL_INTERVAL_MS) {
  stopUpdatePolling()
  updatePollTimer = window.setTimeout(pollUpdateStatus, delay)
}

async function handleUpdateFinished(state, { recovered = false } = {}) {
  stopUpdatePolling()
  updateRecovered = false
  window.sessionStorage.removeItem(UPDATE_JOB_STORAGE_KEY)
  if (state.status === 'failed') {
    ElMessage.error(state.error || state.message || '自动更新失败')
    return
  }
  if (!state.updated) {
    ElMessage.success('当前已经是最新版本')
    await loadVersionStatus()
    return
  }

  if (recovered) {
    ElMessage.success('更新已完成')
    await loadVersionStatus()
    return
  }

  ElMessage.success('更新完成，服务已重启，请重新登录')
  window.setTimeout(() => {
    clearAuthSession()
    window.location.assign('/login?updated=1')
  }, 1000)
}

async function pollUpdateStatus() {
  if (!updateRunning.value) return
  if (Date.now() - updateStartedAt > UPDATE_TIMEOUT_MS) {
    updateState.value = { ...updateState.value, message: '更新耗时较长，仍在等待服务端结果' }
    updateStartedAt = Date.now()
    scheduleUpdatePoll(10_000)
    return
  }

  try {
    const response = await fetch('/api/system/update/status')
    if (response.ok) {
      const state = await response.json()
      if (state.job_id === updateState.value?.job_id) {
        updateState.value = state
        if (!['queued', 'running'].includes(state.status)) {
          await handleUpdateFinished(state, { recovered: updateRecovered })
          return
        }
      }
    }
  } catch {
    // The API is briefly unavailable while the updater restarts the service.
  }
  scheduleUpdatePoll()
}

async function runUpdate() {
  if (!canUpdate.value) {
    ElMessage.warning('仅管理员可以更新系统')
    return
  }
  if (updateRunning.value) return
  try {
    const response = await fetch('/api/system/update', { method: 'POST' })
    if (!response.ok) {
      throw new Error((await readResponseError(response)) || `更新启动失败：${response.status}`)
    }
    updateState.value = await response.json()
    updateStartedAt = Date.now()
    updateRecovered = false
    window.sessionStorage.setItem(UPDATE_JOB_STORAGE_KEY, updateState.value.job_id || '')
    if (!['queued', 'running'].includes(updateState.value.status)) {
      await handleUpdateFinished(updateState.value)
      return
    }
    ElMessage.info('更新任务已启动，服务会自动重启')
    scheduleUpdatePoll()
  } catch (error) {
    ElMessage.error(error.message || '无法启动自动更新')
  }
}

async function resumeRunningUpdate() {
  const trackedJobId = window.sessionStorage.getItem(UPDATE_JOB_STORAGE_KEY)
  if (!trackedJobId) return
  try {
    const response = await fetch('/api/system/update/status')
    if (!response.ok) return
    const state = await response.json()
    if (state.job_id !== trackedJobId) return
    updateState.value = state
    updateRecovered = true
    const startedAt = Date.parse(state.started_at || '')
    updateStartedAt = Number.isFinite(startedAt) ? startedAt : Date.now()
    if (['queued', 'running'].includes(state.status)) {
      scheduleUpdatePoll()
      return
    }
    await handleUpdateFinished(state, { recovered: true })
  } catch {
    // A status check should not block the rest of the sidebar.
  }
}

onMounted(() => {
  loadVersionStatus()
  resumeRunningUpdate()
  versionTimer = window.setInterval(loadVersionStatus, VERSION_CHECK_INTERVAL_MS)
})

onBeforeUnmount(() => {
  if (versionTimer) window.clearInterval(versionTimer)
  stopUpdatePolling()
})
</script>

<style lang="scss" scoped>
.sidebar {
  position: fixed;
  left: 0;
  top: 0;
  bottom: 0;
  z-index: 100;
  display: flex;
  flex-direction: column;
  width: var(--ti-sidebar-width);
  padding: 18px 14px;
  border-right: 1px solid rgba(87, 97, 123, 0.08);
  background: rgba(255, 255, 255, 0.98);
  backdrop-filter: blur(16px);
  overflow-x: hidden;
  transition: width 0.3s ease;
}

.sidebar.collapsed {
  width: var(--ti-sidebar-collapsed);
}

.sidebar__brand {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
  padding: 10px 8px 16px;
  border-bottom: 1px solid var(--ti-border-soft);
}

.sidebar__brand-mark {
  display: inline-flex;
  width: 42px;
  height: 42px;
  align-items: center;
  justify-content: center;
  border-radius: 16px;
  background: linear-gradient(135deg, var(--ti-primary-soft), rgba(244, 248, 255, 0.96));
  color: var(--ti-primary);
  font-size: 20px;
}

.sidebar__brand-text strong {
  color: var(--ti-text-primary);
  font-size: 16px;
}

.sidebar__nav {
  display: flex;
  flex: 1;
  flex-direction: column;
  gap: 8px;
  overflow-y: auto;
  overflow-x: hidden;
}

.sidebar__group {
  display: grid;
  gap: 8px;
}

.sidebar__item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 14px 12px;
  border: 1px solid transparent;
  border-radius: 18px;
  color: var(--ti-text-secondary);
  transition:
    transform 0.2s ease,
    background 0.2s ease,
    border-color 0.2s ease,
    color 0.2s ease;
}

.sidebar__item--button {
  width: 100%;
  background: transparent;
  cursor: pointer;
}

.sidebar__item:hover,
.sidebar__group.active > .sidebar__item {
  transform: translateX(2px);
  border-color: var(--ti-border-soft);
  background: rgba(255, 255, 255, 0.56);
  color: var(--ti-text-primary);
}

.sidebar__item.active,
.sidebar__group.active > .sidebar__item.sidebar__item--button {
  border-color: rgba(45, 93, 255, 0.16);
  background: linear-gradient(135deg, rgba(237, 242, 255, 0.96), rgba(248, 251, 255, 0.96));
  color: var(--ti-text-primary);
}

.sidebar__item-main {
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
}

.sidebar__item-icon,
.sidebar__child-icon {
  flex-shrink: 0;
  width: 38px;
  height: 38px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.84);
  color: var(--ti-accent-strong);
  font-size: 18px;
}

.sidebar__child-icon {
  width: 26px;
  height: 26px;
  border-radius: 10px;
  font-size: 14px;
  background: rgba(45, 93, 255, 0.08);
  color: var(--ti-primary);
}

.sidebar__item-title {
  color: var(--ti-text-primary);
  font-size: 14px;
  font-weight: 700;
}

.sidebar__group-meta {
  display: inline-flex;
  align-items: center;
  gap: 10px;
}

.sidebar__group-arrow {
  color: var(--ti-text-muted);
  font-size: 14px;
}

.sidebar__children {
  display: grid;
  gap: 6px;
  padding-left: 14px;
}

.sidebar__child {
  display: flex;
  align-items: center;
  gap: 10px;
  min-height: 42px;
  padding: 8px 12px;
  border-radius: 14px;
  color: var(--ti-text-secondary);
  transition:
    background 0.2s ease,
    color 0.2s ease,
    transform 0.2s ease;
}

.sidebar__child:hover,
.sidebar__child.active {
  background: rgba(45, 93, 255, 0.08);
  color: var(--ti-text-primary);
  transform: translateX(2px);
}

.sidebar__footer {
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px solid var(--ti-border-soft);
}

.sidebar__version {
  margin-bottom: 12px;
  padding: 14px;
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.62);
  border: 1px solid var(--ti-border-soft);
}

.sidebar__version--update {
  border-color: rgba(232, 128, 48, 0.32);
  background: rgba(255, 248, 238, 0.86);
}

.sidebar__version-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.sidebar__version-label {
  display: inline-block;
  margin-bottom: 6px;
  color: var(--ti-accent-strong);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.sidebar__version-icon {
  color: var(--ti-success-strong);
  font-size: 15px;
}

.sidebar__version-icon--warning {
  color: var(--ti-warning-strong);
}

.sidebar__version strong {
  display: block;
  color: var(--ti-text-primary);
  font-size: 14px;
  line-height: 1.4;
}

.sidebar__version p {
  margin-top: 4px;
  color: var(--ti-text-secondary);
  font-size: 13px;
  line-height: 1.5;
}

.sidebar__update {
  width: 100%;
  margin-top: 10px;
}

.sidebar__update :deep(.el-button__text),
.sidebar__update span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sidebar__collapse {
  width: 100%;
  height: 40px;
  border: 1px solid var(--ti-border-default);
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.72);
  color: var(--ti-text-secondary);
  cursor: pointer;
}

@media (max-width: 767px) {
  .sidebar {
    width: var(--ti-sidebar-collapsed);
    padding-left: 10px;
    padding-right: 10px;
  }

  .sidebar__brand-text,
  .sidebar__item-text,
  .sidebar__version,
  .sidebar__children {
    display: none !important;
  }

  .sidebar__item {
    justify-content: center;
    padding-left: 8px;
    padding-right: 8px;
  }
}
</style>
