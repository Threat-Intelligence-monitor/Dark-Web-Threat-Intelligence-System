import { clearAuthSession, hasModuleAccess, isCurrentUserAdmin } from '@/composables/useAuth'
import { MODULE_KEYS } from '@/config/permissions'
import { openPlatformRemoteLogin } from '@/prototype/dataRuntime'

const VERSION_CHECK_INTERVAL_MS = 5 * 60 * 1000
const UPDATE_POLL_INTERVAL_MS = 2000
const UPDATE_TIMEOUT_MS = 30 * 60 * 1000
const UPDATE_JOB_STORAGE_KEY = 'darkweb-update-job-id'

const versionRuntime = {
  version: null,
  versionError: '',
  versionLoading: false,
  update: null,
  updateStartedAt: 0,
  updateRecovered: false,
  lastCheckedAt: 0,
  lastStatusCheckedAt: 0,
  versionTimer: null,
  updatePollTimer: null,
  eventsInstalled: false,
}

function showToast(message) {
  let toast = document.querySelector('.toast')
  if (!toast) {
    toast = document.createElement('div')
    toast.className = 'toast'
    toast.setAttribute('role', 'status')
    document.body.appendChild(toast)
  }
  toast.textContent = message
  toast.classList.add('show')
  window.clearTimeout(showToast.timer)
  showToast.timer = window.setTimeout(() => toast.classList.remove('show'), 2400)
}

function closeVersionMenus() {
  document.querySelectorAll('.version-dropdown').forEach((menu) => { menu.hidden = true })
  document.querySelectorAll('.version-menu > .app-version').forEach((button) => {
    button.setAttribute('aria-expanded', 'false')
  })
}

function versionIsUpdating() {
  return ['queued', 'running'].includes(versionRuntime.update?.status)
}

function currentVersionLabel() {
  return versionRuntime.version?.current?.version
    || versionRuntime.version?.current?.short_commit
    || 'local'
}

function renderVersionMenus() {
  const updating = versionIsUpdating()
  const canUpdate = isCurrentUserAdmin()
  const updateAvailable = Boolean(versionRuntime.version?.update_available && !versionRuntime.versionError)
  const current = currentVersionLabel()
  const channel = versionRuntime.version?.channel || versionRuntime.version?.current?.channel || 'stable'
  const latest = versionRuntime.version?.latest?.version || versionRuntime.version?.latest?.short_commit || ''

  let title = `当前 ${current}`
  let description = latest ? `${channel} 通道已同步 · ${latest}` : `${channel} 通道已同步`
  let state = 'current'
  let buttonLabel = updateAvailable ? '一键更新' : '检查并更新'

  if (updating) {
    title = '正在更新系统'
    description = versionRuntime.update?.message || '正在准备更新'
    state = 'updating'
    buttonLabel = versionRuntime.update?.message || '正在更新'
  } else if (versionRuntime.versionLoading && !versionRuntime.version) {
    title = '检查中'
    description = '正在检查版本信息'
    state = 'loading'
  } else if (versionRuntime.update?.status === 'failed') {
    title = '更新失败'
    description = versionRuntime.update.error || versionRuntime.update.message || '自动更新失败'
    state = 'error'
  } else if (versionRuntime.versionError) {
    title = '检查失败'
    description = versionRuntime.versionError
    state = 'error'
  } else if (updateAvailable) {
    title = '发现新版本'
    description = `本地 ${current} / 最新 ${latest || '-'}`
    state = 'available'
  }

  document.querySelectorAll('.version-menu').forEach((wrapper) => {
    const badge = wrapper.querySelector('.app-version')
    const badgeVersion = badge?.querySelector('strong')
    if (badgeVersion) badgeVersion.textContent = current
    badge?.classList.toggle('has-update', updateAvailable)
    badge?.classList.toggle('is-busy', updating || versionRuntime.versionLoading)

    const dropdown = wrapper.querySelector('.version-dropdown')
    if (!dropdown) return
    dropdown.dataset.state = state
    const stateLabel = dropdown.querySelector('[data-version-state]')
    const titleNode = dropdown.querySelector('[data-version-title]')
    const descriptionNode = dropdown.querySelector('[data-version-description]')
    const action = dropdown.querySelector('[data-version-update]')
    if (stateLabel) {
      stateLabel.textContent = {
        available: '有更新',
        updating: '更新中',
        loading: '检查中',
        error: '异常',
        current: '已同步',
      }[state] || '已同步'
    }
    if (titleNode) titleNode.textContent = title
    if (descriptionNode) descriptionNode.textContent = description
    if (action) {
      action.textContent = canUpdate ? buttonLabel : '仅管理员可更新'
      action.disabled = !canUpdate || updating || versionRuntime.versionLoading
      action.classList.toggle('btn-primary', canUpdate && updateAvailable && !updating)
      action.classList.toggle('btn-secondary', !canUpdate || !updateAvailable || updating)
    }
  })
}

async function readVersionResponseError(response) {
  try {
    const payload = await response.json()
    return payload?.detail || payload?.message || ''
  } catch {
    return ''
  }
}

async function loadVersionStatus(force = false) {
  if (versionRuntime.versionLoading || versionIsUpdating()) return
  if (!force && versionRuntime.version && Date.now() - versionRuntime.lastCheckedAt < VERSION_CHECK_INTERVAL_MS) {
    renderVersionMenus()
    return
  }
  versionRuntime.versionLoading = true
  versionRuntime.versionError = ''
  renderVersionMenus()
  try {
    const response = await fetch('/api/system/version', { cache: 'no-store' })
    if (!response.ok) throw new Error(`版本检查失败：${response.status}`)
    versionRuntime.version = await response.json()
    if (versionRuntime.version.status === 'error') {
      versionRuntime.versionError = versionRuntime.version.error || versionRuntime.version.message || '无法检查更新服务'
    }
    versionRuntime.lastCheckedAt = Date.now()
  } catch (error) {
    versionRuntime.versionError = error.message || '无法检查更新服务'
  } finally {
    versionRuntime.versionLoading = false
    renderVersionMenus()
  }
}

function stopUpdatePolling() {
  if (versionRuntime.updatePollTimer) window.clearTimeout(versionRuntime.updatePollTimer)
  versionRuntime.updatePollTimer = null
}

function scheduleUpdatePoll(delay = UPDATE_POLL_INTERVAL_MS) {
  stopUpdatePolling()
  versionRuntime.updatePollTimer = window.setTimeout(pollUpdateStatus, delay)
}

async function handleUpdateFinished(state, { recovered = false } = {}) {
  stopUpdatePolling()
  versionRuntime.updateRecovered = false
  window.sessionStorage.removeItem(UPDATE_JOB_STORAGE_KEY)
  renderVersionMenus()
  if (state.status === 'failed') {
    showToast(state.error || state.message || '自动更新失败')
    return
  }
  if (!state.updated) {
    versionRuntime.update = null
    showToast('当前已经是最新版本')
    await loadVersionStatus(true)
    return
  }

  if (recovered) {
    showToast('更新已完成')
    await loadVersionStatus(true)
    return
  }

  showToast('更新完成，服务已重启，请重新登录')
  window.setTimeout(() => {
    clearAuthSession()
    window.location.assign('/login?updated=1')
  }, 1000)
}

async function pollUpdateStatus() {
  if (!versionIsUpdating()) return
  if (Date.now() - versionRuntime.updateStartedAt > UPDATE_TIMEOUT_MS) {
    versionRuntime.update = {
      ...versionRuntime.update,
      message: '更新耗时较长，仍在等待服务端结果',
    }
    versionRuntime.updateStartedAt = Date.now()
    renderVersionMenus()
    scheduleUpdatePoll(10_000)
    return
  }

  try {
    const response = await fetch('/api/system/update/status', { cache: 'no-store' })
    if (response.ok) {
      const state = await response.json()
      if (state.job_id === versionRuntime.update?.job_id) {
        versionRuntime.update = state
        renderVersionMenus()
        if (!['queued', 'running'].includes(state.status)) {
          await handleUpdateFinished(state, { recovered: versionRuntime.updateRecovered })
          return
        }
      }
    }
  } catch {
    // The API is briefly unavailable while the updater restarts the service.
  }
  scheduleUpdatePoll()
}

async function runSystemUpdate() {
  if (!isCurrentUserAdmin()) {
    showToast('仅管理员可以更新系统')
    return
  }
  if (versionIsUpdating() || versionRuntime.versionLoading) return
  try {
    const response = await fetch('/api/system/update', { method: 'POST' })
    if (!response.ok) {
      throw new Error((await readVersionResponseError(response)) || `更新启动失败：${response.status}`)
    }
    versionRuntime.update = await response.json()
    versionRuntime.updateStartedAt = Date.now()
    versionRuntime.updateRecovered = false
    window.sessionStorage.setItem(UPDATE_JOB_STORAGE_KEY, versionRuntime.update.job_id || '')
    renderVersionMenus()
    if (!['queued', 'running'].includes(versionRuntime.update.status)) {
      await handleUpdateFinished(versionRuntime.update)
      return
    }
    showToast('更新任务已启动，服务会自动重启')
    scheduleUpdatePoll()
  } catch (error) {
    versionRuntime.update = {
      status: 'failed',
      message: '自动更新失败',
      error: error.message || '无法启动自动更新',
    }
    renderVersionMenus()
    showToast(versionRuntime.update.error)
  }
}

async function resumeRunningUpdate() {
  if (versionIsUpdating() || Date.now() - versionRuntime.lastStatusCheckedAt < 30_000) return
  const trackedJobId = window.sessionStorage.getItem(UPDATE_JOB_STORAGE_KEY)
  if (!trackedJobId) return
  versionRuntime.lastStatusCheckedAt = Date.now()
  try {
    const response = await fetch('/api/system/update/status', { cache: 'no-store' })
    if (!response.ok) return
    const state = await response.json()
    if (state.job_id !== trackedJobId) return
    versionRuntime.update = state
    versionRuntime.updateRecovered = true
    const startedAt = Date.parse(state.started_at || '')
    versionRuntime.updateStartedAt = Number.isFinite(startedAt) ? startedAt : Date.now()
    if (['queued', 'running'].includes(state.status)) {
      renderVersionMenus()
      scheduleUpdatePoll()
      return
    }
    await handleUpdateFinished(state, { recovered: true })
  } catch {
    // A status check should not block the page.
  }
}

function setupVersionUpdate() {
  resumeRunningUpdate()
  const badges = [...document.querySelectorAll('.app-version')]
  if (!badges.length) return

  badges.forEach((badge, index) => {
    if (badge.closest('.version-menu')) return
    let button = badge
    if (badge.tagName !== 'BUTTON') {
      button = document.createElement('button')
      ;[...badge.attributes].forEach((attribute) => button.setAttribute(attribute.name, attribute.value))
      button.innerHTML = badge.innerHTML
      badge.replaceWith(button)
    }
    button.type = 'button'
    button.setAttribute('aria-label', '版本信息')
    button.setAttribute('aria-haspopup', 'dialog')
    button.setAttribute('aria-expanded', 'false')

    const wrapper = document.createElement('div')
    wrapper.className = 'version-menu'
    button.before(wrapper)
    wrapper.appendChild(button)

    const menu = document.createElement('section')
    menu.className = 'version-dropdown'
    menu.id = `version-dropdown-${index}`
    menu.setAttribute('role', 'dialog')
    menu.setAttribute('aria-label', '版本信息与自动更新')
    menu.hidden = true
    menu.innerHTML = `
      <div class="version-dropdown-head">
        <strong>版本信息</strong>
        <span class="version-state" data-version-state>检查中</span>
      </div>
      <strong class="version-title" data-version-title>检查中</strong>
      <p class="version-description" data-version-description>正在检查版本信息</p>
      <button type="button" class="btn btn-secondary version-update-action" data-version-update>检查并更新</button>`
    wrapper.appendChild(menu)
    button.setAttribute('aria-controls', menu.id)

    button.addEventListener('click', (event) => {
      event.stopPropagation()
      const willOpen = menu.hidden
      closeVersionMenus()
      document.querySelectorAll('.account-dropdown').forEach((accountMenu) => { accountMenu.hidden = true })
      document.querySelectorAll('.account-menu > .avatar').forEach((avatar) => {
        avatar.setAttribute('aria-expanded', 'false')
      })
      menu.hidden = !willOpen
      button.setAttribute('aria-expanded', String(willOpen))
      if (willOpen) loadVersionStatus()
    })
    menu.querySelector('[data-version-update]').addEventListener('click', runSystemUpdate)
  })

  if (!versionRuntime.eventsInstalled) {
    versionRuntime.eventsInstalled = true
    document.addEventListener('click', (event) => {
      if (!event.target.closest('.version-menu')) closeVersionMenus()
    })
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeVersionMenus()
    })
  }

  renderVersionMenus()
  loadVersionStatus()
  if (!versionRuntime.versionTimer) {
    versionRuntime.versionTimer = window.setInterval(loadVersionStatus, VERSION_CHECK_INTERVAL_MS)
  }
}

export function initializePrototype() {
  const $ = (selector, root = document) => root.querySelector(selector)
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)]
  const TABLE_PAGE_SIZE = 20

  function tableStateKey(table) {
    return table.id ? `dwti-table-state:${window.location.pathname}:${table.id}` : ''
  }

  function readTableState(table) {
    const key = tableStateKey(table)
    if (!key) return null
    try {
      return JSON.parse(sessionStorage.getItem(key) || 'null')
    } catch {
      sessionStorage.removeItem(key)
      return null
    }
  }

  function tableControls(table, attribute) {
    return $$(`[${attribute}]`).filter((control) => control.dataset[attribute.replace(/^data-/, '').replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] === table.id)
  }

  function saveTableState(table) {
    const key = tableStateKey(table)
    if (!key) return
    const search = tableControls(table, 'data-table-search')[0]
    sessionStorage.setItem(key, JSON.stringify({
      page: Number(table.dataset.page || 1),
      query: search?.value || '',
      activeTab: table.dataset.activeTab || 'all',
      filters: tableControls(table, 'data-filter-target').map((control) => control.value),
      dateFilters: tableControls(table, 'data-date-filter-target').map((control) => control.value),
    }))
  }

  function restoreTableState(table) {
    const state = readTableState(table)
    if (!state) return false
    table.dataset.page = String(Math.max(1, Number(state.page || 1)))
    table.dataset.query = String(state.query || '')
    table.dataset.activeTab = String(state.activeTab || 'all')
    const search = tableControls(table, 'data-table-search')[0]
    if (search) search.value = table.dataset.query
    tableControls(table, 'data-filter-target').forEach((control, index) => {
      if (state.filters?.[index] !== undefined) control.value = state.filters[index]
    })
    tableControls(table, 'data-date-filter-target').forEach((control, index) => {
      if (state.dateFilters?.[index] !== undefined) control.value = state.dateFilters[index]
    })
    $$('.tabs').filter((tabs) => tabs.dataset.target === table.id).forEach((tabs) => {
      $$('.tab', tabs).forEach((tab) => {
        const active = (tab.dataset.tab || 'all') === table.dataset.activeTab
        tab.classList.toggle('active', active)
        tab.setAttribute('aria-selected', String(active))
      })
    })
    return true
  }

  function renderSidebar() {
    const sidebar = $('.app-sidebar')
    const nav = $('.sidebar-nav', sidebar || document)
    if (!sidebar || !nav) return
    const page = document.body.dataset.prototypePage || window.location.pathname.split('/').pop() || 'dashboard.html'
    const detailParent = {
      'event-detail.html': { page: 'intelligence.html' },
      'vulnerability-detail.html': { page: 'vulnerabilities.html' },
      'ransomware-detail.html': { page: 'ransomware.html' },
      'data-leak-detail.html': { page: 'data-leak.html' },
      'netdisk-detail.html': { page: 'monitoring.html', source: 'netdisk' },
      'library-detail.html': { page: 'monitoring.html', source: 'library' },
      'code-detail.html': { page: 'monitoring.html', source: 'code' },
      'collector-run-detail.html': { page: 'collector-failures.html' }
    }[page]
    const activePage = detailParent?.page || page
    const requestedSource = document.body.dataset.prototypeSource || new URLSearchParams(window.location.search).get('source')
    const source = detailParent?.source || (activePage === 'monitoring.html' && !['netdisk', 'library', 'code'].includes(requestedSource)
      ? 'netdisk'
      : (requestedSource || ''))
    const active = (file, query = '') => activePage === file && (!query || source === query) ? ' active' : ''
    const icons = {
      overview: '<svg viewBox="0 0 24 24" fill="none"><path d="M4 13h6V4H4v9Zm10 7h6V11h-6v9ZM4 20h6v-3H4v3Zm10-13h6V4h-6v3Z"/></svg>',
      intelligence: '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2.5"/><path d="M12 2v3m0 14v3M2 12h3m14 0h3m-3-7-2 2M7 17l-2 2"/></svg>',
      exposure: '<svg viewBox="0 0 24 24" fill="none"><rect x="3" y="4" width="18" height="14" rx="2"/><path d="M6 12h3l2-4 3 8 2-4h2M9 21h6"/></svg>',
      collect: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 20V10m-4 10h8M8 8a5 5 0 0 1 8 0M5 5a9 9 0 0 1 14 0"/><circle cx="12" cy="7" r="2"/></svg>',
      settings: '<svg viewBox="0 0 24 24" fill="none"><path d="M4 6h7m4 0h5M4 12h3m4 0h9M4 18h9m4 0h3"/><circle cx="13" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="15" cy="18" r="2"/></svg>'
    }
    const icon = (name) => `<span class="nav-icon" aria-hidden="true">${icons[name]}</span>`

    const brand = $('.brand', sidebar)
    if (brand) brand.innerHTML = `<span class="brand-mark" aria-hidden="true"><img src="/assets/xuanjian-mark.svg?v=8" alt=""></span><span class="brand-copy"><strong>玄鉴</strong><span>XUANJIAN INTELLIGENCE</span></span>`

    const navLink = (path, label, activeClass = '') => (
      `<a class="nav-link sub${activeClass}" href="${path}">${label}</a>`
    )
    const navGroup = (title, iconName, links, extraTitle = '') => links.length ? `
      <div class="nav-group">
        <div class="nav-group-title">${icon(iconName)}${extraTitle}<span>${title}</span></div>
        <div class="nav-group-items">${links.join('')}</div>
      </div>` : ''
    const currentPath = window.location.pathname
    const activePath = (path) => currentPath === path || currentPath.startsWith(`${path}/`) ? ' active' : ''
    const threatLinks = [
      hasModuleAccess(MODULE_KEYS.INTELLIGENCE_SEARCH) && navLink('/intelligence', '情报检索', active('intelligence.html')),
      hasModuleAccess(MODULE_KEYS.RANSOMWARE) && navLink('/ransomware', '勒索情报', active('ransomware.html')),
      hasModuleAccess(MODULE_KEYS.DATA_LEAK) && navLink('/data-leak', '数据泄露情报', active('data-leak.html')),
      hasModuleAccess(MODULE_KEYS.VULNERABILITY_ALERTS) && navLink('/vulnerability-alerts', '漏洞预警', active('vulnerabilities.html')),
    ].filter(Boolean)
    const exposureLinks = hasModuleAccess(MODULE_KEYS.FILE_MONITORING) ? [
      navLink('/document-exposure/netdisk', '网盘监测', active('monitoring.html', 'netdisk')),
      navLink('/document-exposure/document-library', '文库监测', active('monitoring.html', 'library')),
      navLink('/document-exposure/code-monitoring', '代码监测', active('monitoring.html', 'code')),
    ] : []
    const collectorLinks = hasModuleAccess(MODULE_KEYS.COLLECTOR_CONTROL) ? [
      navLink('/collector-control/sites', '站点管理', active('collector-sites.html')),
      navLink('/collector-control/sync', '同步中心', active('collector-sync.html')),
      navLink('/collector-control/runtime', '运行环境', active('collector-runtime.html')),
      `<a class="nav-link sub${active('collector-failures.html')}" href="/collector-control/failures"><span>任务列表</span><span class="nav-alert-count num" data-task-nav-count hidden>0</span></a>`,
    ] : []
    const systemLinks = [
      hasModuleAccess(MODULE_KEYS.FILE_MONITORING) && navLink('/settings', '监测配置', active('settings.html')),
      isCurrentUserAdmin() && navLink('/settings/data-migration', '数据迁移', active('data-migration.html')),
      isCurrentUserAdmin() && navLink('/account-management', '账号管理', activePath('/account-management')),
    ].filter(Boolean)
    nav.innerHTML = [
      navGroup('威胁概况', 'overview', [navLink('/', '总览', active('dashboard.html'))]),
      navGroup('威胁情报', 'intelligence', threatLinks),
      navGroup('暴露监测', 'exposure', exposureLinks),
      navGroup(
        '采集运营',
        'collect',
        collectorLinks,
        '<span class="nav-module-alert" data-task-nav-alert aria-label="存在失败任务" hidden></span>',
      ),
      navGroup('配置中心', 'settings', systemLinks),
    ].join('')

    const footer = $('.sidebar-footer', sidebar)
    if (footer) footer.innerHTML = '<div class="sidebar-status"><i></i><span>监测服务运行中</span></div>'
  }

  function accountName() {
    try {
      const user = JSON.parse(localStorage.getItem('dwti-current-user') || 'null')
      return user?.username || user?.display_name || '个人用户'
    } catch {
      return '个人用户'
    }
  }

  function closeAccountMenus() {
    $$('.account-dropdown').forEach((menu) => { menu.hidden = true })
    $$('.account-menu > .avatar').forEach((button) => button.setAttribute('aria-expanded', 'false'))
  }

  function ensurePasswordDialog() {
    let overlay = $('[data-account-password-overlay]')
    if (overlay) return overlay
    overlay = document.createElement('div')
    overlay.className = 'account-dialog-overlay'
    overlay.dataset.accountPasswordOverlay = ''
    overlay.hidden = true
    overlay.innerHTML = `
      <section class="account-password-dialog" role="dialog" aria-modal="true" aria-labelledby="account-password-title">
        <header>
          <h2 id="account-password-title">修改密码</h2>
          <button type="button" class="account-dialog-close" aria-label="关闭">×</button>
        </header>
        <form data-account-password-form>
          <label>当前密码<input name="current_password" type="password" autocomplete="current-password" required></label>
          <label>新密码<input name="new_password" type="password" autocomplete="new-password" minlength="6" required></label>
          <label>确认新密码<input name="confirm_password" type="password" autocomplete="new-password" minlength="6" required></label>
          <p class="account-password-error" data-account-password-error role="alert"></p>
          <div class="account-dialog-actions">
            <button type="button" class="btn btn-secondary" data-account-password-cancel>取消</button>
            <button type="submit" class="btn btn-primary">保存</button>
          </div>
        </form>
      </section>`
    document.body.appendChild(overlay)

    const form = $('[data-account-password-form]', overlay)
    const error = $('[data-account-password-error]', overlay)
    const close = () => {
      overlay.hidden = true
      form.reset()
      error.textContent = ''
    }
    $('.account-dialog-close', overlay).addEventListener('click', close)
    $('[data-account-password-cancel]', overlay).addEventListener('click', close)
    overlay.addEventListener('click', (event) => {
      if (event.target === overlay) close()
    })
    form.addEventListener('submit', async (event) => {
      event.preventDefault()
      const currentPassword = form.elements.current_password.value
      const newPassword = form.elements.new_password.value
      const confirmPassword = form.elements.confirm_password.value
      if (newPassword.length < 6) {
        error.textContent = '新密码至少需要 6 个字符'
        return
      }
      if (newPassword !== confirmPassword) {
        error.textContent = '两次输入的新密码不一致'
        return
      }
      const submit = $('button[type="submit"]', form)
      submit.disabled = true
      error.textContent = ''
      try {
        const response = await fetch('/api/auth/change-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
        })
        if (!response.ok) {
          let message = '密码修改失败'
          try {
            const payload = await response.json()
            message = payload.detail || payload.message || message
          } catch {}
          throw new Error(message)
        }
        close()
        showToast('密码修改成功')
      } catch (passwordError) {
        error.textContent = passwordError.message || '密码修改失败'
      } finally {
        submit.disabled = false
      }
    })
    return overlay
  }

  function setupAccountMenu() {
    const avatars = $$('.avatar')
    if (!avatars.length) return
    const passwordDialog = ensurePasswordDialog()
    avatars.forEach((avatar, index) => {
      if (avatar.closest('.account-menu')) return
      let button = avatar
      if (avatar.tagName !== 'BUTTON') {
        button = document.createElement('button')
        ;[...avatar.attributes].forEach((attribute) => button.setAttribute(attribute.name, attribute.value))
        button.type = 'button'
        button.textContent = avatar.textContent
        avatar.replaceWith(button)
      }
      button.type = 'button'
      button.textContent = accountName()
      button.setAttribute('aria-label', '个人账户')
      button.setAttribute('aria-haspopup', 'menu')
      button.setAttribute('aria-expanded', 'false')

      const wrapper = document.createElement('div')
      wrapper.className = 'account-menu'
      button.before(wrapper)
      wrapper.appendChild(button)

      const menu = document.createElement('div')
      menu.className = 'account-dropdown'
      menu.id = `account-dropdown-${index}`
      menu.setAttribute('role', 'menu')
      menu.hidden = true
      menu.innerHTML = `
        <strong class="account-dropdown-name"></strong>
        <button type="button" class="account-dropdown-action" role="menuitem" data-account-action="change-password">
          <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10" width="14" height="11" rx="1.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
          <span>修改密码</span>
        </button>
        <button type="button" class="account-dropdown-action" role="menuitem" data-account-action="logout">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13 5H5v14h8M16 8l4 4-4 4m4-4H9"/></svg>
          <span>退出</span>
        </button>`
      $('.account-dropdown-name', menu).textContent = accountName()
      wrapper.appendChild(menu)
      button.setAttribute('aria-controls', menu.id)

      button.addEventListener('click', (event) => {
        event.stopPropagation()
        const willOpen = menu.hidden
        closeVersionMenus()
        closeAccountMenus()
        menu.hidden = !willOpen
        button.setAttribute('aria-expanded', String(willOpen))
      })
      $('[data-account-action="change-password"]', menu).addEventListener('click', () => {
        closeAccountMenus()
        passwordDialog.hidden = false
        $('input[name="current_password"]', passwordDialog)?.focus()
      })
      $('[data-account-action="logout"]', menu).addEventListener('click', async (event) => {
        const logoutButton = event.currentTarget
        logoutButton.disabled = true
        try {
          await fetch('/api/auth/logout', { method: 'POST' })
        } catch {}
        clearAuthSession()
        window.location.assign('/login')
      })
    })

    if (!document.documentElement.dataset.accountMenuEvents) {
      document.documentElement.dataset.accountMenuEvents = 'true'
      document.addEventListener('click', (event) => {
        if (!event.target.closest('.account-menu')) closeAccountMenus()
      })
      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
          closeAccountMenus()
          const overlay = $('[data-account-password-overlay]')
          if (overlay && !overlay.hidden) $('.account-dialog-close', overlay)?.click()
        }
      })
    }
  }

  function setupSidebar() {
    const shell = $('.app-shell')
    if (!shell) return
    const sidebar = $('.app-sidebar', shell)
    const toggles = $$('[data-sidebar-toggle]')
    const mobile = window.matchMedia('(max-width: 900px)')
    const close = () => shell.classList.remove('sidebar-open')
    const updateToggleState = () => {
      const expanded = mobile.matches && shell.classList.contains('sidebar-open')
      toggles.forEach((button) => {
        button.setAttribute('aria-controls', sidebar?.id || 'app-sidebar')
        button.setAttribute('aria-expanded', String(expanded))
        button.setAttribute('aria-label', expanded ? '收起导航' : '展开导航')
        if (button.classList.contains('menu-button')) {
          button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"/></svg>'
        }
      })
    }
    const applyMode = () => {
      if (sidebar && !sidebar.id) sidebar.id = 'app-sidebar'
      if (mobile.matches) {
        shell.classList.remove('sidebar-collapsed')
      } else {
        close()
        shell.classList.add('sidebar-collapsed')
      }
      updateToggleState()
    }
    toggles.forEach((button) => {
      button.addEventListener('click', () => {
        if (!mobile.matches) return
        shell.classList.toggle('sidebar-open')
        updateToggleState()
      })
    })
    $('.sidebar-backdrop')?.addEventListener('click', close)
    $$('.app-sidebar a').forEach((link) => link.addEventListener('click', close))
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        close()
        updateToggleState()
      }
    })
    mobile.addEventListener('change', applyMode)
    applyMode()
  }

  function rowMatches(row, table) {
    const query = String(table.dataset.query || '').trim().toLowerCase()
    const controlText = $$('input, select, textarea', row).map((control) => control.value).join(' ')
    if (query && !`${row.textContent} ${controlText}`.toLowerCase().includes(query)) return false

    const activeTab = table.dataset.activeTab || 'all'
    if (activeTab !== 'all') {
      const tabValue = row.dataset.category || row.dataset.source || row.dataset.type || ''
      if (tabValue !== activeTab) return false
    }

    for (const select of $$(`[data-filter-target="${table.id}"], [data-filter-linked-target~="${table.id}"]`)) {
      if (!select.value) continue
      const key = select.dataset.filterKey
      if (String(row.dataset[key] || '') !== select.value) return false
    }

    const dateFilter = $(`[data-date-filter-target="${table.id}"]`)
    if (dateFilter?.value) {
      const discoveredAt = Date.parse(row.dataset.discoveredAt || '')
      const referenceTime = Number(table.dataset.discoveryReference)
      const range = Number(dateFilter.value) * 24 * 60 * 60 * 1000
      if (!Number.isFinite(discoveredAt) || referenceTime - discoveredAt > range) return false
    }
    return true
  }

  function ensureTablePagination(table) {
    let pagination = document.querySelector(`[data-pagination-for="${table.id}"]`)
    if (pagination) return pagination

    pagination = document.createElement('footer')
    pagination.className = 'pagination table-pagination'
    pagination.dataset.paginationFor = table.id
    pagination.setAttribute('aria-label', '列表分页')
    pagination.innerHTML = `
      <span class="table-pagination-summary" aria-live="polite"></span>
      <div class="table-pagination-actions">
        <button type="button" data-page-action="first" aria-label="第一页">«</button>
        <button type="button" data-page-action="previous" aria-label="上一页">‹</button>
        <span class="table-pagination-current" aria-live="polite"><input type="number" min="1" value="1" data-page-input aria-label="跳转页码"> / <span data-page-count>1</span> 页</span>
        <button type="button" data-page-action="next" aria-label="下一页">›</button>
        <button type="button" data-page-action="last" aria-label="最后一页">»</button>
      </div>`

    const empty = document.querySelector(`[data-table-empty="${table.id}"]`)
    if (empty) empty.insertAdjacentElement('afterend', pagination)
    else table.parentElement?.insertAdjacentElement('afterend', pagination)

    pagination.addEventListener('click', (event) => {
      const button = event.target.closest('[data-page-action]')
      if (!button || button.disabled) return
      const action = button.dataset.pageAction
      const currentPage = Math.max(1, Number(table.dataset.serverPage || table.dataset.page || 1))
      const pageCount = Math.max(1, Number(table.dataset.serverPageCount || table.dataset.paginationPageCount || 1))
      const targetPage = action === 'first'
        ? 1
        : action === 'last'
          ? pageCount
          : currentPage + (action === 'next' ? 1 : -1)
      if (table.dataset.serverPagination === 'true') {
        table.dispatchEvent(new CustomEvent('prototype:server-page', {
          detail: { page: targetPage },
        }))
        return
      }
      table.dataset.page = String(Math.max(1, targetPage))
      refreshTable(table)
      saveTableState(table)
    })
    pagination.addEventListener('change', (event) => {
      const input = event.target.closest('[data-page-input]')
      if (!input) return
      const pageCount = Math.max(1, Number(table.dataset.serverPageCount || table.dataset.paginationPageCount || 1))
      const targetPage = Math.min(pageCount, Math.max(1, Number(input.value || 1)))
      if (table.dataset.serverPagination === 'true') {
        table.dispatchEvent(new CustomEvent('prototype:server-page', { detail: { page: targetPage } }))
        return
      }
      table.dataset.page = String(targetPage)
      refreshTable(table)
      saveTableState(table)
    })
    return pagination
  }

  function updateTablePagination(table, total, page, pageCount, pageSize = TABLE_PAGE_SIZE) {
    const pagination = ensureTablePagination(table)
    if (!pagination) return
    pagination.hidden = total === 0

    const start = total ? (page - 1) * pageSize + 1 : 0
    const end = Math.min(page * pageSize, total)
    $('.table-pagination-summary', pagination).textContent = `第 ${start}–${end} 条，共 ${total} 条`
    table.dataset.paginationPageCount = String(pageCount)
    const pageInput = $('[data-page-input]', pagination)
    if (pageInput) {
      pageInput.value = String(page)
      pageInput.max = String(pageCount)
    }
    $('[data-page-count]', pagination).textContent = String(pageCount)

    const first = $('[data-page-action="first"]', pagination)
    const previous = $('[data-page-action="previous"]', pagination)
    const next = $('[data-page-action="next"]', pagination)
    const last = $('[data-page-action="last"]', pagination)
    first.disabled = page <= 1
    previous.disabled = page <= 1
    next.disabled = page >= pageCount
    last.disabled = page >= pageCount
  }

  function refreshTable(table) {
    const rows = $$('tbody tr:not([data-table-detail-row]), [data-table-row]:not([data-table-detail-row])', table)
    if (table.dataset.serverPagination === 'true') {
      const total = Math.max(0, Number(table.dataset.serverTotal || 0))
      const page = Math.max(1, Number(table.dataset.serverPage || 1))
      const pageSize = Math.max(1, Number(table.dataset.serverPageSize || TABLE_PAGE_SIZE))
      const pageCount = Math.max(1, Number(table.dataset.serverPageCount || 1))
      rows.forEach((row) => { row.hidden = false })
      const empty = document.querySelector(`[data-table-empty="${table.id}"]`)
      if (empty) empty.style.display = rows.length ? 'none' : 'block'
      updateTablePagination(table, total, page, pageCount, pageSize)
      return
    }
    const discoveredTimes = rows
      .map((row) => Date.parse(row.dataset.discoveredAt || ''))
      .filter(Number.isFinite)
    table.dataset.discoveryReference = String(discoveredTimes.length ? Math.max(...discoveredTimes) : Date.now())
    const matches = rows.filter((row) => rowMatches(row, table))
    const pageCount = Math.max(1, Math.ceil(matches.length / TABLE_PAGE_SIZE))
    const page = Math.min(pageCount, Math.max(1, Number(table.dataset.page || 1)))
    const pageRows = new Set(matches.slice((page - 1) * TABLE_PAGE_SIZE, page * TABLE_PAGE_SIZE))
    table.dataset.page = String(page)

    rows.forEach((row) => {
      row.hidden = !pageRows.has(row)
    })
    $$('[data-table-detail-row]', table).forEach((detailRow) => {
      const summaryRow = detailRow.previousElementSibling
      detailRow.hidden = !summaryRow || summaryRow.hidden || summaryRow.dataset.expanded !== 'true'
    })
    $$(`[data-table-count="${table.id}"]`).forEach((count) => { count.textContent = String(matches.length) })
    const empty = document.querySelector(`[data-table-empty="${table.id}"]`)
    if (empty) empty.style.display = matches.length ? 'none' : 'block'
    updateTablePagination(table, matches.length, page, pageCount)
  }

  function setupTables() {
    $$('[data-table-search]').forEach((input) => {
      const table = document.getElementById(input.dataset.tableSearch)
      if (!table) return
      if (table.dataset.serverPagination === 'true') return
      input.addEventListener('input', () => {
        table.dataset.query = input.value
        table.dataset.page = '1'
        refreshTable(table)
        saveTableState(table)
      })
    })
    $$('[data-filter-target]').forEach((select) => {
      const table = document.getElementById(select.dataset.filterTarget)
      if (!table) return
      if (table.dataset.serverPagination === 'true') return
      select.addEventListener('change', () => {
        const linkedTables = String(select.dataset.filterLinkedTarget || '')
          .split(/\s+/)
          .map((id) => document.getElementById(id))
          .filter(Boolean)
        for (const targetTable of new Set([table, ...linkedTables])) {
          targetTable.dataset.page = '1'
          refreshTable(targetTable)
        }
        saveTableState(table)
      })
    })
    $$('[data-date-filter-target]').forEach((select) => {
      const table = document.getElementById(select.dataset.dateFilterTarget)
      if (!table) return
      if (table.dataset.serverPagination === 'true') return
      select.addEventListener('change', () => {
        table.dataset.page = '1'
        refreshTable(table)
        saveTableState(table)
      })
    })
    const statefulTables = new Set($$('[data-table]'))
    $$('[data-table-search], [data-filter-target], [data-date-filter-target]').forEach((control) => {
      const targetId = control.dataset.tableSearch || control.dataset.filterTarget || control.dataset.dateFilterTarget
      const table = document.getElementById(targetId || '')
      if (table) statefulTables.add(table)
    })
    statefulTables.forEach((table) => {
      if (table.dataset.serverPagination === 'true') {
        if (table.matches('[data-table]')) {
          table.addEventListener('prototype:rows-updated', () => refreshTable(table))
        }
        refreshTable(table)
        return
      }
      const restored = restoreTableState(table)
      if (table.matches('[data-table]')) {
        table.addEventListener('prototype:rows-updated', () => {
          refreshTable(table)
          saveTableState(table)
        })
      }
      if (!restored) refreshTable(table)
    })
  }

  function setupTabs() {
    $$('.tabs').forEach((tabs) => {
      const target = document.getElementById(tabs.dataset.target || '')
      const table = target?.matches('[data-table]') ? target : null
      $$('.tab', tabs).forEach((tab) => {
        tab.addEventListener('click', () => {
          $$('.tab', tabs).forEach((item) => {
            const active = item === tab
            item.classList.toggle('active', active)
            item.setAttribute('aria-selected', String(active))
          })
          if (table) {
            table.dataset.activeTab = tab.dataset.tab || 'all'
            if (table.dataset.serverPagination === 'true') {
              table.dispatchEvent(new CustomEvent('prototype:server-filter', {
                detail: { eventType: table.dataset.activeTab },
              }))
              return
            }
            refreshTable(table)
            saveTableState(table)
          }
          const panels = tabs.dataset.panels
          if (panels) {
            $$(`[data-panel-group="${panels}"]`).forEach((panel) => {
              panel.hidden = panel.dataset.panel !== tab.dataset.tab
            })
          }
        })
      })
    })

    const requestedSettingsTab = new URLSearchParams(window.location.search).get('tab')
    const settingsTabAliases = { 'code-terms': 'rules' }
    const resolvedSettingsTab = settingsTabAliases[requestedSettingsTab] || requestedSettingsTab
    const settingsTabs = ['objects', 'rules', 'notifications']
    if (settingsTabs.includes(resolvedSettingsTab)) {
      $(`.settings-tabs .tab[data-tab="${resolvedSettingsTab}"]`)?.click()
    }
    const requestedCollectorSitesTab = new URLSearchParams(window.location.search).get('view')
    if (['sites', 'access'].includes(requestedCollectorSitesTab)) {
      $(`.collector-site-tabs .tab[data-tab="${requestedCollectorSitesTab}"]`)?.click()
    }
    $$('[data-collector-sites-tab]').forEach((button) => {
      button.addEventListener('click', () => {
        $(`.collector-site-tabs .tab[data-tab="${button.dataset.collectorSitesTab}"]`)?.click()
        const moduleFilter = $('[data-filter-target="collector-health-table"][data-filter-key="module"]')
        if (moduleFilter && button.dataset.settingsModule) {
          moduleFilter.value = button.dataset.settingsModule
          moduleFilter.dispatchEvent(new Event('change'))
        }
        window.scrollTo({ top: 0, behavior: 'smooth' })
      })
    })
    const requestedSettingsModule = new URLSearchParams(window.location.search).get('module')
    const settingsModule = ['netdisk', 'library'].includes(requestedSettingsModule) ? requestedSettingsModule : ''
    if (settingsModule) {
      document.body.dataset.settingsModule = settingsModule
      $$('[data-settings-module-card]').forEach((card) => {
        card.classList.toggle('is-targeted', card.dataset.settingsModuleCard === settingsModule)
      })
      const moduleFilter = $('[data-filter-target="collector-health-table"][data-filter-key="module"]')
      if (moduleFilter) {
        moduleFilter.value = settingsModule
        moduleFilter.dispatchEvent(new Event('change'))
      }
    }

    const requestedSource = document.body.dataset.prototypeSource || new URLSearchParams(window.location.search).get('source')
    const source = ['netdisk', 'library', 'code'].includes(requestedSource) ? requestedSource : (document.body.classList.contains('page-monitoring') ? 'netdisk' : '')
    if (source) {
      $$('[data-panel-group="monitoring-surface"]').forEach((panel) => {
        panel.hidden = panel.dataset.panel !== source
      })
      const pageTitle = {
        netdisk: '网盘监测',
        library: '文库监测',
        code: '代码监测'
      }[source]
      document.title = `${pageTitle} · 玄鉴`
      const tab = $(`.tab[data-tab="${source}"]`)
      tab?.click()
    }
  }

  async function setupCodeConfigStatus() {
    const link = $('[data-code-config-status]')
    if (!link) return
    const label = $('span', link)
    try {
      const responses = await Promise.all([
        fetch('/api/code-monitoring/github-app'),
        fetch('/api/platform-sessions?module=code_monitoring'),
        fetch('/api/code-monitoring/watchlists')
      ])
      if (responses.some((response) => !response.ok)) throw new Error('status unavailable')
      const [githubApp, sessionsPayload, watchlistsPayload] = await Promise.all(responses.map((response) => response.json()))
      const sessions = Array.isArray(sessionsPayload) ? sessionsPayload : (sessionsPayload.sessions || sessionsPayload.items || [])
      const watchlists = Array.isArray(watchlistsPayload) ? watchlistsPayload : (watchlistsPayload.watchlists || watchlistsPayload.items || [])
      const platformReady = Boolean(githubApp.configured) || sessions.some((item) => item.status === 'valid')
      const objectReady = watchlists.some((item) => item.enabled !== false && Array.isArray(item.terms) && item.terms.some((term) => term.enabled !== false && String(term.term || '').trim()))
      const complete = platformReady && objectReady
      link.classList.toggle('is-complete', complete)
      link.classList.toggle('is-missing', !complete)
      label.textContent = complete ? '配置完整' : '配置缺失'
      link.href = complete ? '/settings?tab=objects' : `/settings?tab=${platformReady ? 'objects' : 'access'}`
    } catch {
      label.textContent = '配置状态：待检查'
    }
  }

  function setupActions() {
    const hasRuntimeAction = (element) => Object.keys(element.dataset).some((key) => key.startsWith('runtime'))
    $$('[data-toast]').forEach((button) => {
      button.addEventListener('click', () => {
        if (!hasRuntimeAction(button)) showToast(button.dataset.toast)
      })
    })
    $$('[data-action="scan"]').forEach((button) => {
      button.addEventListener('click', () => {
        if (button.dataset.busy === '1') return
        button.dataset.busy = '1'
        const label = button.textContent
        button.textContent = '正在创建任务…'
        button.disabled = true
        window.setTimeout(() => {
          button.textContent = label
          button.disabled = false
          button.dataset.busy = '0'
          showToast('扫描任务已创建，可在“扫描任务”中查看进度')
        }, 900)
      })
    })
    $$('[data-task-toggle]').forEach((button) => {
      button.addEventListener('click', () => {
        const row = button.closest('.task-row')
        const status = $('.status-dot', row)
        const running = status?.classList.toggle('running')
        status?.classList.toggle('stopped', !running)
        if (status) status.textContent = running ? '运行中' : '已停止'
        button.textContent = running ? '停止' : '启动'
        button.classList.toggle('btn-danger', running)
        button.classList.toggle('btn-secondary', !running)
        showToast(running ? '任务已启动' : '任务已停止')
      })
    })
    $$('[data-copy]').forEach((button) => {
      button.addEventListener('click', async () => {
        if (hasRuntimeAction(button)) return
        const text = button.dataset.copy || ''
        try {
          await navigator.clipboard.writeText(text)
          showToast('已复制到剪贴板')
        } catch {
          showToast('复制失败，请手动选择文本')
        }
      })
    })
    $$('[data-disposition]').forEach((button) => {
      button.addEventListener('click', () => {
        if (hasRuntimeAction(button)) return
        $$('[data-disposition]').forEach((item) => {
          item.classList.remove('btn-primary')
          item.classList.add('btn-secondary')
        })
        button.classList.remove('btn-secondary')
        button.classList.add('btn-primary')
        const state = $('[data-review-state]')
        if (state) state.textContent = button.dataset.disposition
        showToast(`处置状态已更新为“${button.dataset.disposition}”`)
      })
    })
  }

  function navigateSearch(target) {
    const link = document.createElement('a')
    link.href = target
    link.hidden = true
    document.querySelector('.prototype-screen').appendChild(link)
    link.click()
    link.remove()
  }

  function setupGlobalSearch() {
    $$('[data-global-search]').forEach((input) => {
      input.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter') return
        const query = input.value.trim()
        if (query) navigateSearch(`/intelligence?q=${encodeURIComponent(query)}`)
      })
    })
    const query = new URLSearchParams(window.location.search).get('q')
    const tableSearch = $('[data-table-search]')
    if (query && tableSearch) {
      tableSearch.value = query
      tableSearch.dispatchEvent(new Event('input'))
    }
  }

  function setupIntelligenceSearch() {
    const form = $('[data-intel-search-form]')
    const results = $('#intel-results')
    if (!form || !results) return

    const input = $('[data-table-search="intel-results"]', form)
    const advanced = $('[data-intel-advanced]')
    const advancedPanel = $('#intel-advanced-panel')
    const sort = $('[data-intel-sort]')
    const reduceMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

    const moveToResults = () => {
      const section = $('.intelligence-results')
      if (!section) return
      window.scrollTo({ top: Math.max(0, section.offsetTop - 66), behavior: reduceMotion ? 'auto' : 'smooth' })
    }

    const openServerSearch = (value) => {
      const query = String(value || '').trim()
      const url = new URL(window.location.href)
      if (query) url.searchParams.set('q', query)
      else url.searchParams.delete('q')
      url.searchParams.delete('page')
      const target = `${url.pathname}${url.search}`
      if (`${window.location.pathname}${window.location.search}` === target) {
        results.dispatchEvent(new Event('prototype:server-refresh'))
        moveToResults()
        return
      }
      navigateSearch(target)
    }

    form.addEventListener('submit', (event) => {
      event.preventDefault()
      openServerSearch(input?.value)
    })

    $$('[data-intel-hot]').forEach((button) => {
      button.addEventListener('click', () => {
        if (!input) return
        input.value = button.dataset.intelHot || ''
        openServerSearch(input.value)
      })
    })

    advanced?.addEventListener('click', () => {
      if (!advancedPanel) return
      const open = advancedPanel.hidden
      advancedPanel.hidden = !open
      advanced.setAttribute('aria-expanded', String(open))
    })

    $('[data-intel-reset]')?.addEventListener('click', () => {
      if (results.dataset.serverPagination === 'true') {
        navigateSearch('/intelligence')
        return
      }
      if (new URLSearchParams(window.location.search).has('q')) {
        openServerSearch('')
        return
      }
      if (input) {
        input.value = ''
        input.dispatchEvent(new Event('input'))
      }
      $$('[data-filter-target="intel-results"]').forEach((select) => { select.value = '' })
      $('.intel-result-tabs .tab[data-tab="all"]')?.click()
      refreshTable(results)
    })

    sort?.addEventListener('change', () => {
      if (results.dataset.serverPagination === 'true') {
        results.dispatchEvent(new CustomEvent('prototype:server-sort', {
          detail: { sort: sort.value },
        }))
        return
      }
      const items = $$('[data-table-row]', results)
      items.sort((a, b) => {
        if (sort.value === 'oldest') return Number(a.dataset.date || 0) - Number(b.dataset.date || 0)
        if (sort.value === 'severity') {
          return Number(b.dataset.severityRank || 0) - Number(a.dataset.severityRank || 0) || Number(b.dataset.date || 0) - Number(a.dataset.date || 0)
        }
        return Number(b.dataset.date || 0) - Number(a.dataset.date || 0)
      }).forEach((item) => results.appendChild(item))
    })
  }

  function setupDetailContext() {
    const recordId = document.body.dataset.prototypeRecordId || new URLSearchParams(window.location.search).get('id')
    if (!recordId) return
    $$('[data-detail-record-id]').forEach((element) => { element.textContent = recordId })
  }

  function setupFileTrees() {
    $$('[data-file-tree]').forEach((tree) => {
      const search = document.querySelector(`[data-tree-search="${tree.id}"]`)
      const filesOnly = document.querySelector(`[data-tree-files-only="${tree.id}"]`)
      const expand = document.querySelector(`[data-tree-expand="${tree.id}"]`)

      const refresh = () => {
        const entries = $$('[data-tree-entry]', tree)
        const empty = $('[data-tree-empty]', tree)
        const query = String(search?.value || '').trim().toLowerCase()
        let visibleFiles = 0
        entries.filter((entry) => entry.dataset.treeKind === 'file').forEach((file) => {
          const show = !query || file.textContent.toLowerCase().includes(query)
          file.hidden = !show
          if (show) visibleFiles += 1
        })
        entries.filter((entry) => entry.dataset.treeKind === 'folder').reverse().forEach((folder) => {
          const ownMatch = !query || folder.querySelector(':scope > summary')?.textContent.toLowerCase().includes(query)
          const childMatch = $$('[data-tree-entry]', folder).some((child) => child !== folder && !child.hidden)
          folder.hidden = Boolean(query) && !ownMatch && !childMatch
          if (query && childMatch) folder.open = true
        })
        tree.classList.toggle('files-only', Boolean(filesOnly?.checked))
        if (filesOnly?.checked) $$('details', tree).forEach((folder) => { folder.open = true })
        if (empty) empty.hidden = visibleFiles > 0
      }

      search?.addEventListener('input', refresh)
      filesOnly?.addEventListener('change', refresh)
      expand?.addEventListener('click', () => {
        $$('details[data-tree-level="0"], details[data-tree-level="1"]', tree).forEach((folder) => { folder.open = true })
      })
      refresh()
    })
  }

  function setupWorkspaceSelections() {
    [
      ['.source-row', 'active'],
      ['.queue-item', 'selected'],
      ['.page-thumbnails button', 'active']
    ].forEach(([selector, activeClass]) => {
      $$(selector).forEach((item) => {
        item.addEventListener('click', () => {
          $$(selector).forEach((candidate) => candidate.classList.remove(activeClass))
          item.classList.add(activeClass)
        })
      })
    })
  }

  function setupCollectorControl() {
    const root = $('[data-collector-surface]') || $('.collector-main')
    if (!root) return

    const bindText = (name, value) => {
      if (value === undefined || value === null || value === '') return
      $$(`[data-bind="${name}"]`, root).forEach((node) => { node.textContent = String(value) })
    }
    const setBadge = (name, label, tone = '') => {
      $$(`[data-bind="${name}"]`, root).forEach((node) => {
        node.textContent = label
        node.classList.remove('badge-success', 'badge-high')
        if (tone) node.classList.add(tone)
      })
    }
    const formatDate = (value) => {
      if (value === undefined || value === null || value === '') return '—'
      const raw = String(value).trim()
      const parsed = new Date(raw)
      if (Number.isNaN(parsed.getTime())) return raw.replace('T', ' ').replace(/\.\d+(?:Z|[+-]\d\d:\d\d)?$/, '')
      const parts = Object.fromEntries(new Intl.DateTimeFormat('zh-CN', {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hourCycle: 'h23'
      }).formatToParts(parsed).map((part) => [part.type, part.value]))
      return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`
    }
    const statusLabel = (value) => ({
      ok: '正常', healthy: '正常', running: '运行中', in_progress: '运行中', started: '运行中', enabled: '已启用',
      queued: '等待中', enqueued: '等待中', pending: '等待中', waiting: '等待中',
      succeeded: '已完成', success: '已完成', completed: '已完成', complete: '已完成',
      partial_failure: '部分异常', degraded: '部分异常', failed: '失败', error: '失败',
      stale: '异常挂起', stopped: '已停止', cancelled: '已取消', canceled: '已取消', disabled: '未启用',
      configured: '已配置', not_configured: '未配置', login_required: '需要登录', unknown: '未知'
    }[String(value || '').toLowerCase()] || value || '未知')

    async function request(url, options = {}) {
      const settings = { ...options, headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) } }
      const response = await fetch(url, settings)
      if (!response.ok) {
        let message = `请求失败：${response.status}`
        try {
          const payload = await response.json()
          const detail = payload.detail || payload.message
          message = Array.isArray(detail)
            ? detail.map((item) => item?.msg || String(item)).join('；')
            : String(detail || message)
        } catch {}
        const error = new Error(message)
        error.status = response.status
        throw error
      }
      const contentType = response.headers.get('content-type') || ''
      return contentType.includes('application/json') ? response.json() : null
    }

    async function startPlatformLogin(platform) {
      const payload = await request(`/api/platform-sessions/${encodeURIComponent(platform)}/adaptive-login/start`, {
        method: 'POST',
      })
      if (payload?.mode === 'embedded_browser') {
        openPlatformRemoteLogin(platform, payload, { label: payload.label || platform })
      }
      return payload
    }

    const codeConfigState = {
      watchlists: [],
      selectedWatchlistId: null
    }
    const documentConfigState = {
      watchlists: [],
      selectedWatchlistId: null
    }
    let watchlistNotificationState = {}
    let torConfigState = {}
    let torPollTimer = 0
    let torPollBusy = false
    const readyCapabilities = new Set()

    const mutationCapability = (button) => {
      const collectorAction = button.dataset.collectorAction || ''
      const codeAction = button.dataset.codeAction || ''
      const exposureAction = button.dataset.exposureAction || ''
      if (button.dataset.siteRun || button.dataset.siteToggle || collectorAction === 'run-all') return 'jobs'
      if (collectorAction.startsWith('tor-') && collectorAction !== 'tor-refresh') return 'tor'
      if (collectorAction.startsWith('vulnerability-')) return 'vulnerability'
      if (collectorAction.startsWith('ransomware-')) return 'ransomware'
      if (collectorAction.startsWith('bot-')) return 'bot'
      if (collectorAction.startsWith('dingtalk-')) return 'dingtalk'
      if (['monitoring-keyword-add', 'monitoring-keyword-save', 'monitoring-keyword-remove'].includes(codeAction)) return 'monitoring-keywords'
      if (['watchlist-save', 'watchlist-delete'].includes(codeAction)) return 'watchlists'
      if (['github-save', 'github-delete'].includes(codeAction)) return 'github'
      if (['changan-save', 'changan-test', 'changan-delete'].includes(codeAction)) return 'changan'
      if (['sessions-detect', 'session-login', 'session-save', 'session-delete'].includes(codeAction)) return 'code-sessions'
      if (['session-detect', 'session-login', 'session-save'].includes(exposureAction)) return 'document-sessions'
      return ''
    }

    const syncMutationButton = (button) => {
      const capability = mutationCapability(button)
      if (button.closest('[data-watchlist-scoped]') && !codeConfigState.selectedWatchlistId) {
        button.disabled = true
        return
      }
      if (!capability) return
      if (!readyCapabilities.has(capability)) {
        button.dataset.capabilityGated = '1'
        button.disabled = true
        return
      }
      if (button.dataset.capabilityGated === '1') {
        delete button.dataset.capabilityGated
        if (button.dataset.runtimeUnsupported !== '1') button.disabled = false
      }
    }
    const syncMutationButtons = () => $$('button', root).forEach(syncMutationButton)
    const syncObjectScopedControls = () => {
      const disabled = !codeConfigState.selectedWatchlistId
      $$('[data-watchlist-scoped]', root).forEach((container) => {
        $$('input, select, textarea, button', container).forEach((control) => {
          if (control.matches('#code-term-watchlist')) return
          if (disabled) control.disabled = true
          else if (!control.dataset.capabilityGated && control.dataset.runtimeUnsupported !== '1') control.disabled = false
        })
        container.classList.toggle('is-scope-disabled', disabled)
      })
    }

    const collectorState = document.createElement('div')
    collectorState.className = 'runtime-data-state'
    collectorState.setAttribute('role', 'status')
    root.prepend(collectorState)
    const setCollectorState = (state, message = '') => {
      collectorState.dataset.state = state
      collectorState.hidden = state === 'ready'
      collectorState.textContent = message || (state === 'loading' ? '正在加载真实数据…' : '')
    }
    setCollectorState('loading')
    $$('[data-bind]', root).forEach((node) => {
      const key = node.dataset.bind || ''
      node.textContent = /count|total|running|stale|worker|pool/.test(key) ? '0' : '—'
    })
    $('[data-site-health-body]', root)?.replaceChildren()
    $('[data-task-list]', root)?.replaceChildren()
    $('#netdisk-cursor-table tbody', root)?.replaceChildren()
    $$('[data-site-health-segment]', root).forEach((node) => node.style.setProperty('--site-share', '0%'))

    const listPayload = (payload, ...keys) => {
      if (Array.isArray(payload)) return payload
      for (const key of keys) {
        if (Array.isArray(payload?.[key])) return payload[key]
      }
      return []
    }

    const lineValues = (value) => String(value || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean)
    const setControlValue = (selector, value = '') => {
      const control = $(selector, root)
      if (control) control.value = value ?? ''
    }

    function renderGithubApp(payload = {}) {
      const configured = Boolean(payload.configured)
      const hasError = Boolean(payload.lastError || payload.last_error)
      const status = $('[data-bind="github-app-status"]', root)
      if (status) {
        status.textContent = configured ? (hasError ? '连接异常' : '已连接') : '未配置'
        status.classList.remove('badge-success', 'badge-critical')
        if (configured && !hasError) status.classList.add('badge-success')
        if (hasError) status.classList.add('badge-critical')
      }
      const appId = payload.appId ?? payload.app_id ?? ''
      const installationId = payload.installationId ?? payload.installation_id ?? ''
      bindText('github-app-id', appId || '—')
      bindText('github-installation-id', installationId || '—')
      bindText('github-last-validated', formatDate(payload.lastValidatedAt || payload.last_validated_at))
      bindText('github-token-expires', formatDate(payload.tokenExpiresAt || payload.token_expires_at))
      setControlValue('#github-app-id', appId)
      setControlValue('#github-installation-id', installationId)
      setControlValue('#github-private-key', '')
      const error = $('[data-bind="github-last-error"]', root)
      if (error) {
        error.textContent = payload.lastError || payload.last_error || ''
        error.hidden = !error.textContent
      }
    }

    function renderChaojiying(payload = {}) {
      const configured = Boolean(payload.configured)
      const managedConfigured = Boolean(payload.managedConfigured)
      const hasError = Boolean(payload.lastError || payload.last_error)
      const status = $('[data-bind="chaojiying-status"]', root)
      if (status) {
        status.textContent = !configured ? '未配置' : hasError ? '配置异常' : payload.managedByEnvironment ? '环境变量配置' : '已配置'
        status.dataset.configured = configured ? '1' : '0'
        status.dataset.managedConfigured = managedConfigured ? '1' : '0'
        status.classList.remove('badge-success', 'badge-critical')
        if (configured && !hasError) status.classList.add('badge-success')
        if (hasError) status.classList.add('badge-critical')
      }
      bindText('chaojiying-config-state', configured ? '凭据完整' : '未配置')
      bindText('chaojiying-credential-state', payload.hasUser && payload.hasCredential ? '已保存' : '缺失')
      bindText('chaojiying-soft-id-state', payload.hasSoftId ? '已设置' : '未设置')
      bindText('chaojiying-code-type', payload.defaultCodeType || '5000')
      setControlValue('#chaojiying-user', '')
      setControlValue('#chaojiying-password', '')
      setControlValue('#chaojiying-soft-id', '')
      const error = $('[data-bind="chaojiying-last-error"]', root)
      if (error) {
        error.textContent = payload.lastError || payload.last_error || ''
        error.hidden = !error.textContent
      }
      const deleteButton = $('[data-code-action="chaojiying-delete"]', root)
      if (deleteButton) {
        deleteButton.disabled = !managedConfigured
        if (managedConfigured) delete deleteButton.dataset.runtimeUnsupported
        else deleteButton.dataset.runtimeUnsupported = '1'
      }
    }

    function renderChanganAutoLogin(payload = {}) {
      const configured = Boolean(payload.configured)
      const ready = Boolean(payload.ready)
      const providerConfigured = Boolean(payload.providerConfigured)
      const managedConfigured = Boolean(payload.managedConfigured)
      const enabled = payload.enabled !== false
      const hasError = Boolean(payload.lastError || payload.last_error || payload.lastValidationSuccess === false)
      const status = $('[data-bind="changan-auto-login-status"]', root)
      if (status) {
        status.textContent = !configured ? '未配置' : !providerConfigured ? '待配置验证码服务' : !enabled ? '已停用' : hasError ? '验证异常' : payload.managedByEnvironment ? '环境变量配置' : '已启用'
        status.dataset.managedConfigured = managedConfigured ? '1' : '0'
        status.classList.remove('badge-success', 'badge-critical')
        if (ready && enabled && !hasError) status.classList.add('badge-success')
        if (hasError) status.classList.add('badge-critical')
      }
      bindText('changan-config-state', configured ? '凭据完整' : '未配置')
      bindText('changan-provider-state', providerConfigured ? '可用' : '未配置')
      bindText('changan-enabled-state', enabled ? '已启用' : '已停用')
      bindText('changan-last-validated', formatDate(payload.lastValidatedAt || payload.last_validated_at))
      setControlValue('#changan-account', '')
      setControlValue('#changan-password', '')
      const enabledControl = $('#changan-auto-enabled', root)
      if (enabledControl) enabledControl.checked = enabled
      const error = $('[data-bind="changan-last-error"]', root)
      if (error) {
        error.textContent = payload.lastError || payload.last_error || ''
        error.hidden = !error.textContent
      }
      const deleteButton = $('[data-code-action="changan-delete"]', root)
      if (deleteButton) {
        deleteButton.disabled = !managedConfigured
        if (managedConfigured) delete deleteButton.dataset.runtimeUnsupported
        else deleteButton.dataset.runtimeUnsupported = '1'
      }
      const testButton = $('[data-code-action="changan-test"]', root)
      if (testButton) {
        testButton.disabled = !ready
        if (ready) delete testButton.dataset.runtimeUnsupported
        else testButton.dataset.runtimeUnsupported = '1'
      }
    }

    function renderCodeSessions(payload = {}) {
      const rows = listPayload(payload, 'sessions', 'items')
      const statusText = {
        valid: '有效',
        configured: '已配置',
        invalid: '无效',
        missing: '缺失',
        unavailable: '不可用',
        login_in_progress: '登录中',
        not_configured: '未配置'
      }
      $$('[data-code-session-platform]', root).forEach((row) => {
        const item = rows.find((candidate) => candidate.platform === row.dataset.codeSessionPlatform) || {}
        const state = String(item.status || 'not_configured')
        const status = $('[data-session-status]', row)
        if (status) {
          status.textContent = statusText[state] || state
          status.className = 'session-state ' + (['valid', 'configured'].includes(state) ? 'status-valid' : ['invalid', 'unavailable'].includes(state) ? 'status-invalid' : state === 'login_in_progress' ? 'status-progress' : 'status-missing')
        }
        const account = $('[data-session-account]', row)
        if (account) account.value = item.account_label || ''
        const verified = $('[data-session-verified]', row)
        if (verified) verified.textContent = formatDate(item.last_verified_at || item.lastValidatedAt)
        const error = $('[data-session-error]', row)
        if (error) error.textContent = item.last_error || '—'
      })
    }

    function documentSessionPlatform(row) {
      const label = $('.source-platform strong', row)?.textContent || ''
      return label.includes('百度文库') ? 'baidu_wenku' : ''
    }

    function renderDocumentSessions(payload = {}) {
      const rows = listPayload(payload, 'sessions', 'items')
      const statusText = {
        valid: '有效', configured: '已配置', invalid: '无效', missing: '缺失', unavailable: '不可用',
        login_in_progress: '登录中', not_configured: '未配置'
      }
      $$('.document-session-row', root).forEach((row) => {
        const platform = documentSessionPlatform(row)
        const item = rows.find((candidate) => candidate.platform === platform) || {}
        const state = platform ? String(item.status || 'not_configured') : 'unavailable'
        const status = $('.session-state', row)
        if (status) {
          status.textContent = platform ? (statusText[state] || state) : '暂不支持'
          status.className = 'session-state ' + (['valid', 'configured'].includes(state) ? 'status-valid' : ['invalid', 'unavailable'].includes(state) ? 'status-invalid' : state === 'login_in_progress' ? 'status-progress' : 'status-missing')
        }
        const account = $('.input', row)
        if (account) {
          account.value = item.account_label || ''
          account.disabled = !platform
        }
        const verified = $('.num', row)
        if (verified) verified.textContent = formatDate(item.last_verified_at || item.lastValidatedAt)
        $$('[data-exposure-action]', row).forEach((button) => {
          button.dataset.runtimeUnsupported = platform ? '0' : '1'
          button.disabled = !platform
          if (!platform) button.title = '当前后端未提供该平台会话接口'
        })
      })
    }

    function renderExposurePlatforms(payload = {}) {
      const platforms = listPayload(payload, 'platforms', 'items')
      const preferredPlatforms = {
        '百度网盘': 'baidupan_share',
        '阿里云盘': 'aliyundrive_share',
        '夸克网盘': 'quark_share',
        OneDrive: 'onedrive_share',
        '百度文库': 'baidu_wenku',
        '道客巴巴': 'doc88',
        '豆丁网': 'docin',
        'CSDN 文库': 'csdn'
      }
      $$('.source-access-row', root).forEach((row) => {
        const labelNode = $('.source-platform strong', row)
        const originalLabel = String(labelNode?.textContent || '').trim()
        const label = originalLabel.toLowerCase()
        const aliases = label.replace(/网盘|云盘|文库|网|\s+/g, '')
        const preferredKey = preferredPlatforms[originalLabel]
        const item = platforms.find((candidate) => candidate.platform === preferredKey) || platforms.find((candidate) => {
          const candidateLabel = String(candidate.label || '').toLowerCase()
          const candidateKey = String(candidate.platform || '').toLowerCase()
          return Boolean(candidateLabel && aliases) && (candidateLabel === label
            || candidateLabel.includes(aliases)
            || label.includes(candidateLabel)
            || candidateKey.includes(aliases))
        })
        const domain = $('.source-domain', row)
        const columns = [...row.children]
        const toggle = $('input[type="checkbox"]', row)
        if (!item) {
          if (domain) domain.textContent = '后端未接入'
          if (columns[2]) columns[2].textContent = '不可用'
          if (columns[3]) columns[3].textContent = '未纳入来源目录'
          if (toggle) {
            toggle.checked = false
            toggle.disabled = true
            toggle.title = '当前后端来源目录未提供该平台'
          }
          return
        }
        if (labelNode) labelNode.textContent = item.label || labelNode.textContent
        if (domain) domain.textContent = item.domains?.[0] || '—'
        if (columns[2]) columns[2].textContent = item.requires_login ? '需要会话' : '公开访问'
        if (columns[3]) columns[3].textContent = item.discovery_only ? '仅用于来源发现' : (item.scan_note || '来源目录已接入')
        if (toggle) {
          toggle.checked = item.scan_enabled ?? true
          toggle.disabled = true
          toggle.title = '当前为后端来源目录的只读状态，未提供单项启停接口'
        }
      })
    }

    function fillWatchlistSelectors() {
      const selectors = [$('#code-watchlist-select', root), $('#code-term-watchlist', root), $('#document-policy-watchlist', root), $('#notification-watchlist-select', root)].filter(Boolean)
      selectors.forEach((select) => {
        const value = codeConfigState.selectedWatchlistId == null ? '' : String(codeConfigState.selectedWatchlistId)
        select.replaceChildren()
        const empty = document.createElement('option')
        empty.value = ''
        empty.textContent = codeConfigState.watchlists.length ? '请选择监测对象' : '暂无对象，请新建'
        select.appendChild(empty)
        codeConfigState.watchlists.forEach((item) => {
          const option = document.createElement('option')
          option.value = String(item.id)
          option.textContent = item.name || '未命名对象'
          select.appendChild(option)
        })
        select.value = value
      })
    }

    function refreshObjectReadiness() {
      const summary = $('[data-od-id="code-object-readiness"]', root)
      if (!summary) return

      const name = $('#code-object-name', root)?.value.trim() || ''
      const organization = $('#code-organization-name', root)?.value.trim() || ''
      const basicCompleted = [name, organization].filter(Boolean).length
      const profileControls = $$('[data-code-profile]', root).filter((control) => control.type !== 'checkbox')
      const profileCompleted = profileControls.filter((control) => control.value.trim()).length
      const detectionChecks = [
        $$('[data-code-platform]', root).some((control) => control.checked),
        $$('[data-code-rule]', root).some((control) => control.checked),
        readCodeTerms().length > 0,
        $$('[data-document-module-toggle] [data-document-field="enabled"]', root).some((control) => control.checked)
      ]
      const detectionCompleted = detectionChecks.filter(Boolean).length
      const totalCompleted = basicCompleted + profileCompleted + detectionCompleted
      const totalChecks = 2 + profileControls.length + detectionChecks.length
      const coverage = totalChecks ? Math.round(totalCompleted / totalChecks * 100) : 0

      bindText('code-object-monogram', name ? Array.from(name)[0].toUpperCase() : '未')
      bindText('code-object-summary-name', name || '尚未选择监测对象')
      bindText('code-object-summary-org', organization || (name ? '所属机构待补充' : '新建对象后开始维护检测范围'))
      bindText('code-basic-coverage', `${basicCompleted}/2`)
      bindText('code-profile-coverage', `${profileCompleted}/${profileControls.length}`)
      bindText('code-detection-coverage', `${detectionCompleted}/${detectionChecks.length}`)
      bindText('code-config-coverage', `${coverage}%`)

      const setMilestoneState = (key, value, total) => {
        const item = $(`[data-readiness-item="${key}"]`, summary)
        if (item) item.dataset.state = value === 0 ? 'empty' : value === total ? 'complete' : 'partial'
      }
      setMilestoneState('basic', basicCompleted, 2)
      setMilestoneState('profile', profileCompleted, profileControls.length)
      setMilestoneState('detection', detectionCompleted, detectionChecks.length)

      const bar = $('[data-object-readiness-bar]', summary)
      if (bar) bar.style.width = `${coverage}%`
      const next = basicCompleted < 2
        ? '请先填写对象名称与所属机构'
        : profileCompleted === 0
          ? '至少补充一个企业名称或域名锚点'
          : detectionCompleted < detectionChecks.length
            ? '继续完善平台、敏感规则、检索词和暴露监测范围'
            : profileCompleted < profileControls.length
              ? '关键检测条件已具备，可继续完善企业画像'
              : '对象配置已覆盖全部关键条件'
      bindText('code-config-next', next)
    }

    function renderCodeTerms(terms = []) {
      const body = $('#code-term-list', root)
      if (!body) return
      body.replaceChildren()
      const typeLabels = {
        company_name: '企业名称',
        domain: '域名',
        project_name: '项目名称',
        product_name: '产品名称',
        custom: '自定义'
      }
      terms.forEach((item, index) => {
        const row = document.createElement('tr')
        row.dataset.tableRow = ''
        row.dataset.type = item.term_type || 'company_name'
        row.dataset.state = item.enabled === false ? 'disabled' : 'enabled'
        row.dataset.termIndex = String(index)
        row.dataset.termWeight = String(Number(item.weight || 0))

        const termCell = document.createElement('td')
        const termInput = document.createElement('input')
        termInput.className = 'input'
        termInput.dataset.codeTermField = 'term'
        termInput.value = item.term || ''
        termInput.placeholder = '输入检索词'
        termCell.appendChild(termInput)

        const typeCell = document.createElement('td')
        const typeSelect = document.createElement('select')
        typeSelect.className = 'select'
        typeSelect.dataset.codeTermField = 'term_type'
        Object.entries(typeLabels).forEach(([value, label]) => {
          const option = document.createElement('option')
          option.value = value
          option.textContent = label
          option.selected = value === (item.term_type || 'company_name')
          typeSelect.appendChild(option)
        })
        typeCell.appendChild(typeSelect)

        const stateCell = document.createElement('td')
        const enabled = document.createElement('label')
        enabled.className = 'code-term-state'
        const enabledInput = document.createElement('input')
        enabledInput.type = 'checkbox'
        enabledInput.dataset.codeTermField = 'enabled'
        enabledInput.checked = item.enabled !== false
        enabled.append(enabledInput, document.createTextNode(enabledInput.checked ? '已启用' : '已停用'))
        stateCell.appendChild(enabled)

        const updatedCell = document.createElement('td')
        updatedCell.className = 'num'
        updatedCell.textContent = formatDate(item.updated_at) || '随对象保存'

        const actionCell = document.createElement('td')
        const remove = document.createElement('button')
        remove.className = 'btn btn-ghost'
        remove.dataset.codeTermRemove = ''
        remove.textContent = '删除'
        actionCell.appendChild(remove)

        row.append(termCell, typeCell, stateCell, updatedCell, actionCell)
        body.appendChild(row)
      })
      const table = $('#code-term-table', root)
      if (table) refreshTable(table)
      refreshObjectReadiness()
    }

    function renderDerivedCodeTerms(terms = []) {
      const list = $('[data-derived-code-terms]', root)
      if (!list) return
      list.replaceChildren()
      terms.forEach((item) => {
        const tag = document.createElement('span')
        tag.className = 'derived-term-tag'
        tag.textContent = item.term || ''
        list.appendChild(tag)
      })
      bindText('derived-code-term-count', terms.length)
      if (!terms.length) list.textContent = codeConfigState.selectedWatchlistId ? '当前企业画像尚未生成搜索词。' : '保存监测对象后显示自动生成词。'
    }

    function updateMonitoringKeywordSummary() {
      const rows = $$('.monitoring-keyword-table tbody tr', root)
      bindText('monitoring-keyword-total', rows.length)
      bindText('monitoring-keyword-enabled', rows.filter((row) => $('[data-monitoring-keyword-field="enabled"]', row)?.checked).length)
      const empty = $('[data-monitoring-keyword-empty]', root)
      if (empty) {
        empty.hidden = rows.length > 0
        empty.textContent = rows.length ? '' : '暂无规则，请新增第一条情报监控关键词。'
      }
    }

    function renderMonitoringKeywords(payload = []) {
      const body = $('[data-monitoring-keyword-list]', root)
      if (!body) return
      const rows = listPayload(payload, 'keywords', 'items')
      const categoryLabels = {
        geo_keywords: '地域关键词',
        org_keywords: '组织关键词',
        custom_keywords: '自定义关键词'
      }
      const modeLabels = {
        contains: '包含匹配',
        word_boundary: '英文单词边界'
      }
      body.replaceChildren()
      rows.forEach((item) => {
        const row = document.createElement('tr')

        const keywordCell = document.createElement('td')
        const keyword = document.createElement('input')
        keyword.className = 'input'
        keyword.dataset.monitoringKeywordField = 'keyword'
        keyword.value = item.keyword || ''
        keyword.placeholder = '输入企业、行业或地域关键词'
        keywordCell.appendChild(keyword)

        const categoryCell = document.createElement('td')
        const category = document.createElement('select')
        category.className = 'select'
        category.dataset.monitoringKeywordField = 'category'
        const selectedCategory = item.category || 'custom_keywords'
        if (!categoryLabels[selectedCategory]) categoryLabels[selectedCategory] = selectedCategory
        Object.entries(categoryLabels).forEach(([value, label]) => {
          const option = document.createElement('option')
          option.value = value
          option.textContent = label
          option.selected = value === selectedCategory
          category.appendChild(option)
        })
        categoryCell.appendChild(category)

        const weightCell = document.createElement('td')
        const weight = document.createElement('input')
        weight.className = 'input num'
        weight.type = 'number'
        weight.min = '0'
        weight.max = '100'
        weight.dataset.monitoringKeywordField = 'weight'
        weight.value = String(Number(item.weight ?? 5))
        weightCell.appendChild(weight)

        const modeCell = document.createElement('td')
        const mode = document.createElement('select')
        mode.className = 'select'
        mode.dataset.monitoringKeywordField = 'match_mode'
        const selectedMode = item.match_mode || 'contains'
        Object.entries(modeLabels).forEach(([value, label]) => {
          const option = document.createElement('option')
          option.value = value
          option.textContent = label
          option.selected = value === selectedMode
          mode.appendChild(option)
        })
        modeCell.appendChild(mode)

        const stateCell = document.createElement('td')
        const state = document.createElement('label')
        state.className = 'monitoring-keyword-state'
        const enabled = document.createElement('input')
        enabled.type = 'checkbox'
        enabled.checked = item.enabled !== false
        enabled.dataset.monitoringKeywordField = 'enabled'
        const stateText = document.createElement('span')
        stateText.textContent = enabled.checked ? '启用' : '停用'
        state.append(enabled, stateText)
        stateCell.appendChild(state)

        const actionCell = document.createElement('td')
        const remove = document.createElement('button')
        remove.className = 'btn btn-ghost'
        remove.type = 'button'
        remove.textContent = '删除'
        remove.dataset.codeAction = 'monitoring-keyword-remove'
        actionCell.appendChild(remove)

        row.append(keywordCell, categoryCell, weightCell, modeCell, stateCell, actionCell)
        body.appendChild(row)
      })
      updateMonitoringKeywordSummary()
    }

    function readMonitoringKeywords() {
      return $$('.monitoring-keyword-table tbody tr', root).map((row) => ({
        keyword: $('[data-monitoring-keyword-field="keyword"]', row)?.value.trim() || '',
        category: $('[data-monitoring-keyword-field="category"]', row)?.value || 'custom_keywords',
        weight: Number($('[data-monitoring-keyword-field="weight"]', row)?.value || 0),
        enabled: Boolean($('[data-monitoring-keyword-field="enabled"]', row)?.checked),
        match_mode: $('[data-monitoring-keyword-field="match_mode"]', row)?.value || 'contains'
      })).filter((item) => item.keyword)
    }

    function renderDocumentTerms(terms = []) {
      const list = $('#document-term-list', root)
      const empty = $('[data-document-term-empty]', root)
      if (!list) return
      list.replaceChildren()
      const typeLabels = {
        product_name: '产品名称',
        project_name: '项目名称',
        custom: '自定义',
        sensitive_keyword: '敏感词'
      }
      terms.forEach((item) => {
        const row = document.createElement('div')
        row.className = 'document-term-row'
        row.setAttribute('role', 'row')
        row.dataset.termWeight = String(Number(item.weight || 10))

        const term = document.createElement('input')
        term.className = 'input'
        term.placeholder = '输入产品、项目或敏感词'
        term.value = item.term || ''
        term.dataset.documentTermField = 'term'

        const type = document.createElement('select')
        type.className = 'select'
        type.dataset.documentTermField = 'term_type'
        Object.entries(typeLabels).forEach(([value, label]) => {
          const option = document.createElement('option')
          option.value = value
          option.textContent = label
          option.selected = value === (item.term_type || 'product_name')
          type.appendChild(option)
        })

        const enabled = document.createElement('label')
        enabled.className = 'switch-control compact-switch document-term-state'
        const enabledInput = document.createElement('input')
        enabledInput.type = 'checkbox'
        enabledInput.checked = item.enabled !== false
        enabledInput.dataset.documentTermField = 'enabled'
        const track = document.createElement('span')
        track.className = 'switch-track'
        track.setAttribute('aria-hidden', 'true')
        const enabledText = document.createElement('span')
        enabledText.textContent = enabledInput.checked ? '启用' : '停用'
        enabled.append(enabledInput, track, enabledText)

        const remove = document.createElement('button')
        remove.className = 'btn btn-ghost'
        remove.type = 'button'
        remove.textContent = '删除'
        remove.dataset.documentTermDelete = ''
        row.append(term, type, enabled, remove)
        list.appendChild(row)
      })
      if (empty) empty.hidden = terms.length > 0
    }

    function readDocumentTerms() {
      return $$('#document-term-list .document-term-row', root).map((row) => ({
        term: $('[data-document-term-field="term"]', row)?.value.trim() || '',
        term_type: $('[data-document-term-field="term_type"]', row)?.value || 'product_name',
        weight: Number(row.dataset.termWeight || 10),
        enabled: Boolean($('[data-document-term-field="enabled"]', row)?.checked)
      })).filter((item) => item.term)
    }

    function applyDocumentMonitoring(config = {}) {
      const defaults = {
        netdisk: { enabled: true, file_types: ['pdf', 'docx', 'xlsx', 'zip'], detail_fetch: true },
        library: { enabled: true, file_types: ['pdf', 'docx', 'pptx'], detail_fetch: true, candidate_limit: 30 }
      }
      Object.entries(defaults).forEach(([moduleKey, fallback]) => {
        const value = { ...fallback, ...(config[moduleKey] || {}) }
        const membership = $(`[data-document-module-toggle="${moduleKey}"]`, root)
        const enabled = $('[data-document-field="enabled"]', membership)
        if (enabled) enabled.checked = value.enabled !== false

        const policy = $(`[data-document-policy="${moduleKey}"]`, root)
        if (!policy) return
        $$('[data-document-field]', policy).forEach((control) => {
          const field = control.dataset.documentField
          if (control.type === 'checkbox') control.checked = value[field] !== false
          else control.value = value[field] ?? ''
        })
        $$('[data-document-file-type]', policy).forEach((control) => {
          control.checked = Array.isArray(value.file_types) && value.file_types.includes(control.value)
        })
      })
    }

    function readDocumentMonitoring() {
      return Object.fromEntries(['netdisk', 'library'].map((moduleKey) => {
        const membership = $(`[data-document-module-toggle="${moduleKey}"]`, root)
        const policy = $(`[data-document-policy="${moduleKey}"]`, root)
        const value = {
          enabled: $('[data-document-field="enabled"]', membership)?.checked !== false,
          file_types: $$('[data-document-file-type]', policy).filter((control) => control.checked).map((control) => control.value),
          detail_fetch: $('[data-document-field="detail_fetch"]', policy)?.checked !== false
        }
        const limit = $('[data-document-field="candidate_limit"]', policy)
        if (limit) value.candidate_limit = Number(limit.value || 30)
        return [moduleKey, value]
      }))
    }

    function documentWatchlistFor(codeWatchlist) {
      if (!codeWatchlist) return null
      return documentConfigState.watchlists.find((item) =>
        item.organization_name && item.organization_name === codeWatchlist.organization_name,
      ) || documentConfigState.watchlists.find((item) => item.name === codeWatchlist.name) || null
    }

    function applyDocumentWatchlist(item = null) {
      documentConfigState.selectedWatchlistId = item?.id ?? null
      const sourceFamilies = Array.isArray(item?.source_families) ? item.source_families : []
      const sharedTypes = Array.isArray(item?.file_types) ? item.file_types : []
      const sourcePolicies = item?.source_policies && typeof item.source_policies === 'object' ? item.source_policies : {}
      const netdiskPolicy = sourcePolicies.netdisk_aggregator || {}
      const libraryPolicy = sourcePolicies.document_library || {}
      applyDocumentMonitoring(item ? {
        netdisk: {
          enabled: sourceFamilies.includes('netdisk_aggregator'),
          file_types: Array.isArray(netdiskPolicy.file_types) ? netdiskPolicy.file_types : sharedTypes,
          detail_fetch: netdiskPolicy.detail_fetch ?? (item.detail_fetch !== false)
        },
        library: {
          enabled: sourceFamilies.includes('document_library'),
          file_types: Array.isArray(libraryPolicy.file_types) ? libraryPolicy.file_types : sharedTypes,
          detail_fetch: libraryPolicy.detail_fetch ?? (item.detail_fetch !== false),
          candidate_limit: Number(libraryPolicy.candidate_limit || item.page_limit || 30)
        }
      } : {})
      renderDocumentTerms(Array.isArray(item?.terms) ? item.terms : [])
    }

    function renderExposureWatchlists(payload = {}) {
      documentConfigState.watchlists = listPayload(payload, 'watchlists', 'items')
      const codeWatchlist = codeConfigState.watchlists.find((item) => String(item.id) === String(codeConfigState.selectedWatchlistId)) || null
      applyDocumentWatchlist(documentWatchlistFor(codeWatchlist))
    }

    function applyCodeWatchlist(item = null) {
      codeConfigState.selectedWatchlistId = item?.id ?? null
      fillWatchlistSelectors()
      setControlValue('#code-object-name', item?.name || '')
      setControlValue('#code-organization-name', item?.organization_name || '')
      setControlValue('#code-object-notes', item?.notes || '')
      const enabled = $('#code-object-enabled', root)
      if (enabled) enabled.checked = item?.enabled ?? true
      bindText('code-watchlist-state', item?.id ? (item.enabled === false ? '已停用' : '已启用') : '新建草稿')
      $$('[data-bind="current-watchlist-scope"]', root).forEach((node) => { node.textContent = item?.name || '未选择' })

      const profile = item?.enterprise_profile || {}
      $$('[data-code-profile]', root).forEach((control) => {
        const key = control.dataset.codeProfile
        if (control.type === 'checkbox') {
          const guarded = Array.isArray(profile[key]) ? profile[key] : []
          control.checked = key === 'short_alias_guard' ? (guarded.length > 0 || !item?.id) : Boolean(profile[key])
        }
        else control.value = Array.isArray(profile[key]) ? profile[key].join('\n') : (profile[key] || '')
      })
      $$('[data-code-platform]', root).forEach((control) => {
        control.checked = (Array.isArray(item?.platforms) && item.platforms.length ? item.platforms : ['github', 'gitlab', 'gitee']).includes(control.dataset.codePlatform)
      })
      applyDocumentWatchlist(documentWatchlistFor(item))
      const extensions = Array.isArray(item?.file_extensions) ? item.file_extensions : ['env', 'yaml', 'yml', 'json', 'ini', 'conf', 'properties', 'py', 'js', 'ts', 'java']
      setControlValue('#code-file-extensions', extensions.join('\n'))
      const detailFetch = $('#code-detail-fetch', root)
      if (detailFetch) detailFetch.checked = item?.detail_fetch ?? true
      setControlValue('#code-search-page-limit', Number(item?.search_page_limit || 0))
      setControlValue('#code-max-results', Number(item?.max_results_per_term || 0))
      const ruleKeys = Array.isArray(item?.enabled_rule_keys) ? item.enabled_rule_keys : ['api_key', 'token', 'ak_sk', 'db_url', 'jwt_secret', 'redis_url', 'private_key', 'internal_url', 'password']
      $$('[data-code-rule]', root).forEach((control) => { control.checked = ruleKeys.includes(control.dataset.codeRule) })
      renderCodeTerms(Array.isArray(item?.terms) ? item.terms : [])
      renderDerivedCodeTerms(Array.isArray(item?.derived_terms) ? item.derived_terms : [])
      syncMutationButtons()
      syncObjectScopedControls()
    }

    function renderCodeWatchlists(payload = {}) {
      codeConfigState.watchlists = listPayload(payload, 'watchlists', 'items')
      const selected = codeConfigState.watchlists.find((item) => String(item.id) === String(codeConfigState.selectedWatchlistId)) || codeConfigState.watchlists[0] || null
      applyCodeWatchlist(selected)
    }

    function readCodeTerms() {
      return $$('#code-term-list tr', root).map((row) => ({
        term: $('[data-code-term-field="term"]', row)?.value.trim() || '',
        term_type: $('[data-code-term-field="term_type"]', row)?.value || 'company_name',
        weight: Number(row.dataset.termWeight || 0),
        enabled: Boolean($('[data-code-term-field="enabled"]', row)?.checked)
      })).filter((item) => item.term)
    }

    function codeWatchlistPayload() {
      const name = $('#code-object-name', root)?.value.trim() || ''
      const organizationName = $('#code-organization-name', root)?.value.trim() || ''
      if (!name) throw new Error('请输入监测对象名称')
      if (!organizationName) throw new Error('请输入所属机构')
      const enterpriseProfile = {}
      $$('[data-code-profile]', root).forEach((control) => {
        const key = control.dataset.codeProfile
        if (key === 'short_alias_guard') return
        enterpriseProfile[key] = lineValues(control.value)
      })
      const shortAliases = [...(enterpriseProfile.brand_aliases || []), ...(enterpriseProfile.english_aliases || [])]
        .filter((value) => value.replace(/[^a-z0-9]/gi, '').length <= 4)
      enterpriseProfile.short_alias_guard = $('[data-code-profile="short_alias_guard"]', root)?.checked ? shortAliases : []
      return {
        id: codeConfigState.selectedWatchlistId,
        name,
        organization_name: organizationName,
        notes: $('#code-object-notes', root)?.value.trim() || '',
        enabled: Boolean($('#code-object-enabled', root)?.checked),
        platforms: $$('[data-code-platform]', root).filter((control) => control.checked).map((control) => control.dataset.codePlatform),
        file_extensions: lineValues($('#code-file-extensions', root)?.value).map((item) => item.replace(/^\./, '')),
        search_page_limit: Number($('#code-search-page-limit', root)?.value || 0),
        max_results_per_term: Number($('#code-max-results', root)?.value || 0),
        detail_fetch: Boolean($('#code-detail-fetch', root)?.checked),
        enabled_rule_keys: $$('[data-code-rule]', root).filter((control) => control.checked).map((control) => control.dataset.codeRule),
        terms: readCodeTerms(),
        enterprise_profile: enterpriseProfile
      }
    }

    function documentWatchlistPayload() {
      const monitoring = readDocumentMonitoring()
      const sourceFamilies = []
      if (monitoring.netdisk.enabled) sourceFamilies.push('netdisk_aggregator')
      if (monitoring.library.enabled) sourceFamilies.push('document_library')
      const fileTypes = [...new Set([...(monitoring.netdisk.file_types || []), ...(monitoring.library.file_types || [])])]
      return {
        id: documentConfigState.selectedWatchlistId,
        name: $('#code-object-name', root)?.value.trim() || '',
        organization_name: $('#code-organization-name', root)?.value.trim() || '',
        enabled: Boolean($('#code-object-enabled', root)?.checked),
        notes: $('#code-object-notes', root)?.value.trim() || '',
        source_families: sourceFamilies,
        file_types: fileTypes,
        page_limit: Number(monitoring.library.candidate_limit || 30),
        detail_fetch: [monitoring.netdisk, monitoring.library].filter((item) => item.enabled).every((item) => item.detail_fetch !== false),
        source_policies: {
          netdisk_aggregator: {
            file_types: monitoring.netdisk.file_types || [],
            detail_fetch: monitoring.netdisk.detail_fetch !== false
          },
          document_library: {
            file_types: monitoring.library.file_types || [],
            detail_fetch: monitoring.library.detail_fetch !== false,
            candidate_limit: Number(monitoring.library.candidate_limit || 30)
          }
        },
        terms: readDocumentTerms()
      }
    }

    function createCodeWatchlist() {
      applyCodeWatchlist({
        enabled: true,
        platforms: ['github', 'gitlab', 'gitee'],
        file_extensions: ['env', 'yaml', 'yml', 'json', 'ini', 'conf', 'properties', 'py', 'js', 'ts', 'java'],
        search_page_limit: 0,
        max_results_per_term: 0,
        detail_fetch: true,
        enabled_rule_keys: ['api_key', 'token', 'ak_sk', 'db_url', 'jwt_secret', 'redis_url', 'private_key', 'internal_url', 'password'],
        terms: [],
        enterprise_profile: {}
      })
      $('#code-object-name', root)?.focus()
    }

    function addCodeTerm() {
      renderCodeTerms([...readCodeTerms(), { term: '', term_type: 'company_name', enabled: true }])
      $('#code-term-list tr:last-child input', root)?.focus()
    }

    function downloadCodeTermTemplate() {
      if (!window.XLSX) throw new Error('Excel 组件未加载，请刷新页面后重试')
      const sheet = window.XLSX.utils.aoa_to_sheet([
        ['检索词', '类型', '是否启用'],
        ['示例企业名称', 'company_name', '是']
      ])
      sheet['!cols'] = [{ wch: 30 }, { wch: 18 }, { wch: 14 }]
      const exampleSheet = window.XLSX.utils.aoa_to_sheet([
        ['检索词', '类型', '是否启用'],
        ['example.com', 'domain', '是'],
        ['内部项目代号', 'project_name', '是'],
        ['旧品牌简称', 'custom', '否']
      ])
      const instructionSheet = window.XLSX.utils.aoa_to_sheet([
        ['字段', '填写要求'],
        ['检索词', '必填；同一对象内按“检索词 + 类型”自动去重'],
        ['类型', 'company_name、domain、project_name、product_name、custom'],
        ['是否启用', '是/否、true/false 或 1/0']
      ])
      const workbook = window.XLSX.utils.book_new()
      window.XLSX.utils.book_append_sheet(workbook, sheet, '检索词')
      window.XLSX.utils.book_append_sheet(workbook, exampleSheet, '示例')
      window.XLSX.utils.book_append_sheet(workbook, instructionSheet, '填写说明')
      window.XLSX.writeFile(workbook, '代码监测检索词导入模板.xlsx')
    }

    function setTorRouteState(nextState) {
      const route = $('.network-route', root)
      if (!route || route.dataset.routeState === nextState) return
      route.dataset.routeState = nextState
      route.classList.remove('is-state-change')
      void route.offsetWidth
      route.classList.add('is-state-change')
      window.setTimeout(() => route.classList.remove('is-state-change'), 560)
    }

    const torModeHelp = (mode) => ({
      snowflake: 'Snowflake 通过代理节点建立连接，适合快速恢复采集链路。',
      obfs4: 'obfs4 将 Tor 流量伪装为随机数据，适合审查较严格的网络。',
      meek_lite: 'meek 借助云服务建立连接，兼容性较好但速度通常较慢。',
      custom: '使用已知 Bridge 地址；请在下方每行粘贴一条完整配置。'
    })[mode] || ''

    function renderTorModeHelp(mode, payload = {}) {
      const help = $('#tor-mode-help', root)
      if (!help) return
      const automaticUpdate = mode !== 'custom' && payload.builtin_bridge_auto_update
      const updatedAt = payload.builtin_bridge_updated_at ? formatDate(payload.builtin_bridge_updated_at) : ''
      const updateHint = automaticUpdate
        ? ` 项目每天自动检查 Tor 运行时与内置网桥更新${updatedAt ? `（当前配置 ${updatedAt}）` : ''}。`
        : ''
      help.textContent = `${torModeHelp(mode)}${updateHint}`
    }

    function renderTor(payload = {}) {
      torConfigState = { ...torConfigState, ...payload }
      const enabled = Boolean(payload.enabled)
      const running = Boolean(payload.process_running)
      const connected = Boolean(payload.connected) || payload.connection_state === 'connected'
      const errorText = payload.last_error || (Array.isArray(payload.runtime_errors) ? payload.runtime_errors[0] : '')
      const failed = payload.connection_state === 'error' || Boolean(errorText)
      const progress = Math.max(0, Math.min(100, Math.round(Number(payload.bootstrap_percent || 0))))
      const enabledInput = $('#tor-enabled', root)
      const mode = $('#tor-mode', root)
      const host = $('#tor-host', root)
      const port = $('#tor-port', root)
      const lines = $('#tor-lines', root)
      if (enabledInput) enabledInput.checked = enabled
      if (mode && payload.bridge_mode && [...mode.options].some((option) => option.value === payload.bridge_mode)) {
        mode.value = payload.bridge_mode
      }
      renderTorModeHelp(payload.bridge_mode || mode?.value, payload)
      if (host && payload.socks_host) host.value = payload.socks_host
      if (port && payload.socks_port) port.value = payload.socks_port
      if (lines && Array.isArray(payload.bridge_lines)) lines.value = payload.bridge_lines.join('\n')
      const connectionLabel = failed ? '连接失败' : connected ? '已连接' : running ? '连接中' : enabled ? '待连接' : '未启用'
      setBadge('tor-status', connectionLabel, failed ? 'badge-high' : connected ? 'badge-success' : '')
      bindText('tor-connection', connectionLabel)
      bindText('tor-exit-ip', payload.exit_ip || (connected ? '检测中…' : '连接成功后显示'))
      bindText('tor-proxy', payload.collector_proxy || `socks5h://${payload.socks_host || '127.0.0.1'}:${payload.socks_port || 9050}`)
      bindText('tor-progress-label', errorText || payload.bootstrap_summary || (connected ? 'Tor 网络连接完成' : enabled ? '等待连接' : '网桥未启用'))
      bindText('tor-progress-value', `${progress}%`)
      bindText('tor-summary', errorText ? `最近错误：${errorText}` : (payload.bootstrap_summary || '网桥状态已与采集代理同步。'))
      const routeState = failed ? 'error' : connected ? 'connected' : running ? 'connecting' : enabled ? 'ready' : 'disabled'
      setTorRouteState(routeState)
      const track = $('[data-bind-progress="tor-progress"]', root)
      if (track) {
        track.style.width = `${progress}%`
        track.parentElement?.setAttribute('aria-valuenow', String(progress))
      }
      scheduleTorPoll(payload)
    }

    function stopTorPoll() {
      if (torPollTimer) window.clearTimeout(torPollTimer)
      torPollTimer = 0
    }

    function scheduleTorPoll(payload = {}) {
      stopTorPoll()
      const shouldPoll = (
        payload.process_running && !payload.connected && payload.connection_state !== 'error'
      ) || (
        payload.connected && !payload.exit_ip && !payload.exit_ip_error
      )
      if (!shouldPoll || !root.isConnected) return
      torPollTimer = window.setTimeout(async () => {
        torPollTimer = 0
        if (torPollBusy || !root.isConnected) return
        torPollBusy = true
        try {
          renderTor(await request('/api/tor-bridge/status'))
        } catch {
          stopTorPoll()
        } finally {
          torPollBusy = false
        }
      }, 1500)
    }

    function renderSiteHealth(items = []) {
      if (!Array.isArray(items)) return
      const healthyStatuses = new Set(['ok', 'healthy', 'running', '正常', '运行中', '等待中'])
      const isHealthy = (item) => healthyStatuses.has(String(item.overall_status || '').toLowerCase())
      const needsLogin = (item) => ['missing', 'login_required', 'login_in_progress'].includes(String(item.auth_status || '').toLowerCase())
      const healthy = items.filter(isHealthy).length
      const abnormal = items.length - healthy
      bindText('site-total', items.length)
      bindText('site-healthy', healthy)
      bindText('site-abnormal', abnormal)
      bindText('site-auth', items.filter(needsLogin).length)
      bindText('site-circuit', items.filter((item) => Boolean(item.circuit_breaker_open)).length)
      const denominator = Math.max(items.length, 1)
      const healthySegment = $('[data-site-health-segment="healthy"]', root)
      const abnormalSegment = $('[data-site-health-segment="abnormal"]', root)
      if (healthySegment) healthySegment.style.setProperty('--site-share', `${healthy / denominator * 100}%`)
      if (abnormalSegment) abnormalSegment.style.setProperty('--site-share', `${abnormal / denominator * 100}%`)
      const body = $('[data-site-health-body]', root)
      if (!body) return
      body.replaceChildren()
      items.forEach((item) => {
        const row = document.createElement('tr')
        const rawModule = String(item.business_type || item.source_family || item.module || 'darkweb').toLowerCase()
        const moduleKey = ['netdisk', 'cloud_disk', 'network_disk'].includes(rawModule)
          ? 'netdisk'
          : ['library', 'document_library', 'wenku'].includes(rawModule) ? 'library' : 'darkweb'
        const moduleLabel = { darkweb: '暗网', netdisk: '网盘', library: '文库' }[moduleKey]
        row.dataset.site = item.site_name || ''
        row.dataset.module = moduleKey
        row.dataset.status = isHealthy(item) ? 'healthy' : 'abnormal'
        row.dataset.auth = needsLogin(item) ? 'login' : 'public'
        const cells = [
          [item.display_name || item.site_name || '未知站点', `${moduleLabel} · ${needsLogin(item) ? '需要登录' : item.auth_required ? '会话站点' : '公开站点'}`],
          [statusLabel(item.overall_status), ''],
          [`${item.running_jobs || 0} / ${item.enqueued_jobs || 0}`, ''],
          [item.failed_jobs_24h || 0, ''],
          [`${item.consecutive_failures || 0}/${item.failure_threshold || 3}`, ''],
          [item.circuit_breaker_open ? '冷却中' : '关闭', ''],
          [formatDate(item.last_success_at), '']
        ]
        const labels = ['站点', '状态', '执行 / 排队', '24h 失败', '连续失败', '熔断', '最近成功']
        cells.forEach(([primary, secondary], index) => {
          const cell = document.createElement('td')
          cell.dataset.label = labels[index]
          if (index === 0) {
            cell.className = 'table-title'
            cell.textContent = primary
            const small = document.createElement('span')
            small.textContent = secondary
            cell.appendChild(small)
          } else if (index === 1) {
            const state = document.createElement('span')
            state.className = `status-dot ${isHealthy(item) ? 'running' : 'stopped'}`
            state.textContent = primary
            cell.appendChild(state)
          } else if (index === 5) {
            cell.className = 'health-extra'
            const badge = document.createElement('span')
            badge.className = `badge ${item.circuit_breaker_open ? 'badge-high' : 'badge-success'}`
            badge.textContent = primary
            cell.appendChild(badge)
          } else {
            cell.textContent = primary
            if ([2, 3, 4].includes(index)) cell.classList.add('num')
            if (index === 6) cell.classList.add('health-extra')
          }
          row.appendChild(cell)
        })
        const actionCell = document.createElement('td')
        actionCell.dataset.label = '操作'
        const actions = document.createElement('div')
        actions.className = 'table-actions'
        const run = document.createElement('button')
        run.className = 'btn btn-secondary'
        run.dataset.siteRun = item.site_name || ''
        run.textContent = '运行'
        const toggle = document.createElement('button')
        toggle.className = 'btn btn-secondary'
        toggle.dataset.siteToggle = item.site_name || ''
        toggle.dataset.enabled = String(item.enabled !== false)
        toggle.textContent = item.enabled === false ? '启用' : '停用'
        const detailsToggle = document.createElement('button')
        detailsToggle.className = 'site-details-toggle'
        detailsToggle.type = 'button'
        detailsToggle.setAttribute('aria-expanded', 'false')
        detailsToggle.setAttribute('aria-label', `展开${item.display_name || item.site_name || '站点'}信息`)
        detailsToggle.innerHTML = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4"/></svg>'
        actions.append(run, toggle, detailsToggle)
        actionCell.appendChild(actions)
        row.appendChild(actionCell)
        body.appendChild(row)

        const sourceUrls = Array.isArray(item.seed_urls) ? item.seed_urls.filter(Boolean) : []
        const sourceUrl = sourceUrls[0] || ''
        let hostname = ''
        try {
          hostname = new URL(sourceUrl).hostname
        } catch {
          hostname = sourceUrl
        }
        const fetchModeLabel = (mode) => ({ browser: 'Tor 浏览器', tor_http: 'Tor HTTP' }[String(mode || '').toLowerCase()] || '未配置')
        const siteType = hostname.endsWith('.onion') ? 'Onion 站点' : 'Web 站点'
        const probeFailureLabel = { route_unavailable: 'Tor 链路异常', timeout: '连接超时', fetch_failed: '链路不可用' }[item.connectivity_failure_reason] || '链路不可用'
        const probeSuccessTime = item.connectivity_last_success_at || (item.connectivity_available === true ? item.connectivity_checked_at : '')
        const availabilityValue = item.connectivity_available === true
          ? `链路可用 · ${formatDate(probeSuccessTime)}`
          : item.connectivity_available === false
            ? `${probeFailureLabel}${probeSuccessTime ? ` · 上次可用 ${formatDate(probeSuccessTime)}` : ''}`
            : '等待每日自动探测'
        const detailRow = document.createElement('tr')
        detailRow.className = 'collector-site-detail-row'
        detailRow.dataset.tableDetailRow = ''
        detailRow.hidden = true
        const detailCell = document.createElement('td')
        detailCell.colSpan = 8
        const detailPanel = document.createElement('div')
        detailPanel.className = 'collector-site-detail'
        const detailGrid = document.createElement('dl')
        detailGrid.className = 'collector-site-detail-grid'
        const detailItems = [
          ['站点标题', item.display_name || item.site_name || '未知站点'],
          ['站点类型', `${moduleLabel} · ${siteType}`],
          ['可用性', availabilityValue],
          ['最近访问', formatDate(item.last_success_at)],
          ['采集方式', `种子：${fetchModeLabel(item.seed_fetch_mode)} · 详情：${fetchModeLabel(item.detail_fetch_mode)}`],
          ['更新频率', ({ hot: '高频', warm: '常规', cold: '低频' }[String(item.profile || '').toLowerCase()] || '未配置')]
        ]
        const detailValueNodes = new Map()
        detailItems.forEach(([label, value]) => {
          const wrapper = document.createElement('div')
          const term = document.createElement('dt')
          const description = document.createElement('dd')
          term.textContent = label
          description.textContent = value || '-'
          detailValueNodes.set(label, description)
          wrapper.append(term, description)
          detailGrid.appendChild(wrapper)
        })
        const address = document.createElement('div')
        address.className = 'collector-site-address'
        const addressLabel = document.createElement('span')
        addressLabel.textContent = sourceUrls.length > 1 ? `站点地址（${sourceUrls.length} 个入口）` : '站点地址'
        const addressValue = document.createElement('code')
        addressValue.className = 'site-detail-url'
        addressValue.textContent = sourceUrl || '未配置'
        addressValue.title = sourceUrls.join('\n') || '未配置'
        address.append(addressLabel, addressValue)
        detailPanel.appendChild(detailGrid)
        if (item.frontier?.enabled) {
          const frontier = item.frontier
          const progress = document.createElement('div')
          progress.className = 'collector-site-frontier'
          progress.dataset.backfillPaused = String(Boolean(frontier.backfill_paused))
          const counts = document.createElement('p')
          counts.textContent = `待抓 ${frontier.pending || 0} · 执行中 ${frontier.inflight || 0} · 队列已完成 ${frontier.completed || 0}`
          const mode = document.createElement('p')
          mode.textContent = item.enabled === false
            ? '站点已停用，保留队列和回补进度。'
            : frontier.backfill_paused
              ? '积压达到上限，暂停历史回补；继续检查最新页。'
              : `最新页优先，每轮最多回补 ${frontier.backfill_pages_per_run || 0} 个历史页。`
          const cursors = document.createElement('ul')
          const pageCursors = Array.isArray(frontier.page_cursors) ? frontier.page_cursors : []
          pageCursors.forEach((cursor, index) => {
            const entry = document.createElement('li')
            entry.textContent = `分区 ${index + 1}：${cursor.completed_at ? '本轮列表已扫描至末页' : `下次回补第 ${cursor.next_page || 2} 页`}`
            entry.title = cursor.source_url || ''
            cursors.appendChild(entry)
          })
          const note = document.createElement('p')
          note.textContent = `${pageCursors.length ? '' : '尚无历史回补记录。'}队列已完成仅统计已发现任务，不代表站点全部历史数据。`
          progress.append(counts, mode, cursors, note)
          detailPanel.appendChild(progress)
        }
        detailPanel.appendChild(address)
        detailCell.appendChild(detailPanel)
        detailRow.appendChild(detailCell)
        body.appendChild(detailRow)

        const availabilityNode = detailValueNodes.get('可用性')
        if (availabilityNode) {
          const availabilityClass = item.connectivity_available === true
            ? 'is-available'
            : item.connectivity_available === false
              ? 'is-unavailable'
              : 'is-idle'
          availabilityNode.classList.add('collector-site-availability', availabilityClass)
          if (item.connectivity_error) availabilityNode.title = item.connectivity_error
        }

        detailsToggle.addEventListener('click', () => {
          const expanded = detailsToggle.getAttribute('aria-expanded') === 'true'
          row.dataset.expanded = String(!expanded)
          detailsToggle.setAttribute('aria-expanded', String(!expanded))
          detailsToggle.setAttribute('aria-label', `${expanded ? '展开' : '收起'}${item.display_name || item.site_name || '站点'}信息`)
          detailRow.hidden = expanded
        })
      })
      const table = body.closest('table')
      if (table) refreshTable(table)
    }

    async function renderNetdiskCursors(items = []) {
      if (!Array.isArray(items)) return
      const platforms = await request('/api/exposure-platforms?module=document_exposure').catch(() => [])
      const table = $('#netdisk-cursor-table', root)
      const body = $('tbody', table || root)
      if (!table || !body) return
      body.replaceChildren()
      items.forEach((item) => {
        const sourceKey = String(item.sourceKey || '').toLowerCase()
        const sourceLabel = String(item.sourceLabel || '').toLowerCase()
        const platform = platforms.find((candidate) =>
          String(candidate.platform || '').toLowerCase() === sourceKey
          || sourceLabel.includes(String(candidate.label || '').toLowerCase()),
        )
        const rawStatus = String(item.status || '').toLowerCase()
        const healthy = ['healthy', 'ok', 'normal'].includes(rawStatus) && !item.lastError && !item.backoffUntil && item.enabled !== false
        const row = document.createElement('tr')
        const values = [
          item.sourceLabel || item.sourceKey || '未知来源',
          item.domain || platform?.domains?.[0] || '—',
          item.enabled === false ? '已停用' : item.backoffUntil ? '退避中' : item.lastError ? '异常' : statusLabel(item.status || 'healthy')
        ]
        values.forEach((value, index) => {
          const cell = document.createElement('td')
          if (index === 1) cell.className = 'num'
          if (index === 2) {
            const badge = document.createElement('span')
            badge.className = `badge ${healthy ? 'badge-success' : 'badge-high'}`
            badge.textContent = value
            cell.appendChild(badge)
          } else cell.textContent = String(value)
          row.appendChild(cell)
        })
        body.appendChild(row)
      })
      refreshTable(table)
    }

    function renderTasks(payload = {}) {
      const normalizeStatus = (value) => {
        const status = String(value || '').toLowerCase()
        if (['running', 'in_progress', 'started', '运行中'].includes(status)) return 'running'
        if (['queued', 'enqueued', 'pending', 'waiting', '等待中'].includes(status)) return 'enqueued'
        if (['succeeded', 'success', 'completed', 'complete', 'ok', 'healthy', '正常', '已完成'].includes(status)) return 'succeeded'
        if (['failed', 'error', 'partial_failure', '异常', '部分失败', '会话失效', '待登录'].includes(status)) return 'failed'
        if (['stale', 'degraded', '陈旧任务', '异常挂起'].includes(status)) return 'stale'
        if (['cancelled', 'canceled', 'stopped', '已停止'].includes(status)) return 'cancelled'
        return 'unknown'
      }
      const normalizeTask = (item = {}) => {
        const rawStatus = item.status || item.state || item.job_status || item.overall_status
        return {
          site_name: item.display_name || item.site_name || item.site || '',
          job_type: item.job_type || item.type || item.name || '采集任务',
          status: normalizeStatus(rawStatus),
          target: item.target || item.url || item.scope || '',
          message: item.error_message || item.message || item.description || '',
          time: item.finished_at || item.updated_at || item.started_at || item.created_at || item.last_success_at || '',
          id: item.id || item.job_id || '',
          auth_required: Boolean(item.auth_required),
          auth_platform: item.auth_platform || ''
        }
      }
      const recentFailures = Array.isArray(payload.recent_failures) ? payload.recent_failures : []
      const directTasks = [payload.jobs, payload.recent_jobs, payload.task_list].find(Array.isArray)
      let tasks = directTasks ? directTasks.map(normalizeTask) : []

      const summaryOnly = !directTasks
      if (summaryOnly) {
        const siteHealth = Array.isArray(payload.site_health) ? payload.site_health : []
        siteHealth.forEach((site) => {
          const siteName = site.display_name || site.site_name || ''
          const latestFailure = recentFailures.find((item) => item.site_name === site.site_name)
          tasks.push({
            site_name: siteName,
            job_type: latestFailure ? '站点失败摘要' : '站点运行摘要',
            status: normalizeStatus(site.overall_status),
            target: site.auth_required ? (site.auth_platform || '需要平台会话') : '站点级状态',
            message: latestFailure?.error_message || site.last_error || `种子任务：${site.seed_status || '未运行'}；详情任务：${site.detail_status || '未运行'}`,
            time: latestFailure?.finished_at || site.last_success_at || payload.updated_at || '',
            id: '',
            summaryOnly: true,
            auth_required: Boolean(site.auth_required),
            auth_platform: site.auth_platform || ''
          })
        })
      }

      const counts = tasks.reduce((result, item) => {
        result[item.status] = (result[item.status] || 0) + 1
        return result
      }, {})
      bindText('task-count', summaryOnly ? `${tasks.length} 个站点摘要` : `${tasks.length} 条`)
      bindText('task-running-count', counts.running || 0)
      bindText('task-pending-count', counts.enqueued || 0)
      bindText('task-succeeded-count', counts.succeeded || 0)
      bindText('task-failed-count', counts.failed || 0)
      bindText('task-stale-count', counts.stale || 0)
      bindText('task-site-count', new Set(tasks.map((item) => item.site_name).filter(Boolean)).size)
      bindText('failure-total', recentFailures.length)

      const recentFailureTasks = recentFailures.map((item) => normalizeTask({ ...item, status: 'failed' }))
      const failedTasks = tasks.filter((item) => item.status === 'failed')
      const failedCount = Math.max(failedTasks.length, recentFailureTasks.length)
      const latestFailure = [...failedTasks, ...recentFailureTasks]
        .sort((a, b) => String(b.time || '').localeCompare(String(a.time || '')))[0]
      bindText('task-failed-count', failedCount)
      $$('[data-task-nav-alert]').forEach((node) => {
        node.hidden = failedCount === 0
        node.setAttribute('aria-label', failedCount ? `${failedCount} 个失败任务` : '无失败任务')
      })
      $$('[data-task-nav-count]').forEach((node) => {
        node.hidden = failedCount === 0
        node.textContent = String(failedCount)
      })
      const failureAlert = $('[data-task-failure-alert]', root)
      if (failureAlert) {
        failureAlert.hidden = failedCount === 0
        const count = $('[data-task-alert-count]', failureAlert)
        const detail = $('[data-task-alert-detail]', failureAlert)
        if (count) count.textContent = String(failedCount)
        if (detail && latestFailure) detail.textContent = `${latestFailure.site_name || '未知站点'} · ${latestFailure.message || latestFailure.job_type || '任务执行失败'}`
      }

      const list = $('[data-task-list]', root)
      if (!list) return
      if (summaryOnly) {
        const section = $('[data-od-id="collector-task-list-section"]', root)
        const title = $('.collector-table-toolbar > div:first-child > span', section)
        const foot = $('.collector-table-foot > span', section)
        const link = $('.collector-table-foot > a', section)
        if (title) title.textContent = '站点运行摘要'
        if (foot) foot.textContent = '后端当前提供站点级状态与最近失败摘要，不提供单任务编号、进度或日志。'
        if (link) link.textContent = '打开站点摘要 →'
      }
      list.replaceChildren()
      if (!tasks.length) {
        const empty = $(`[data-table-empty="${list.id}"]`, root)
        if (empty) empty.textContent = '暂无任务记录，连接采集服务后将显示各状态任务。'
        refreshTable(list)
        return
      }
      const empty = $(`[data-table-empty="${list.id}"]`, root)
      if (empty) empty.textContent = '没有符合当前筛选条件的任务。'

      tasks
        .sort((a, b) => String(b.time || '').localeCompare(String(a.time || '')))
        .forEach((item) => {
          const article = document.createElement('article')
          article.className = 'task-list-item'
          article.dataset.tableRow = ''
          article.dataset.status = item.status
          article.dataset.type = item.job_type

          const state = document.createElement('div')
          state.className = 'task-state'
          const status = document.createElement('span')
          status.className = `task-status-dot ${item.status}`
          status.textContent = statusLabel(item.status)
          state.appendChild(status)

          const identity = document.createElement('div')
          identity.className = 'task-identity'
          const title = document.createElement('h3')
          title.textContent = item.site_name || '未知站点'
          const type = document.createElement('p')
          type.textContent = item.job_type || '采集任务'
          identity.append(title, type)

          const context = document.createElement('div')
          context.className = 'task-context'
          const target = document.createElement('strong')
          target.textContent = item.target || '—'
          const message = document.createElement('p')
          message.textContent = item.message || ({
            running: '任务正在执行',
            enqueued: '等待调度执行',
            succeeded: '任务已完成',
            failed: '任务执行失败',
            stale: '任务长时间未更新',
            cancelled: '任务已取消'
          }[item.status] || '暂无补充信息')
          context.append(target, message)

          const meta = document.createElement('div')
          meta.className = 'task-meta'
          const time = document.createElement('span')
          time.textContent = formatDate(item.time)
          const detail = document.createElement('a')
          const recordId = String(item.id || 'latest')
          const query = new URLSearchParams({ site: item.site_name || '', job: item.job_type || '' })
          detail.href = `/collector-control/run/${encodeURIComponent(recordId)}?${query.toString()}`
          detail.textContent = item.summaryOnly ? '站点摘要' : '查看详情'
          meta.append(time)
          if (item.auth_required && item.auth_platform) {
            const login = document.createElement('a')
            const loginQuery = new URLSearchParams(query)
            loginQuery.set('login', '1')
            login.href = `/collector-control/run/${encodeURIComponent(recordId)}?${loginQuery.toString()}`
            login.textContent = '内部浏览器登录'
            meta.appendChild(login)
          }
          meta.appendChild(detail)

          article.append(state, identity, context, meta)
          list.appendChild(article)
        })
      refreshTable(list)
    }

    function renderFailureHistory(payload = {}) {
      const history = Array.isArray(payload.failed_job_history) ? payload.failed_job_history : []
      const total = Number(payload.failed_job_history_total ?? history.length)
      const limit = Number(payload.failed_job_history_limit || history.length)
      bindText('failure-history-count', total > history.length ? `最近 ${history.length} 条` : `${total} 条`)

      const list = $('[data-failure-history-list]', root)
      if (!list) return
      list.replaceChildren()
      list.dataset.page = '1'

      const note = $('[data-failure-history-note]', root)
      if (note) {
        note.textContent = total > history.length
          ? `数据库共有 ${total} 条真实失败任务，当前展示最近 ${Math.min(limit, history.length)} 条。`
          : `共 ${total} 条真实失败任务；不受 24 小时窗口和后续成功影响。`
      }

      history.forEach((item) => {
        const article = document.createElement('article')
        article.className = 'task-list-item'
        article.dataset.tableRow = ''
        article.dataset.status = 'failed'
        article.dataset.type = item.job_type || ''

        const state = document.createElement('div')
        state.className = 'task-state'
        const status = document.createElement('span')
        status.className = 'task-status-dot failed'
        status.textContent = '失败'
        state.appendChild(status)

        const identity = document.createElement('div')
        identity.className = 'task-identity'
        const title = document.createElement('h3')
        title.textContent = item.display_name || item.site_name || '未知站点'
        const type = document.createElement('p')
        const jobType = { seed: '种子任务', detail: '详情任务' }[item.job_type] || item.job_type || '采集任务'
        type.textContent = item.queue_name ? `${jobType} · ${item.queue_name}` : jobType
        identity.append(title, type)

        const context = document.createElement('div')
        context.className = 'task-context'
        const target = document.createElement('strong')
        target.textContent = item.target || '—'
        const message = document.createElement('p')
        message.textContent = item.error_message || '任务执行失败'
        context.append(target, message)

        const meta = document.createElement('div')
        meta.className = 'task-meta'
        const time = document.createElement('span')
        time.textContent = formatDate(item.finished_at || item.started_at || item.enqueued_at)
        meta.appendChild(time)
        if (item.duration_ms !== null && item.duration_ms !== undefined && item.duration_ms !== '' && Number.isFinite(Number(item.duration_ms))) {
          const duration = document.createElement('span')
          duration.textContent = `${(Number(item.duration_ms) / 1000).toFixed(1)} 秒`
          meta.appendChild(duration)
        }

        article.append(state, identity, context, meta)
        list.appendChild(article)
      })
      refreshTable(list)
    }

    function renderJobs(payload = {}) {
      const overall = statusLabel(payload.overall_status)
      bindText('running-jobs', Number(payload.running_jobs || 0))
      bindText('stale-jobs', Number(payload.stale_jobs || 0))
      const browser = payload.browser_runtime || {}
      const pool = browser.local_process_pool || {}
      bindText('browser-workers', `${Number(browser.browser_worker_count || 0)}/${Number(browser.browser_concurrency || browser.configured_concurrency || 2)}`)
      bindText('browser-pool', `${Number(pool.running_or_pending || 0)}/${Number(pool.max_workers || browser.browser_concurrency || 2)}`)
      const runtime = payload.runtime_db || {}
      const postgresActive = runtime.database_engine === 'postgresql'
      setBadge('runtime-db-mode', postgresActive ? 'PostgreSQL' : (runtime.using_runtime_db ? 'WSL 运行库' : 'Windows 源库'), postgresActive || runtime.using_runtime_db ? 'badge-success' : 'badge-high')
      bindText('runtime-db-path', runtime.runtime_db_path || '—')
      bindText('source-db-path', runtime.source_db_path || '—')
      bindText('runtime-prepared-at', formatDate(runtime.prepared_at))
      bindText('normalized-count', runtime.copied_counts?.normalized_intelligence_events ?? '—')
      renderSiteHealth(payload.site_health || [])
      renderTasks(payload)
      renderFailureHistory(payload)
      setBadge('site-health-summary', overall === '正常' ? '全部正常' : '部分异常', overall === '正常' ? 'badge-success' : 'badge-high')
    }

    function renderVulnerabilitySync(payload = {}) {
      const active = Boolean(payload.running || payload.enabled)
      const failed = Boolean(payload.last_error)
      setBadge('vulnerability-status', failed ? '同步异常' : payload.running ? '同步中' : payload.enabled ? '自动同步中' : '未启动', failed ? 'badge-high' : active ? 'badge-success' : '')
      bindText('vulnerability-last-sync', formatDate(payload.last_success_at || payload.last_tick_at))
      const interval = $('#vulnerability-interval', root)
      const hours = Math.max(1, Math.round(Number(payload.interval_seconds || 3600) / 3600))
      if (interval && [...interval.options].some((option) => Number(option.value) === hours)) interval.value = String(hours)
    }

    function renderRansomwareSync(payload = {}) {
      bindText('ransomware-count', Number(payload.record_count || 0))
      bindText('ransomware-source', payload.last_source || '—')
      const interval = $('#ransomware-interval', root)
      const hours = Math.max(1, Math.round(Number(payload.interval_seconds || 3600) / 3600))
      if (interval && [...interval.options].some((option) => Number(option.value) === hours)) interval.value = String(hours)
    }

    function renderRansomwareConfig(payload = {}) {
      const configured = Boolean(payload.has_api_key)
      setBadge('ransomware-configured', configured ? '已配置' : '未配置', configured ? 'badge-success' : '')
      const input = $('#ransomware-key', root)
      if (input) {
        input.value = ''
        input.placeholder = configured ? '已配置；留空不修改' : '输入 API Key'
      }
    }

    function renderBot(payload = {}) {
      setBadge('bot-status', payload.configured ? '已配置' : '待配置', payload.configured ? 'badge-success' : '')
      bindText('bot-target-count', Number(payload.chat_target_count || (payload.chat_id ? 1 : 0)))
      bindText('bot-secret-status', payload.has_secret ? '已配置' : '未配置')
    }

    function renderDingTalk(payload = {}) {
      const configured = Boolean(payload.configured)
      const endpoints = Array.isArray(payload.endpoints) ? payload.endpoints : []
      const endpointCount = Number(payload.endpoint_count ?? (endpoints.length || (configured ? 1 : 0)))
      const secretCount = endpoints.length
        ? endpoints.filter((item) => Boolean(item.has_secret)).length
        : (payload.has_secret ? 1 : 0)
      setBadge('dingtalk-status', configured ? `已配置 ${endpointCount} 个` : '待配置', configured ? 'badge-success' : '')
      bindText('dingtalk-webhook-status', configured ? (payload.webhook_host || '已配置') : '未配置')
      bindText('dingtalk-secret-status', payload.has_secret ? '已配置' : '未配置（可选）')
      bindText('dingtalk-endpoint-count', endpointCount)
      bindText('dingtalk-secret-count', secretCount)
      const webhook = $('#dingtalk-webhook', root)
      const secret = $('#dingtalk-secret', root)
      const name = $('#dingtalk-name', root)
      if (webhook) {
        webhook.value = ''
        webhook.placeholder = '输入新的钉钉机器人 Webhook 或 access_token'
      }
      if (secret) secret.value = ''
      if (name) name.value = ''

      const list = $('#dingtalk-endpoint-list', root)
      if (!list) return
      list.replaceChildren()
      if (!endpoints.length) {
        const empty = document.createElement('p')
        empty.className = 'dingtalk-endpoint-empty'
        empty.textContent = '当前对象尚未配置钉钉机器人'
        list.appendChild(empty)
        return
      }
      endpoints.forEach((endpoint, index) => {
        const endpointId = String(endpoint.endpoint_id || '')
        const item = document.createElement('div')
        item.className = 'dingtalk-endpoint-item'

        const identity = document.createElement('div')
        identity.className = 'dingtalk-endpoint-identity'
        const title = document.createElement('strong')
        title.textContent = endpoint.name || `钉钉机器人 ${index + 1}`
        const detail = document.createElement('small')
        detail.textContent = endpoint.has_secret ? '已启用加签' : '未启用加签'
        identity.append(title, detail)

        const maskedWebhook = document.createElement('div')
        maskedWebhook.className = 'dingtalk-endpoint-webhook'
        maskedWebhook.textContent = endpoint.masked_webhook_url || endpoint.webhook_host || 'Webhook 已保存'

        const actions = document.createElement('div')
        actions.className = 'dingtalk-endpoint-row-actions'
        const testButton = document.createElement('button')
        testButton.type = 'button'
        testButton.className = 'btn btn-ghost'
        testButton.textContent = '测试'
        testButton.dataset.dingtalkEndpointTest = endpointId
        const deleteButton = document.createElement('button')
        deleteButton.type = 'button'
        deleteButton.className = 'btn btn-danger'
        deleteButton.textContent = '删除'
        deleteButton.dataset.dingtalkEndpointDelete = endpointId
        deleteButton.dataset.dingtalkEndpointName = title.textContent
        actions.append(testButton, deleteButton)
        item.append(identity, maskedWebhook, actions)
        list.appendChild(item)
      })
    }

    function renderWatchlistNotifications(payload = {}) {
      watchlistNotificationState = payload
      renderMonitoringKeywords(payload.keywords || [])
      renderBot(payload.wechat || {})
      renderDingTalk(payload.dingtalk || {})
      const wechatEnabled = $('#watchlist-wechat-enabled', root)
      const dingtalkEnabled = $('#watchlist-dingtalk-enabled', root)
      const wechatConfigured = Boolean(payload.wechat?.configured)
      const dingtalkConfigured = Boolean(payload.dingtalk?.configured)
      if (wechatEnabled) {
        wechatEnabled.checked = Boolean(payload.wechat_enabled)
        wechatEnabled.disabled = !wechatConfigured
        wechatEnabled.dataset.runtimeUnsupported = wechatConfigured ? '0' : '1'
      }
      if (dingtalkEnabled) {
        dingtalkEnabled.checked = Boolean(payload.dingtalk_enabled)
        dingtalkEnabled.disabled = !dingtalkConfigured
        dingtalkEnabled.dataset.runtimeUnsupported = dingtalkConfigured ? '0' : '1'
      }
      const channelActions = [['bot-test', wechatConfigured], ['bot-delete', wechatConfigured], ['dingtalk-test', dingtalkConfigured], ['dingtalk-delete', dingtalkConfigured]]
      channelActions.forEach(([action, configured]) => {
        const button = $(`[data-collector-action="${action}"]`, root)
        if (!button) return
        button.disabled = !configured
        button.dataset.runtimeUnsupported = configured ? '0' : '1'
      })
      $$('[data-bind="current-watchlist-scope"]', root).forEach((node) => {
        node.textContent = payload.watchlist_name || codeConfigState.watchlists.find((item) => String(item.id) === String(codeConfigState.selectedWatchlistId))?.name || '未选择'
      })
    }

    const watchlistNotificationProfilePayload = () => ({
      keywords: readMonitoringKeywords(),
      wechat_enabled: Boolean($('#watchlist-wechat-enabled', root)?.checked),
      dingtalk_enabled: Boolean($('#watchlist-dingtalk-enabled', root)?.checked)
    })

    async function saveWatchlistNotificationProfile() {
      const watchlistId = codeConfigState.selectedWatchlistId
      if (!watchlistId) throw new Error('请先选择监测对象')
      const payload = await request(`/api/code-monitoring/watchlists/${encodeURIComponent(watchlistId)}/notifications`, {
        method: 'PUT',
        body: JSON.stringify(watchlistNotificationProfilePayload())
      })
      renderWatchlistNotifications(payload)
      return payload
    }

    async function refreshWatchlistNotifications() {
      const watchlistId = codeConfigState.selectedWatchlistId
      if (!watchlistId) {
        renderWatchlistNotifications({ keywords: [], wechat: {}, dingtalk: {} })
        readyCapabilities.delete('monitoring-keywords')
        readyCapabilities.delete('bot')
        readyCapabilities.delete('dingtalk')
        syncMutationButtons()
        syncObjectScopedControls()
        return
      }
      const payload = await request(`/api/code-monitoring/watchlists/${encodeURIComponent(watchlistId)}/notifications`)
      renderWatchlistNotifications(payload)
      readyCapabilities.add('monitoring-keywords')
      readyCapabilities.add('bot')
      readyCapabilities.add('dingtalk')
      syncMutationButtons()
      syncObjectScopedControls()
    }

    async function refreshCollector(options = {}) {
      const tasks = []
      if (root.hasAttribute('data-needs-jobs')) tasks.push(['/api/jobs', renderJobs, 'jobs'])
      if ($('#netdisk-cursor-table', root)) tasks.push(['/api/document-exposures/netdisk/source-health?source_family=netdisk_aggregator', renderNetdiskCursors, 'netdisk'])
      if (root.hasAttribute('data-needs-tor') || $('[data-bind="tor-status"]', root)) tasks.push(['/api/tor-bridge/status', renderTor, 'tor'])
      if (root.hasAttribute('data-needs-bot')) tasks.push(['/api/bot/status', renderBot, 'bot'])
      if ($('[data-bind="dingtalk-status"]', root) && !root.hasAttribute('data-needs-watchlist-notifications')) tasks.push(['/api/dingtalk/status', renderDingTalk, 'dingtalk'])
      if ($('[data-od-id="collector-vulnerability-sync"]', root)) {
        tasks.push(['/api/vulnerabilities/sync/status', renderVulnerabilitySync, 'vulnerability'])
        tasks.push(['/api/ransomware/sync/status', renderRansomwareSync, 'ransomware'])
        tasks.push(['/api/ransomware/config', renderRansomwareConfig, 'ransomware'])
      }
      if (root.hasAttribute('data-needs-platform-access')) {
        tasks.push(['/api/code-monitoring/github-app', renderGithubApp, 'github'])
        tasks.push(['/api/captcha-providers/chaojiying', renderChaojiying, 'chaojiying'])
        tasks.push(['/api/platform-sessions/changan/auto-login', renderChanganAutoLogin, 'changan'])
        tasks.push(['/api/platform-sessions?module=code_monitoring', renderCodeSessions, 'code-sessions'])
      }
      if (root.hasAttribute('data-needs-code-config')) {
        tasks.push(['/api/code-monitoring/watchlists', renderCodeWatchlists, 'watchlists'])
        tasks.push(['/api/exposure-watchlists', renderExposureWatchlists, 'watchlists'])
      }
      if ($('.document-session-grid', root)) tasks.push(['/api/platform-sessions?module=document_exposure', renderDocumentSessions, 'document-sessions'])
      if ($('.source-access-table', root)) tasks.push(['/api/exposure-platforms?module=document_exposure', renderExposurePlatforms, 'exposure-platforms'])
      const results = await Promise.allSettled(tasks.map(async ([url, render]) => render(await request(url))))
      const capabilityResults = new Map()
      tasks.forEach(([, , capability], index) => {
        if (!capability) return
        const states = capabilityResults.get(capability) || []
        states.push(results[index].status === 'fulfilled')
        capabilityResults.set(capability, states)
      })
      capabilityResults.forEach((states, capability) => {
        if (states.every(Boolean)) readyCapabilities.add(capability)
        else readyCapabilities.delete(capability)
      })
      const failures = results.filter((result) => result.status === 'rejected')
      if (root.hasAttribute('data-needs-watchlist-notifications')) {
        try {
          await refreshWatchlistNotifications()
        } catch (error) {
          readyCapabilities.delete('monitoring-keywords')
          readyCapabilities.delete('bot')
          readyCapabilities.delete('dingtalk')
          failures.push({ status: 'rejected', reason: error })
        }
      }
      syncMutationButtons()
      syncObjectScopedControls()
      if (failures.length) {
        const message = failures.map((result) => result.reason?.message).filter(Boolean).join('；') || '真实数据接口加载失败'
        setCollectorState('error', `部分真实数据加载失败：${message}`)
      } else {
        setCollectorState('ready')
      }
      if (!options.silent) {
        const successful = results.filter((result) => result.status === 'fulfilled').length
        showToast(failures.length ? `已刷新 ${successful} 项，${failures.length} 项失败` : '采集状态已刷新')
      }
    }

    async function runAction(button, task, successMessage) {
      if (button.dataset.busy === '1') return
      button.dataset.busy = '1'
      button.classList.add('is-loading')
      button.disabled = true
      try {
        await task()
        showToast(successMessage)
        await refreshCollector({ silent: true })
      } catch (error) {
        if (button.dataset.collectorAction === 'tor-start') {
          setTorRouteState('error')
          try {
            renderTor(await request('/api/tor-bridge/status'))
          } catch {}
        }
        showToast(error.message || '操作失败，请检查采集服务')
      } finally {
        button.dataset.busy = '0'
        button.classList.remove('is-loading')
        button.disabled = false
        syncMutationButton(button)
      }
    }

    const requireDispatched = (payload) => {
      if (payload?.dispatch_mode === 'skipped') throw new Error(payload.message || payload.reason || '任务未触发')
      return payload
    }

    const bridgeLineMode = (line) => {
      const parts = String(line || '').trim().split(/\s+/)
      if (parts[0]?.toLowerCase() === 'bridge') parts.shift()
      const mode = parts[0]?.toLowerCase()
      if (mode === 'meek') return 'meek_lite'
      return ['snowflake', 'obfs4', 'meek_lite', 'webtunnel'].includes(mode) ? mode : 'vanilla'
    }

    function bridgePayload() {
      const selectedMode = $('#tor-mode', root)?.value || torConfigState.bridge_mode || 'snowflake'
      const bridgeLines = String($('#tor-lines', root)?.value || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
      const lineModes = new Set(bridgeLines.map(bridgeLineMode))
      if (bridgeLines.length && selectedMode !== 'custom' && [...lineModes].some((mode) => mode !== selectedMode)) {
        throw new Error(`Bridge 地址协议与所选 ${selectedMode} 模式不一致`)
      }
      if (!bridgeLines.length && selectedMode === 'custom') {
        throw new Error('当前模式需要填写 Bridge 地址')
      }
      return {
        tor_executable: torConfigState.tor_executable || '',
        transport_executable: selectedMode === torConfigState.bridge_mode ? torConfigState.transport_executable || '' : '',
        extra_torrc_lines: Array.isArray(torConfigState.extra_torrc_lines) ? torConfigState.extra_torrc_lines : [],
        data_directory: torConfigState.data_directory || '',
        enabled: Boolean($('#tor-enabled', root)?.checked),
        bridge_mode: selectedMode,
        socks_host: $('#tor-host', root)?.value.trim() || '127.0.0.1',
        socks_port: Number($('#tor-port', root)?.value || 9050),
        bridge_lines: bridgeLines
      }
    }

    root.addEventListener('click', (event) => {
      const button = event.target.closest('button')
      if (!button) return
      const action = button.dataset.collectorAction
      const codeAction = button.dataset.codeAction
      const exposureAction = button.dataset.exposureAction
      const requiredCapability = mutationCapability(button)
      if (requiredCapability && !readyCapabilities.has(requiredCapability)) {
        showToast('相关真实数据尚未加载完成，请先刷新后重试')
        return
      }
      if (button.hasAttribute('data-document-term-add')) {
        renderDocumentTerms([...readDocumentTerms(), { term: '', term_type: 'product_name', enabled: true }])
        $('#document-term-list .document-term-row:last-child input', root)?.focus()
        return
      }
      if (button.hasAttribute('data-document-term-delete')) {
        button.closest('.document-term-row')?.remove()
        const empty = $('[data-document-term-empty]', root)
        if (empty) empty.hidden = $$('#document-term-list .document-term-row', root).length > 0
        return
      }
      if (exposureAction === 'cursor-refresh') return void runAction(button, async () => renderNetdiskCursors(await request('/api/document-exposures/netdisk/source-health?source_family=netdisk_aggregator')), '来源健康已刷新')
      if (exposureAction === 'session-detect') return void runAction(button, async () => {
        const sessions = await request('/api/platform-sessions/auto-detect?module=document_exposure', { method: 'POST' })
        renderDocumentSessions(sessions)
      }, '文库平台会话检测完成')
      if (exposureAction === 'session-login') {
        const platform = documentSessionPlatform(button.closest('.document-session-row'))
        if (!platform) return void showToast('当前后端未提供该平台会话接口')
        return void runAction(button, () => startPlatformLogin(platform), '文库登录流程已启动')
      }
      if (exposureAction === 'session-save') {
        const row = button.closest('.document-session-row')
        const platform = documentSessionPlatform(row)
        if (!platform) return void showToast('当前后端未提供该平台会话接口')
        const account = $('.input', row)?.value.trim() || ''
        if (!account) {
          showToast('请先填写账号标签')
          return
        }
        return void runAction(button, async () => {
          await request(`/api/platform-sessions/${encodeURIComponent(platform)}/save`, { method: 'POST', body: JSON.stringify({ account_label: account }) })
          renderDocumentSessions(await request('/api/platform-sessions?module=document_exposure'))
        }, '文库平台会话已保存')
      }
      if (codeAction === 'watchlist-new') {
        createCodeWatchlist()
        return
      }
      if (codeAction === 'monitoring-keyword-refresh') return void runAction(button, refreshWatchlistNotifications, '当前对象情报监控关键词已刷新')
      if (codeAction === 'monitoring-keyword-add') {
        renderMonitoringKeywords([...readMonitoringKeywords(), { keyword: '', category: 'custom_keywords', weight: 5, enabled: true, match_mode: 'contains' }])
        $('.monitoring-keyword-table tbody tr:last-child input', root)?.focus()
        return
      }
      if (codeAction === 'monitoring-keyword-remove') {
        button.closest('tr')?.remove()
        updateMonitoringKeywordSummary()
        return
      }
      if (codeAction === 'monitoring-keyword-save') {
        if (!readMonitoringKeywords().length) {
          showToast('至少保留一条情报监控关键词')
          return
        }
        return void runAction(button, saveWatchlistNotificationProfile, '当前对象情报监控关键词已保存')
      }
      if (codeAction === 'watchlist-save') return void runAction(button, async () => {
        const saved = await request('/api/code-monitoring/watchlists', { method: 'POST', body: JSON.stringify(codeWatchlistPayload()) })
        if (saved) {
          const currentIndex = codeConfigState.watchlists.findIndex((item) => String(item.id) === String(saved.id))
          if (currentIndex >= 0) codeConfigState.watchlists.splice(currentIndex, 1, saved)
          else codeConfigState.watchlists.push(saved)
          applyCodeWatchlist(saved)
        }
        let savedDocument
        try {
          savedDocument = await request('/api/exposure-watchlists', { method: 'POST', body: JSON.stringify(documentWatchlistPayload()) })
        } catch (error) {
          throw new Error(`代码配置已保存，暴露策略保存失败，可直接重试：${error.message}`)
        }
        if (savedDocument) {
          const documentIndex = documentConfigState.watchlists.findIndex((item) => String(item.id) === String(savedDocument.id))
          if (documentIndex >= 0) documentConfigState.watchlists.splice(documentIndex, 1, savedDocument)
          else documentConfigState.watchlists.push(savedDocument)
          documentConfigState.selectedWatchlistId = savedDocument.id
          applyDocumentWatchlist(savedDocument)
        }
      }, '监测对象与暴露监测配置已保存')
      if (codeAction === 'watchlist-delete') {
        if (!codeConfigState.selectedWatchlistId) {
          showToast('当前对象尚未保存，无需删除')
          return
        }
        if (!window.confirm('删除后将同时移除代码监测与文件暴露配置、检索词、命中结果和扫描历史，但不会影响企业微信或钉钉机器人配置。确认删除此监测对象？')) return
        return void runAction(button, async () => {
          const documentWatchlist = documentWatchlistFor(
            codeConfigState.watchlists.find((item) => String(item.id) === String(codeConfigState.selectedWatchlistId)),
          )
          if (documentWatchlist?.id) {
            try {
              await request('/api/exposure-watchlists/' + encodeURIComponent(documentWatchlist.id), { method: 'DELETE' })
            } catch (error) {
              if (error.status !== 404) throw error
            }
          }
          await request('/api/code-monitoring/watchlists/' + encodeURIComponent(codeConfigState.selectedWatchlistId), { method: 'DELETE' })
          codeConfigState.selectedWatchlistId = null
          documentConfigState.selectedWatchlistId = null
        }, '监测对象已删除')
      }
      if (codeAction === 'github-refresh') return void runAction(button, async () => renderGithubApp(await request('/api/code-monitoring/github-app')), 'GitHub App 状态已刷新')
      if (codeAction === 'github-save') return void runAction(button, async () => {
        const appId = Number($('#github-app-id', root)?.value || 0)
        const installationId = Number($('#github-installation-id', root)?.value || 0)
        if (!Number.isInteger(appId) || appId <= 0 || !Number.isInteger(installationId) || installationId <= 0) throw new Error('App ID 和 Installation ID 必须是正整数')
        const privateKey = $('#github-private-key', root)?.value.trim() || ''
        if ($('[data-bind="github-app-status"]', root)?.textContent === '未配置' && !privateKey) throw new Error('首次配置必须填写 GitHub App 私钥')
        renderGithubApp(await request('/api/code-monitoring/github-app', { method: 'PUT', body: JSON.stringify({ app_id: appId, installation_id: installationId, private_key: privateKey }) }))
      }, 'GitHub App 已连接')
      if (codeAction === 'github-delete') {
        if (!window.confirm('确认删除 GitHub App 配置？现有代码平台会话不会被删除。')) return
        return void runAction(button, () => request('/api/code-monitoring/github-app', { method: 'DELETE' }), 'GitHub App 配置已删除')
      }
      if (codeAction === 'chaojiying-refresh') return void runAction(button, async () => renderChaojiying(await request('/api/captcha-providers/chaojiying')), '超级鹰状态已刷新')
      if (codeAction === 'chaojiying-save') return void runAction(button, async () => {
        const user = $('#chaojiying-user', root)?.value.trim() || ''
        const password = $('#chaojiying-password', root)?.value || ''
        const configured = $('[data-bind="chaojiying-status"]', root)?.dataset.configured === '1'
        if (!configured && (!user || !password)) throw new Error('首次配置必须填写超级鹰账号和密码')
        renderChaojiying(await request('/api/captcha-providers/chaojiying', {
          method: 'PUT',
          body: JSON.stringify({
            user,
            password,
            soft_id: $('#chaojiying-soft-id', root)?.value.trim() || ''
          })
        }))
        renderChanganAutoLogin(await request('/api/platform-sessions/changan/auto-login'))
      }, '超级鹰公共配置已保存')
      if (codeAction === 'chaojiying-delete') {
        if (!window.confirm('删除后，所有依赖超级鹰的站点都将无法自动识别验证码。确认删除？')) return
        return void runAction(button, async () => {
          renderChaojiying(await request('/api/captcha-providers/chaojiying', { method: 'DELETE' }))
          renderChanganAutoLogin(await request('/api/platform-sessions/changan/auto-login'))
        }, '超级鹰公共配置已删除')
      }
      if (codeAction === 'changan-refresh') return void runAction(button, async () => renderChanganAutoLogin(await request('/api/platform-sessions/changan/auto-login')), '长安自动登录状态已刷新')
      if (codeAction === 'changan-save') return void runAction(button, async () => {
        const changanUsername = $('#changan-account', root)?.value.trim() || ''
        const changanPassword = $('#changan-password', root)?.value || ''
        const managedConfigured = $('[data-bind="changan-auto-login-status"]', root)?.dataset.managedConfigured === '1'
        if (!managedConfigured && [changanUsername, changanPassword].some((value) => !value)) {
          throw new Error('首次配置必须填写长安账号和长安密码')
        }
        renderChanganAutoLogin(await request('/api/platform-sessions/changan/auto-login', {
          method: 'PUT',
          body: JSON.stringify({
            enabled: Boolean($('#changan-auto-enabled', root)?.checked),
            changan_username: changanUsername,
            changan_password: changanPassword
          })
        }))
      }, '长安自动登录配置已保存')
      if (codeAction === 'changan-test') {
        if (!window.confirm('本次测试会请求真实验证码并消耗超级鹰题分；识别错误时会自动调用报错接口返分。确认继续？')) return
        return void runAction(button, async () => {
          try {
            renderChanganAutoLogin(await request('/api/platform-sessions/changan/auto-login/test', { method: 'POST' }))
          } catch (error) {
            try { renderChanganAutoLogin(await request('/api/platform-sessions/changan/auto-login')) } catch {}
            throw error
          }
        }, '长安自动登录测试成功')
      }
      if (codeAction === 'changan-delete') {
        if (!window.confirm('删除后会话过期时将无法使用前端保存的凭据自动恢复。确认删除？')) return
        return void runAction(button, async () => renderChanganAutoLogin(await request('/api/platform-sessions/changan/auto-login', { method: 'DELETE' })), '长安自动登录配置已删除')
      }
      if (codeAction === 'sessions-detect') return void runAction(button, async () => renderCodeSessions(await request('/api/platform-sessions/auto-detect?module=code_monitoring', { method: 'POST' })), '平台会话检测完成')
      if (codeAction === 'session-login') return void runAction(button, () => startPlatformLogin(button.dataset.platform), button.dataset.platform + ' 登录流程已启动')
      if (codeAction === 'session-save') return void runAction(button, () => {
        const row = button.closest('[data-code-session-platform]')
        const accountLabel = $('[data-session-account]', row)?.value.trim() || ''
        return request('/api/platform-sessions/' + encodeURIComponent(button.dataset.platform) + '/save', { method: 'POST', body: JSON.stringify({ account_label: accountLabel }) })
      }, button.dataset.platform + ' 会话已保存')
      if (codeAction === 'session-delete') {
        if (!window.confirm('确认删除 ' + button.dataset.platform + ' 平台会话？')) return
        return void runAction(button, () => request('/api/platform-sessions/' + encodeURIComponent(button.dataset.platform), { method: 'DELETE' }), button.dataset.platform + ' 会话已删除')
      }
      if (codeAction === 'term-add') {
        addCodeTerm()
        return
      }
      if (codeAction === 'term-template') {
        try {
          downloadCodeTermTemplate()
          showToast('附加代码检索词模板已生成')
        } catch (error) {
          showToast(error.message || '模板生成失败')
        }
        return
      }
      if (codeAction === 'term-import') {
        $('#code-term-import', root)?.click()
        return
      }
      if (button.hasAttribute('data-code-term-remove')) {
        button.closest('tr')?.remove()
        const table = $('#code-term-table', root)
        if (table) refreshTable(table)
        refreshObjectReadiness()
        return
      }
      if (button.dataset.dingtalkEndpointTest) return void runAction(button, async () => {
        const watchlistId = codeConfigState.selectedWatchlistId
        if (!watchlistId) throw new Error('请先选择监测对象')
        const endpointId = encodeURIComponent(button.dataset.dingtalkEndpointTest)
        const result = await request(`/api/code-monitoring/watchlists/${encodeURIComponent(watchlistId)}/notifications/dingtalk/${endpointId}/test`, {
          method: 'POST',
          body: JSON.stringify({ content: `### 玄鉴威胁情报平台\n> 当前钉钉机器人测试：${new Date().toLocaleString('zh-CN')}` })
        })
        if (Number(result.failed || 0) > 0) throw new Error(result.errors?.[0]?.error || '钉钉机器人测试失败')
        return result
      }, '钉钉机器人测试消息已发送')
      if (button.dataset.dingtalkEndpointDelete) {
        const endpointName = button.dataset.dingtalkEndpointName || '该钉钉机器人'
        if (!window.confirm(`仅删除当前监测对象的“${endpointName}”，其他机器人不受影响。确认删除？`)) return
        return void runAction(button, async () => {
          const watchlistId = codeConfigState.selectedWatchlistId
          if (!watchlistId) throw new Error('请先选择监测对象')
          const endpointId = encodeURIComponent(button.dataset.dingtalkEndpointDelete)
          renderWatchlistNotifications(await request(`/api/code-monitoring/watchlists/${encodeURIComponent(watchlistId)}/notifications/dingtalk/${endpointId}`, { method: 'DELETE' }))
        }, '钉钉机器人已删除')
      }
      if (action === 'refresh') return void refreshCollector()
      if (action === 'filter-failed') {
        const filter = $('[data-filter-target="collector-task-list"][data-filter-key="status"]', root)
        if (filter) {
          filter.value = 'failed'
          filter.dispatchEvent(new Event('change'))
        }
        return
      }
      if (action === 'run-all') return void runAction(button, async () => requireDispatched(await request('/api/jobs/run-all-once', { method: 'POST', body: JSON.stringify({ force: true }) })), '已触发全部站点运行')
      if (action === 'tor-refresh') return void runAction(button, async () => renderTor(await request('/api/tor-bridge/status')), 'Tor 网桥状态已刷新')
      if (action === 'tor-save') return void runAction(button, async () => renderTor(await request('/api/tor-bridge/config', { method: 'POST', body: JSON.stringify(bridgePayload()) })), 'Tor 网桥配置已保存')
      if (action === 'tor-start') return void runAction(button, async () => {
        setTorRouteState('connecting')
        await request('/api/tor-bridge/config', { method: 'POST', body: JSON.stringify(bridgePayload()) })
        renderTor(await request('/api/tor-bridge/start', { method: 'POST' }))
      }, '正在连接 Tor 网桥')
      if (action === 'tor-stop') return void runAction(button, async () => renderTor(await request('/api/tor-bridge/stop', { method: 'POST' })), 'Tor 网桥已停止')
      if (action === 'vulnerability-run') return void runAction(button, () => request('/api/vulnerabilities/sync/run', { method: 'POST', body: JSON.stringify({ limit: 300 }) }), '已触发漏洞同步')
      if (action === 'vulnerability-start') return void runAction(button, () => request('/api/vulnerabilities/sync/start', { method: 'POST', body: JSON.stringify({ interval_seconds: Number($('#vulnerability-interval', root)?.value || 1) * 3600, limit: 300 }) }), '已开启漏洞自动同步')
      if (action === 'vulnerability-stop') return void runAction(button, () => request('/api/vulnerabilities/sync/stop', { method: 'POST' }), '已停止漏洞自动同步')
      if (action === 'ransomware-save') return void runAction(button, () => {
        const apiKey = $('#ransomware-key', root)?.value.trim()
        if (!apiKey) throw new Error('请输入 ransomware.live API Key')
        return request('/api/ransomware/config', { method: 'POST', body: JSON.stringify({ api_key: apiKey }) })
      }, 'ransomware.live API Key 已保存')
      if (action === 'ransomware-run') return void runAction(button, () => request('/api/ransomware/sync/run', { method: 'POST', body: JSON.stringify({ limit: 0 }) }), '已触发 ransomware.live 同步')
      if (action === 'ransomware-start') return void runAction(button, () => request('/api/ransomware/sync/start', { method: 'POST', body: JSON.stringify({ interval_seconds: Number($('#ransomware-interval', root)?.value || 1) * 3600, limit: 0 }) }), '已开启 ransomware.live 自动同步')
      if (action === 'ransomware-stop') return void runAction(button, () => request('/api/ransomware/sync/stop', { method: 'POST' }), '已停止 ransomware.live 自动同步')
      if (action === 'bot-save') return void runAction(button, async () => {
        const watchlistId = codeConfigState.selectedWatchlistId
        if (!watchlistId) throw new Error('请先选择监测对象')
        const botId = $('#bot-id', root)?.value.trim()
        const secret = $('#bot-secret', root)?.value.trim()
        if (botId || secret) {
          if (!botId || !secret) throw new Error('替换企业微信配置时需同时填写 Bot ID 和 Secret')
          await request(`/api/code-monitoring/watchlists/${encodeURIComponent(watchlistId)}/notifications/wechat`, { method: 'PUT', body: JSON.stringify({ bot_id: botId, secret }) })
          const enabled = $('#watchlist-wechat-enabled', root)
          if (enabled) enabled.checked = true
        } else if (!watchlistNotificationState.wechat?.configured) {
          throw new Error('请填写当前监测对象的 Bot ID 和 Secret')
        }
        await saveWatchlistNotificationProfile()
      }, '当前对象企业微信配置已保存')
      if (action === 'bot-delete') {
        if (!window.confirm('仅删除当前监测对象的企业微信配置和已登记会话，不影响其他对象。确认删除？')) return
        return void runAction(button, async () => {
          const watchlistId = codeConfigState.selectedWatchlistId
          if (!watchlistId) throw new Error('请先选择监测对象')
          renderWatchlistNotifications(await request(`/api/code-monitoring/watchlists/${encodeURIComponent(watchlistId)}/notifications/wechat`, { method: 'DELETE' }))
          const botId = $('#bot-id', root)
          const secret = $('#bot-secret', root)
          if (botId) botId.value = ''
          if (secret) secret.value = ''
        }, '当前对象企业微信配置已删除')
      }
      if (action === 'bot-test') return void runAction(button, () => {
        const watchlistId = codeConfigState.selectedWatchlistId
        if (!watchlistId) throw new Error('请先选择监测对象')
        return request(`/api/code-monitoring/watchlists/${encodeURIComponent(watchlistId)}/notifications/wechat_work/test`, { method: 'POST', body: JSON.stringify({ content: `### 玄鉴威胁情报平台\n> 当前监测对象企业微信测试：${new Date().toLocaleString('zh-CN')}` }) })
      }, '当前对象企业微信测试消息已发送')
      if (action === 'dingtalk-save') return void runAction(button, async () => {
        const watchlistId = codeConfigState.selectedWatchlistId
        if (!watchlistId) throw new Error('请先选择监测对象')
        const name = $('#dingtalk-name', root)?.value.trim() || ''
        const webhookUrl = $('#dingtalk-webhook', root)?.value.trim()
        const secret = $('#dingtalk-secret', root)?.value.trim() || ''
        if (!webhookUrl) throw new Error('请输入要添加的钉钉 Webhook 或 access_token')
        renderWatchlistNotifications(await request(`/api/code-monitoring/watchlists/${encodeURIComponent(watchlistId)}/notifications/dingtalk`, {
          method: 'PUT',
          body: JSON.stringify({ name, webhook_url: webhookUrl, secret })
        }))
      }, '钉钉机器人已添加')
      if (action === 'dingtalk-toggle-save') return void runAction(button, saveWatchlistNotificationProfile, '当前对象钉钉启用状态已保存')
      if (action === 'dingtalk-delete') {
        if (!window.confirm('将删除当前监测对象的全部钉钉机器人，不影响其他对象。确认清空？')) return
        return void runAction(button, async () => {
          const watchlistId = codeConfigState.selectedWatchlistId
          if (!watchlistId) throw new Error('请先选择监测对象')
          renderWatchlistNotifications(await request(`/api/code-monitoring/watchlists/${encodeURIComponent(watchlistId)}/notifications/dingtalk`, { method: 'DELETE' }))
        }, '当前对象钉钉机器人已清空')
      }
      if (action === 'dingtalk-test') return void runAction(button, async () => {
        const watchlistId = codeConfigState.selectedWatchlistId
        if (!watchlistId) throw new Error('请先选择监测对象')
        const result = await request(`/api/code-monitoring/watchlists/${encodeURIComponent(watchlistId)}/notifications/dingtalk/test`, { method: 'POST', body: JSON.stringify({ content: `### 玄鉴威胁情报平台\n> 当前监测对象钉钉测试：${new Date().toLocaleString('zh-CN')}` }) })
        if (Number(result.failed || 0) > 0) throw new Error(`已成功 ${result.sent || 0} 个，失败 ${result.failed} 个：${result.errors?.[0]?.error || '请检查机器人配置'}`)
        return result
      }, '全部钉钉机器人测试消息已发送')
      if (button.dataset.siteRun) return void runAction(button, async () => requireDispatched(await request('/api/jobs/run-site', { method: 'POST', body: JSON.stringify({ site_name: button.dataset.siteRun, force: true }) })), `已触发 ${button.dataset.siteRun} 运行一次`)
      if (button.dataset.siteToggle) {
        const enabled = button.dataset.enabled !== 'true'
        return void runAction(button, async () => {
          await request(`/api/sites/${encodeURIComponent(button.dataset.siteToggle)}/enabled`, { method: 'POST', body: JSON.stringify({ enabled }) })
          button.dataset.enabled = String(enabled)
          button.textContent = enabled ? '停用' : '启用'
        }, enabled ? `已启用 ${button.dataset.siteToggle}` : `已停用 ${button.dataset.siteToggle}`)
      }
    })

    const selectCodeWatchlist = (value) => {
      const item = codeConfigState.watchlists.find((candidate) => String(candidate.id) === String(value)) || null
      applyCodeWatchlist(item)
      if (root.hasAttribute('data-needs-watchlist-notifications')) {
        refreshWatchlistNotifications().catch((error) => showToast(error.message || '对象通知配置加载失败'))
      }
    }

    $('#code-watchlist-select', root)?.addEventListener('change', (event) => selectCodeWatchlist(event.target.value))
    $('#code-term-watchlist', root)?.addEventListener('change', (event) => selectCodeWatchlist(event.target.value))
    $('#document-policy-watchlist', root)?.addEventListener('change', (event) => selectCodeWatchlist(event.target.value))
    $('#notification-watchlist-select', root)?.addEventListener('change', (event) => selectCodeWatchlist(event.target.value))

    root.addEventListener('input', (event) => {
      if (event.target.matches('#code-object-name, #code-organization-name, [data-code-profile], [data-code-term-field="term"], [data-document-term-field="term"]')) refreshObjectReadiness()
    })

    root.addEventListener('change', (event) => {
      if (event.target.matches('[data-monitoring-keyword-field]')) {
        if (event.target.matches('[data-monitoring-keyword-field="enabled"]')) {
          const label = event.target.closest('.monitoring-keyword-state')?.querySelector('span')
          if (label) label.textContent = event.target.checked ? '启用' : '停用'
        }
        updateMonitoringKeywordSummary()
      }
      if (event.target.matches('#code-object-name, #code-organization-name, [data-code-profile], [data-code-platform], [data-code-rule], [data-code-term-field], [data-document-field], [data-document-file-type], [data-document-term-field]')) refreshObjectReadiness()
      if (event.target.matches('[data-document-term-field="enabled"]')) {
        const label = event.target.closest('.document-term-state')?.lastElementChild
        if (label) label.textContent = event.target.checked ? '启用' : '停用'
      }
      const control = event.target.closest('[data-code-term-field]')
      if (!control) return
      const row = control.closest('tr')
      if (!row) return
      if (control.dataset.codeTermField === 'enabled') {
        row.dataset.state = control.checked ? 'enabled' : 'disabled'
        const text = control.parentElement?.lastChild
        if (text?.nodeType === Node.TEXT_NODE) text.textContent = control.checked ? '已启用' : '已停用'
      }
      if (control.dataset.codeTermField === 'term_type') row.dataset.type = control.value
      const table = $('#code-term-table', root)
      if (table) refreshTable(table)
    })

    $('#code-term-import', root)?.addEventListener('change', async (event) => {
      const file = event.target.files?.[0]
      event.target.value = ''
      if (!file) return
      try {
        if (!window.XLSX) throw new Error('Excel 组件未加载，请刷新页面后重试')
        const workbook = window.XLSX.read(await file.arrayBuffer(), { type: 'array' })
        const sheetName = workbook.SheetNames.includes('检索词') ? '检索词' : workbook.SheetNames[0]
        if (!sheetName) throw new Error('工作簿中没有可读取的工作表')
        const sheet = workbook.Sheets[sheetName]
        const rows = window.XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '', raw: false }).slice(1)
        const typeMap = {
          企业名称: 'company_name', 企业名: 'company_name', company_name: 'company_name',
          域名: 'domain', domain: 'domain',
          项目名称: 'project_name', 项目名: 'project_name', project_name: 'project_name',
          产品名称: 'product_name', 产品名: 'product_name', product_name: 'product_name',
          自定义: 'custom', custom: 'custom'
        }
        const validTypes = new Set(['company_name', 'domain', 'project_name', 'product_name', 'custom'])
        const existing = readCodeTerms()
        const keys = new Set(existing.map((item) => item.term.toLowerCase() + '|' + item.term_type))
        let added = 0
        let skipped = 0
        let errors = 0
        rows.forEach(([term, rawType, rawEnabled]) => {
          const value = String(term || '').trim()
          const rawTypeValue = String(rawType || '').trim()
          const termType = typeMap[rawTypeValue] || rawTypeValue || 'company_name'
          if (!value || !validTypes.has(termType)) {
            errors += 1
            return
          }
          const key = value.toLowerCase() + '|' + termType
          if (keys.has(key)) {
            skipped += 1
            return
          }
          keys.add(key)
          existing.push({ term: value, term_type: termType, enabled: !['否', 'false', '0', '停用', '禁用'].includes(String(rawEnabled || '').trim().toLowerCase()) })
          added += 1
        })
        renderCodeTerms(existing)
        const summary = $('[data-code-import-summary]', root)
        if (summary) {
          summary.hidden = false
          summary.classList.toggle('has-errors', errors > 0)
          summary.textContent = `导入完成：新增 ${added} 条，重复跳过 ${skipped} 条，错误 ${errors} 行。`
        }
        showToast(`已导入 ${added} 条检索词，跳过 ${skipped} 条，错误 ${errors} 行`)
      } catch (error) {
        const summary = $('[data-code-import-summary]', root)
        if (summary) {
          summary.hidden = false
          summary.classList.add('has-errors')
          summary.textContent = error.message || '检索词导入失败'
        }
        showToast(error.message || '检索词导入失败')
      }
    })

    $('#tor-mode', root)?.addEventListener('change', (event) => renderTorModeHelp(event.target.value))

    $$('.source-access-row input[type="checkbox"]', root).forEach((control) => {
      control.disabled = true
      control.title = '当前后端未提供来源启停接口'
    })
    $$('.source-access-row', root).forEach((row) => {
      const columns = [...row.children]
      const domain = $('.source-domain', row)
      if (domain) domain.textContent = '正在核对…'
      if (columns[2]) columns[2].textContent = '加载中'
      if (columns[3]) columns[3].textContent = '等待真实来源目录'
      const toggle = $('input[type="checkbox"]', row)
      if (toggle) toggle.checked = false
    })
    syncMutationButtons()
    refreshObjectReadiness()
    refreshCollector({ silent: true })
  }

  function setupLogin() {
    const form = $('[data-login-form]')
    if (!form) return
    const password = $('input[name="password"]', form)
    const toggle = $('[data-password-toggle]', form)
    const error = $('[data-login-error]', form)
    const service = $('[data-login-service]')
    const serviceLabel = $('[data-login-service-label]')
    const setServiceState = (state, label) => {
      if (service) service.dataset.state = state
      if (serviceLabel) serviceLabel.textContent = label
    }
    fetch('/api/health', { cache: 'no-store' })
      .then(async (response) => {
        const payload = response.ok ? await response.json() : null
        if (!response.ok || payload?.status !== 'ok') throw new Error('unavailable')
        setServiceState('available', '服务可用')
      })
      .catch(() => setServiceState('unavailable', '服务不可用'))
    toggle?.addEventListener('click', () => {
      const reveal = password.type === 'password'
      password.type = reveal ? 'text' : 'password'
      toggle.setAttribute('aria-label', reveal ? '隐藏密码' : '显示密码')
      toggle.classList.toggle('is-visible', reveal)
    })
    form.addEventListener('submit', async (event) => {
      event.preventDefault()
      const account = $('input[name="account"]', form)
      const firstMissing = [account, password].find((input) => !input.value.trim())
      if (firstMissing) {
        error.textContent = firstMissing === account ? '请输入账号' : '请输入密码'
        firstMissing.focus()
        return
      }
      error.textContent = ''
      const submit = $('.login-submit', form)
      submit.disabled = true
      submit.querySelector('span').textContent = '正在验证…'
      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: account.value.trim(), password: password.value }),
        })
        if (!response.ok) {
          let message = '账号或密码错误'
          try {
            const payload = await response.json()
            message = payload.detail || payload.message || message
          } catch {}
          throw new Error(message)
        }
        const payload = await response.json()
        localStorage.setItem('dwti-auth-token', payload.access_token || '')
        localStorage.setItem('dwti-current-user', JSON.stringify(payload.user || null))
        if (form.elements.remember?.checked) localStorage.setItem('dwti-remembered-account', account.value.trim())
        else localStorage.removeItem('dwti-remembered-account')
        const redirect = new URLSearchParams(window.location.search).get('redirect') || '/'
        window.location.assign(redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : '/')
      } catch (loginError) {
        error.textContent = loginError.message || '登录失败，请稍后重试'
        submit.disabled = false
        submit.querySelector('span').textContent = '进入平台'
      }
    })
    const rememberedAccount = localStorage.getItem('dwti-remembered-account') || ''
    if (rememberedAccount) $('input[name="account"]', form).value = rememberedAccount
  }

  renderSidebar()
  setupSidebar()
  setupVersionUpdate()
  setupAccountMenu()
  setupTables()
  setupTabs()
  setupCodeConfigStatus()
  setupActions()
  setupIntelligenceSearch()
  setupGlobalSearch()
  setupDetailContext()
  setupFileTrees()
  setupWorkspaceSelections()
  setupCollectorControl()
  setupLogin()
}
