import countryCentroidsJson from 'world-countries-centroids/dist/countries.geojson?raw'
import { createRemoteBrowserStream } from '@/utils/remoteBrowserStream'
import { shouldRenderResourceAsImage } from '@/prototype/resourceRendering'

const COUNTRY_COORDINATES = JSON.parse(countryCentroidsJson).features.reduce((coordinates, feature) => {
  const code = feature.properties.ISO
  if (code && !coordinates[code]) coordinates[code] = feature.geometry.coordinates
  return coordinates
}, {})

const INCIDENT_FILES = new Set([
  'event-detail.html',
  'ransomware-detail.html',
  'data-leak-detail.html',
  'vulnerability-detail.html',
])

const REVIEW_FILES = new Set(['netdisk-detail.html', 'library-detail.html', 'code-detail.html'])

const DATA_FILES = new Set([
  'dashboard.html',
  'intelligence.html',
  'ransomware.html',
  'data-leak.html',
  'vulnerabilities.html',
  'monitoring.html',
  'collector-run-detail.html',
  ...INCIDENT_FILES,
  ...REVIEW_FILES,
])

function query(root, selector) {
  return root?.querySelector(selector) || null
}

function queryAll(root, selector) {
  return root ? [...root.querySelectorAll(selector)] : []
}

function showToast(message) {
  let toast = document.querySelector('.toast')
  if (!toast) return
  toast.textContent = message
  toast.classList.add('show')
  window.clearTimeout(showToast.timer)
  showToast.timer = window.setTimeout(() => toast.classList.remove('show'), 2600)
}

const JSON_CACHE_TTL_MS = 15_000
const INTELLIGENCE_PAGE_SIZE = 20
const PAGE_EVENT_LIMIT = 500
const CACHEABLE_JSON_PATHS = new Set([
  '/api/intelligence',
  '/api/intelligence/dashboard',
  '/api/intelligence/ransomware',
  '/api/intelligence/data-leak',
  '/api/events/search',
])
const jsonResponseCache = new Map()
const inFlightJsonRequests = new Map()
const searchResponseCache = new Map()
let searchCacheAccount = ''

async function requestSearch(url) {
  const account = localStorage.getItem('dwti-current-user') || ''
  if (account !== searchCacheAccount) {
    searchResponseCache.clear()
    searchCacheAccount = account
  }
  const cached = searchResponseCache.get(url)
  if (cached && Date.now() - cached.storedAt < JSON_CACHE_TTL_MS) return cached.payload
  const payload = await requestJsonUncached(url)
  if (account === (localStorage.getItem('dwti-current-user') || '')) {
    searchResponseCache.delete(url)
    searchResponseCache.set(url, { payload, storedAt: Date.now() })
    while (searchResponseCache.size > 24) searchResponseCache.delete(searchResponseCache.keys().next().value)
  }
  return payload
}

async function requestJson(url, options = {}) {
  const { preferCached = false, ...fetchOptions } = options
  const method = String(fetchOptions.method || 'GET').toUpperCase()
  const pathname = new URL(url, window.location.origin).pathname
  const cacheable = method === 'GET' && CACHEABLE_JSON_PATHS.has(pathname)
  if (cacheable) {
    const cached = jsonResponseCache.get(url)
    const fresh = cached && Date.now() - cached.storedAt < JSON_CACHE_TTL_MS
    if (cached && (fresh || preferCached)) {
      if (!fresh && !inFlightJsonRequests.has(url)) {
        const refresh = requestJsonUncached(url, fetchOptions)
          .then((payload) => {
            jsonResponseCache.set(url, { storedAt: Date.now(), payload })
            return payload
          })
          .catch(() => cached.payload)
          .finally(() => inFlightJsonRequests.delete(url))
        inFlightJsonRequests.set(url, refresh)
      }
      return cached.payload
    }
    const inFlight = inFlightJsonRequests.get(url)
    if (inFlight) return inFlight
  }

  const request = requestJsonUncached(url, fetchOptions)
  if (!cacheable) return request
  inFlightJsonRequests.set(url, request)
  try {
    const payload = await request
    jsonResponseCache.set(url, { storedAt: Date.now(), payload })
    return payload
  } finally {
    inFlightJsonRequests.delete(url)
  }
}

async function requestJsonUncached(url, options = {}) {
  const headers = new Headers(options.headers || {})
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  const response = await fetch(url, { ...options, headers })
  if (!response.ok) {
    let detail = ''
    try {
      const payload = await response.json()
      detail = payload?.detail || payload?.message || ''
    } catch {
      detail = await response.text().catch(() => '')
    }
    throw new Error(detail || `请求失败（${response.status}）`)
  }
  if (response.status === 204) return null
  return response.json()
}

function number(value) {
  return Number(value || 0).toLocaleString('zh-CN')
}

function parseTimestamp(value) {
  if (value instanceof Date) return value.getTime()
  if (typeof value === 'number') return Number.isFinite(value) ? value : Number.NaN
  const text = String(value || '').trim()
  if (!text) return Number.NaN
  const direct = Date.parse(text)
  if (Number.isFinite(direct)) return direct
  const slashDate = text.match(/^(\d{1,2})\/(\d{1,2})(?:\/(\d{4}))?(?:\s+(\d{1,2}):(\d{2}))?$/)
  if (!slashDate) return Number.NaN
  const first = Number(slashDate[1])
  const second = Number(slashDate[2])
  const hasYear = Boolean(slashDate[3])
  const year = hasYear ? Number(slashDate[3]) : new Date().getFullYear()
  const month = hasYear && first > 12 ? second : first
  const day = hasYear && first > 12 ? first : second
  const timestamp = new Date(year, month - 1, day, Number(slashDate[4] || 0), Number(slashDate[5] || 0)).getTime()
  return month >= 1 && month <= 12 && day >= 1 && day <= 31 ? timestamp : Number.NaN
}

function formatDate(value, withTime = true) {
  if (!value) return '—'
  const timestamp = parseTimestamp(value)
  if (!Number.isFinite(timestamp)) return String(value)
  const date = new Date(timestamp)
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    ...(withTime ? { hour: '2-digit', minute: '2-digit', hour12: false } : {}),
  }).format(date)
}

function usableText(value) {
  const text = String(value || '').trim()
  return /^"?QUERY LENGTH LIMIT EXCEEDED\b/i.test(text) ? '' : text
}

function excerpt(value, limit = 260) {
  const text = usableText(value).replace(/\s+/g, ' ')
  if (!text || text.length <= limit) return text
  return `${text.slice(0, limit).trimEnd()}…`
}

function relativeTime(value) {
  const timestamp = parseTimestamp(value)
  if (!Number.isFinite(timestamp)) return '时间未提供'
  const minutes = Math.max(0, Math.floor((Date.now() - timestamp) / 60000))
  if (minutes < 1) return '刚刚更新'
  if (minutes < 60) return `${minutes} 分钟前`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} 小时前`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days} 天前`
  return formatDate(value, false)
}

function severityOf(item) {
  const raw = String(item?.severity || '').toLowerCase()
  if (['critical', 'high', 'medium', 'low'].includes(raw)) return raw
  const score = Number(item?.riskScore ?? item?.risk_score ?? 0)
  if (score >= 90) return 'critical'
  if (score >= 70) return 'high'
  if (score >= 40) return 'medium'
  return 'low'
}

function severityLabel(value) {
  return { critical: '严重', high: '高危', medium: '中危', low: '低危' }[value] || '未知'
}

function eventType(item) {
  const value = String(item?.normalized_event_type || item?.event_type || item?.raw_source_type || '').toLowerCase()
  if (item?.cveId || item?.cve_id || value.includes('vulnerab')) return 'vulnerability'
  if (value.includes('ransom') || value === 'victim') return 'ransomware'
  if (value.includes('leak') || value === 'forum') return 'data-leak'
  return ''
}

function eventTypeLabel(type) {
  return { vulnerability: '漏洞', ransomware: '勒索', 'data-leak': '数据泄露' }[type] || '情报'
}

function detailHref(item) {
  const id = encodeURIComponent(String(item?.id || ''))
  const type = eventType(item)
  if (type === 'vulnerability') return `/vulnerability-alerts/${id}`
  if (type === 'ransomware') return `/ransomware/${id}`
  if (type === 'data-leak') return `/data-leak/${id}`
  return `/event/${id}`
}

function setText(root, selector, value) {
  const node = query(root, selector)
  if (node) node.textContent = value == null || value === '' ? '—' : String(value)
}

function setCounts(container, values) {
  queryAll(container, 'article').forEach((card, index) => {
    const target = query(card, 'strong[data-count], strong.num, strong')
    if (!target || index >= values.length) return
    const value = Number(values[index] || 0)
    target.textContent = number(value)
    if (target.hasAttribute('data-count')) target.dataset.count = String(value)
    const note = query(card, 'small')
    if (note) note.textContent = '实时数据'
  })
}

function setSummary(group, pairs) {
  queryAll(group, ':scope > div').forEach((item, index) => {
    if (!pairs[index]) return
    const [label, value] = pairs[index]
    const labelNode = query(item, 'span, dt')
    const valueNode = query(item, 'strong, dd')
    if (labelNode) labelNode.textContent = label
    if (valueNode) valueNode.textContent = value == null || value === '' ? '—' : String(value)
  })
}

function setCell(cell, main, sub = '') {
  if (!cell) return
  cell.replaceChildren()
  cell.append(document.createTextNode(main == null || main === '' ? '—' : String(main)))
  if (sub) {
    const secondary = document.createElement('span')
    secondary.textContent = String(sub)
    cell.appendChild(secondary)
  }
}

function setBadgeCell(cell, label, tone = '') {
  if (!cell) return
  cell.replaceChildren()
  const badge = document.createElement('span')
  badge.className = `badge${tone ? ` badge-${tone}` : ''}`
  badge.textContent = label
  cell.appendChild(badge)
}

function setActionCell(cell, label, href) {
  if (!cell) return
  cell.replaceChildren()
  const link = document.createElement('a')
  link.className = 'btn btn-ghost'
  link.href = href
  link.textContent = label
  cell.appendChild(link)
}

function documentTypeMeta(rawType) {
  const type = String(rawType || '').toLowerCase()
  if (type.includes('pdf')) return { label: 'PDF', className: 'pdf' }
  if (type.includes('xls') || type.includes('sheet')) return { label: 'XLS', className: 'xls' }
  if (type.includes('ppt') || type.includes('presentation')) return { label: 'PPT', className: 'ppt' }
  return { label: 'DOC', className: 'doc' }
}

function setDocumentTitleCell(cell, title, rawType) {
  if (!cell) return
  const meta = documentTypeMeta(rawType)
  const content = document.createElement('span')
  content.className = 'document-title-cell'
  const icon = document.createElement('span')
  icon.className = `inline-doc ${meta.className}`
  icon.textContent = meta.label
  const text = document.createElement('span')
  text.className = 'document-title-text'
  text.textContent = title || '—'
  content.append(icon, text)
  cell.replaceChildren(content)
  cell.title = title || ''
}

function setDocumentSourceCell(cell, platform, label) {
  if (!cell) return
  const marks = {
    baidu_wenku: 'baidu-doc',
    baidu_doc: 'baidu-doc',
    baidu: 'baidu-disk',
    baidu_netdisk: 'baidu-disk',
    baidupan_share: 'baidu-disk',
    aliyun: 'aliyun',
    alipan: 'aliyun',
    aliyundrive_share: 'aliyun',
    quark: 'quark',
    quark_share: 'quark',
    quark_doc: 'quark',
    onedrive: 'onedrive',
    onedrive_share: 'onedrive',
    doc88: 'doc88',
    docin: 'docin',
    csdn: 'csdn',
    csdn_wenku: 'csdn',
    csdn_download: 'csdn',
    tencent_wenku: 'tencent-doc',
    github: 'github',
    gitlab: 'gitlab',
    gitee: 'gitee',
  }
  const site = document.createElement('span')
  site.className = 'source-site'
  const mark = marks[String(platform || '').toLowerCase()]
  if (mark) {
    const logo = document.createElement('span')
    logo.className = `source-logo logo-${mark}`
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use')
    use.setAttribute('href', `#mark-${mark}`)
    svg.appendChild(use)
    logo.appendChild(svg)
    site.appendChild(logo)
  }
  const text = document.createElement('span')
  text.textContent = label || platform || '—'
  site.appendChild(text)
  cell.replaceChildren(site)
}

function setClassTextCell(cell, label, className) {
  if (!cell) return
  const value = document.createElement('span')
  value.className = className
  value.textContent = label || '—'
  cell.replaceChildren(value)
}

function setResultStatusCell(cell, label) {
  if (!cell) return
  const status = document.createElement('span')
  const value = label || '未处理'
  const tone = value.includes('确认') ? 'confirmed'
    : value.includes('处理') && !value.includes('未处理') ? 'processing'
      : value.includes('无效') || value.includes('失效') ? 'expired' : 'pending'
  status.className = `result-status ${tone}`
  status.textContent = value
  cell.replaceChildren(status)
}

function replaceFilterOptions(root, selector, placeholder, entries) {
  const select = query(root, selector)
  if (!select) return
  const unique = new Map()
  for (const entry of entries) {
    const value = String(entry?.value ?? entry ?? '').trim()
    const label = String(entry?.label ?? entry ?? '').trim()
    if (value && label && !unique.has(value)) unique.set(value, label)
  }
  const options = [new Option(placeholder, '')]
  for (const [value, label] of unique) options.push(new Option(label, value))
  select.replaceChildren(...options)
}

function formatFullDate(value, withTime = false) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    ...(withTime ? { hour: '2-digit', minute: '2-digit', hour12: false } : {}),
  }).format(date).replaceAll('/', '-')
}

function itemDateValue(item) {
  return item?.updatedTimeRaw
    || item?.updated_time_raw
    || item?.lastSeenAt
    || item?.firstSeenAt
    || item?.disclosureTimeRaw
    || item?.disclosure_time_raw
    || item?.disclosureTime
    || item?.disclosure_time
    || item?.disclosureDate
    || ''
}

function filterByDays(items, days, referenceTime = Date.now()) {
  if (!days) return [...items]
  const cutoff = referenceTime - Number(days) * 24 * 60 * 60 * 1000
  return items.filter((item) => {
    const timestamp = parseTimestamp(itemDateValue(item))
    return Number.isFinite(timestamp) && timestamp >= cutoff && timestamp <= referenceTime + 60 * 60 * 1000
  })
}

function buildDailyTrend(items, days = 7, referenceTime = Date.now()) {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  })
  const buckets = []
  const indexByDate = new Map()
  for (let offset = days - 1; offset >= 0; offset -= 1) {
    const date = new Date(referenceTime - offset * 24 * 60 * 60 * 1000)
    const key = formatter.format(date)
    indexByDate.set(key, buckets.length)
    buckets.push({ date: key, value: 0 })
  }
  for (const item of items) {
    const timestamp = parseTimestamp(itemDateValue(item))
    if (!Number.isFinite(timestamp)) continue
    const key = formatter.format(new Date(timestamp))
    const index = indexByDate.get(key)
    if (index !== undefined) buckets[index].value += 1
  }
  return buckets
}

function chartPoints(values, { xStart, xEnd, yTop, yBottom }) {
  const safeValues = values.length ? values.map((value) => Math.max(0, Number(value || 0))) : [0]
  const maximum = Math.max(1, ...safeValues)
  return safeValues.map((value, index) => ({
    x: safeValues.length === 1 ? (xStart + xEnd) / 2 : xStart + (xEnd - xStart) * index / (safeValues.length - 1),
    y: yBottom - (yBottom - yTop) * value / maximum,
    value,
  }))
}

function evenlySample(items, count) {
  if (items.length <= count) return [...items]
  return Array.from({ length: count }, (_, index) => items[Math.round(index * (items.length - 1) / Math.max(1, count - 1))])
}

function linePath(points) {
  return points.map((point, index) => `${index ? 'L' : 'M'}${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(' ')
}

function areaPath(points, yBottom) {
  if (!points.length) return ''
  return `${linePath(points)} L${points.at(-1).x.toFixed(1)} ${yBottom} L${points[0].x.toFixed(1)} ${yBottom} Z`
}

function setConicChart(node, values, colors, customProperty = '') {
  if (!node) return
  const safeValues = values.map((value) => Math.max(0, Number(value || 0)))
  const total = safeValues.reduce((sum, value) => sum + value, 0)
  let gradient = 'conic-gradient(var(--border) 0 100%)'
  if (total > 0) {
    let start = 0
    const stops = safeValues.map((value, index) => {
      const end = start + value / total * 100
      const stop = `${colors[index % colors.length]} ${start.toFixed(2)}% ${end.toFixed(2)}%`
      start = end
      return stop
    })
    gradient = `conic-gradient(${stops.join(', ')})`
  }
  if (customProperty) node.style.setProperty(customProperty, gradient)
  else node.style.background = gradient
}

function setChartMarkers(group, selector, points, update) {
  if (!group) return
  const nodes = queryAll(group, selector)
  nodes.forEach((node, index) => {
    const point = points[index]
    node.hidden = !point
    node.style.opacity = point ? '1' : '0'
    if (point) update(node, point, index)
  })
}

function sourceLogoKey(value) {
  const label = String(value || '').toLowerCase()
  if (/github/.test(label)) return 'github'
  if (/gitlab/.test(label)) return 'gitlab'
  if (/gitee|码云/.test(label)) return 'gitee'
  if (/百度.*文库|baidu.*wenku|baidu_doc/.test(label)) return 'baidu-doc'
  if (/百度.*网盘|baidupan|baidu_netdisk/.test(label)) return 'baidu-disk'
  if (/阿里|aliyun|alipan/.test(label)) return 'aliyun'
  if (/夸克|quark/.test(label)) return 'quark'
  if (/onedrive/.test(label)) return 'onedrive'
  if (/道客|doc88/.test(label)) return 'doc88'
  if (/豆丁|docin/.test(label)) return 'docin'
  if (/csdn/.test(label)) return 'csdn'
  if (/腾讯.*(?:文库|文档)|tencent_(?:wenku|docs?)/.test(label)) return 'tencent-doc'
  return ''
}

function setSourceLogo(logo, value) {
  if (!logo) return
  const key = sourceLogoKey(value)
  ;[...logo.classList].filter((name) => name.startsWith('logo-')).forEach((name) => logo.classList.remove(name))
  if (key) logo.classList.add(`logo-${key}`)
  const use = query(logo, 'use')
  if (use) use.setAttribute('href', key ? `#mark-${key}` : '')
  logo.hidden = !key
}

function fillSourceDistribution(container, items, total, percentage = false) {
  if (!container) return
  container.__runtimeRowTemplate ||= container.firstElementChild?.cloneNode(true)
  while (container.children.length < items.length && container.__runtimeRowTemplate) {
    container.appendChild(container.__runtimeRowTemplate.cloneNode(true))
  }
  const rows = [...container.children]
  rows.forEach((row, index) => {
    const item = items[index]
    row.hidden = !item
    if (!item) return
    const name = item.name || item.label || item.key || '未知来源'
    const share = Math.round(Number(item.value || 0) / Math.max(1, total) * 100)
    setSourceLogo(query(row, '.source-logo'), name)
    const nestedName = query(row, ':scope > span > strong')
    const nameNode = nestedName || query(row, ':scope > span:not(.source-logo)')
    if (nameNode) nameNode.textContent = name
    const valueNode = nestedName ? query(row, ':scope > span > small') : query(row, ':scope > b')
    if (valueNode) {
      if (valueNode.matches('small')) {
        valueNode.replaceChildren()
        const count = document.createElement('b')
        count.textContent = number(item.value)
        valueNode.append(count, document.createTextNode(` · ${share}%`))
      } else {
        valueNode.textContent = percentage ? `${share}%` : number(item.value)
      }
    }
    row.style.setProperty('--share', `${share}%`)
  })
}

function reviewStatusLabel(value) {
  return {
    new: '待处理',
    triaged: '处理中',
    confirmed: '已确认',
    false_positive: '误报',
    closed: '已关闭',
    suppressed: '已压制',
  }[String(value || '').toLowerCase()] || value || '—'
}

function setLabeledValues(container, values) {
  if (!container) return
  queryAll(container, ':scope > div').forEach((item) => {
    const labelNode = query(item, ':scope > span, :scope > dt')
    const valueNode = query(item, ':scope > strong, :scope > dd')
    if (!labelNode || !valueNode) return
    const label = labelNode.textContent.trim()
    const value = Object.prototype.hasOwnProperty.call(values, label) ? values[label] : '—'
    valueNode.textContent = value == null || value === '' ? '—' : String(value)
  })
}

function ensureDataState(root) {
  let node = query(root, '.runtime-data-state')
  if (node) return node
  const main = query(root, 'main')
  if (!main) return null
  node = document.createElement('div')
  node.className = 'runtime-data-state'
  node.setAttribute('role', 'status')
  main.prepend(node)
  return node
}

function setDataState(root, state, message = '') {
  const node = ensureDataState(root)
  if (!node) return
  node.dataset.state = state
  node.hidden = state === 'ready'
  node.textContent = message || (state === 'loading' ? '正在加载真实数据…' : '')
}

function setActionAvailable(element, available, title = '') {
  if (!element) return
  if ('disabled' in element) element.disabled = !available
  element.classList.toggle('runtime-disabled', !available)
  element.setAttribute('aria-disabled', String(!available))
  if (title) element.title = title
}

function prepareDataPage(root, file) {
  setDataState(root, 'loading', '正在加载真实数据…')
  queryAll(root, '[data-count]').forEach((node) => {
    node.textContent = '—'
    node.dataset.count = ''
  })
  queryAll(root, 'table[data-table]').forEach((table) => clearTable(root, `#${table.id}`))
  queryAll(root, '[data-table-count]').forEach((node) => { node.textContent = '0' })
  queryAll(root, '.actor-rank, .timeline-feed li, .situation-watch-list a, .situation-region-rank .compact-bar, .industry-heat-list > div, .rank-card .bar-row-v2, .vendor-bars > div, .industry-block, .product-bubble, .code-secret-rank > div').forEach((node) => { node.hidden = true })
  queryAll(root, '.source-row').forEach((row) => {
    setText(row, 'small', '0 条 · 可信 0')
    setText(row, 'b', '0%')
  })
  queryAll(root, '.monitor-donut-legend > div, .code-source-grid > div, .code-risk-legend > div, .severity-legend > div, .signal-source-list > div').forEach((node) => { node.hidden = true })
  queryAll(root, '.trend-area, .trend-line, .vuln-area-path, .vuln-line-path, .monitor-area, .monitor-line, .code-line, .situation-spark path').forEach((path) => path.setAttribute('d', ''))
  queryAll(root, '.vuln-points circle, .monitor-points circle, .monitor-columns rect, .monitor-peak-ring, .code-dots circle').forEach((node) => { node.style.opacity = '0' })
  queryAll(root, '.monitor-chart-values text, .monitor-chart-dates text, .code-chart-values text, .code-chart-dates text, .vuln-chart-values text, .chart-labels text, .trend-axis-labels span').forEach((node) => { node.textContent = '—' })
  queryAll(root, '.monitor-trend-summary strong, .trend-summary strong').forEach((node) => { node.textContent = '—' })
  queryAll(root, '[data-pagination-for]').forEach((pagination) => {
    pagination.hidden = true
    setText(pagination, '.table-pagination-summary', '')
  })
  setConicChart(query(root, '.situation-donut'), [], ['var(--danger)'], '--runtime-donut')
  queryAll(root, '.severity-donut, .monitor-donut, .code-risk-donut, .signal-ring').forEach((node) => setConicChart(node, [], ['var(--border)']))

  if (file === 'monitoring.html') {
    queryAll(root, '.monitor-kpi-grid small, .code-kpi-layout small').forEach((node) => { node.textContent = '等待真实接口' })
    queryAll(root, '.monitor-donut-card .meta, .code-risk-card .meta').forEach((node) => { node.textContent = '等待真实接口' })
  }

  if (file === 'dashboard.html') {
    queryAll(root, '.situation-status-strip strong').forEach((node) => { node.textContent = '—' })
    setText(root, '.situation-status-strip > div:first-child small', '等待真实接口')
    queryAll(root, '.situation-kpi-head b').forEach((node) => { node.textContent = '加载中' })
    queryAll(root, '.situation-world .map-point, .situation-map-label').forEach((node) => { node.hidden = true })
    setText(root, '.situation-map-foot > b strong', '—')
    setText(root, '.situation-watch-card .panel-header .badge', '—')
    queryAll(root, '.situation-donut-legend .legend-item b').forEach((node) => { node.textContent = '—' })
    queryAll(root, '.rank-card .rank-badge').forEach((node) => { node.textContent = '—' })
    queryAll(root, '.rank-card .rank-hero strong').forEach((node) => { node.textContent = '正在加载' })
    queryAll(root, '.rank-card .rank-hero span:last-child').forEach((node) => { node.textContent = '等待真实接口' })
  }

  if (file === 'intelligence.html') {
    const list = query(root, '#intel-results')
    if (list) {
      list.__runtimeItemTemplate ||= query(list, '.intel-result-item')?.cloneNode(true)
      list.replaceChildren()
    }
    queryAll(root, '.intel-result-tabs b, [data-intel-total]').forEach((node) => { node.textContent = '0' })
  }

  if (INCIDENT_FILES.has(file) || REVIEW_FILES.has(file) || file === 'collector-run-detail.html') {
    setText(root, 'main h1', '正在加载记录…')
    queryAll(root, '.detail-summary strong, .detail-kpi strong, .definition-grid strong').forEach((node) => { node.textContent = '—' })
    queryAll(root, '.detail-list, .detail-matrix, .timeline').forEach((container) => replaceRecordContainer(container, []))
    queryAll(root, '.detail-code, .detail-log, .detail-proof').forEach((node) => { node.textContent = '—' })
    queryAll(root, '.source-link-line a').forEach((link) => {
      link.removeAttribute('href')
      link.textContent = '—'
    })
    queryAll(root, '.mirror-frame figcaption > *, .mirror-frame-bar time').forEach((node) => { node.textContent = '—' })
    queryAll(root, '.evidence-actions a, .source-link-line a').forEach((link) => {
      link.removeAttribute('href')
      link.hidden = true
    })
    queryAll(root, '[data-copy]').forEach((button) => {
      button.dataset.copy = ''
      delete button.dataset.runtimeCopy
      setActionAvailable(button, false, '等待真实接口数据')
    })
    queryAll(root, '[data-runtime-open], [data-runtime-download]').forEach((button) => {
      delete button.dataset.runtimeOpen
      delete button.dataset.runtimeDownload
      setActionAvailable(button, false, '等待真实接口数据')
    })
  }

  queryAll(root, 'button[data-toast], button[data-disposition]').forEach((button) => {
    setActionAvailable(button, false, '等待真实接口状态')
  })
}

function replaceRows(table, items, fillRow) {
  const body = query(table, 'tbody')
  if (!body) return
  const template = table.__runtimeRowTemplate?.cloneNode(true)
    || query(body, 'tr')?.cloneNode(true)
    || document.createElement('tr')
  const rows = items.map((item) => {
    const row = template.cloneNode(true)
    row.hidden = false
    fillRow(row, item)
    return row
  })
  body.replaceChildren(...rows)
  const count = table.id ? document.querySelector(`[data-table-count="${table.id}"]`) : null
  if (count) count.textContent = String(items.length)
  const empty = table.id ? document.querySelector(`[data-table-empty="${table.id}"]`) : null
  if (empty) empty.style.display = items.length ? 'none' : 'block'
  table.dispatchEvent(new CustomEvent('prototype:rows-updated'))
}

function clearTable(root, selector) {
  const table = query(root, selector)
  const body = query(table, 'tbody')
  if (body) {
    table.__runtimeRowTemplate ||= query(body, 'tr')?.cloneNode(true)
    body.replaceChildren()
  }
  return table
}

function countBy(items, getter) {
  const counts = new Map()
  for (const item of items) {
    const key = String(getter(item) || '未知')
    counts.set(key, (counts.get(key) || 0) + 1)
  }
  return [...counts].map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value)
}

function fillNamedRows(container, items) {
  if (!container) return
  const rows = [...container.children]
  const max = Math.max(1, Number(items[0]?.value || 0))
  rows.forEach((row, index) => {
    const item = items[index]
    row.hidden = !item
    if (!item) return
    const labels = queryAll(row, 'span')
    const name = labels.find((node) => !node.classList.contains('source-logo')) || query(row, 'strong')
    const value = query(row, ':scope > strong:last-child, :scope > b:last-child') || query(row, 'strong:last-child')
    if (name) name.textContent = item.name
    if (value && value !== name) value.textContent = number(item.value)
    const bar = query(row, 'i, .bar-fill-v2')
    if (bar) {
      const percentage = `${Math.round(Number(item.value || 0) / max * 100)}%`
      bar.style.setProperty('--bar', percentage)
      bar.style.setProperty('--value', percentage)
      bar.style.setProperty('--score', percentage)
    }
  })
}

function fillRankCard(card, items, subtitle) {
  if (!card) return
  const first = items[0] || { name: '暂无数据', value: 0 }
  setText(card, '.rank-badge', number(first.value))
  setText(card, '.rank-hero strong', first.name)
  setText(card, '.rank-hero span:last-child', subtitle)
  fillNamedRows(query(card, '.bar-list-v2'), items)
}

function markExports(root, state, tableSelectors) {
  queryAll(root, 'button[data-toast]').forEach((button) => {
    if (!button.textContent.includes('导出')) return
    const panel = button.closest('article, section')
    const table = tableSelectors.map((selector) => query(panel || root, selector) || query(root, selector)).find(Boolean)
    if (!table) return
    button.dataset.runtimeExport = table.id || tableSelectors[0]
    state.tables.set(button.dataset.runtimeExport, table)
    setActionAvailable(button, true)
  })
}

function exportTable(table, filename = '玄鉴数据.csv') {
  if (!table) return
  const lines = queryAll(table, 'tr')
    .filter((row) => !row.hidden)
    .map((row) => queryAll(row, 'th, td').map((cell) => `"${cell.textContent.trim().replaceAll('"', '""')}"`).join(','))
  const blob = new Blob([`\uFEFF${lines.join('\n')}`], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
  showToast('已导出当前真实数据')
}

function installActionGuard(root, state) {
  root.__dataRuntimeAbort?.abort()
  const controller = new AbortController()
  root.__dataRuntimeAbort = controller
  root.addEventListener('click', async (event) => {
    const target = event.target.closest('button, a')
    if (!target || !root.contains(target)) return

    const handled = target.dataset.runtimeExport
      || target.dataset.runtimeRefresh
      || target.dataset.runtimeFilter
      || target.dataset.runtimeReviewStatus
      || target.dataset.runtimeReviewSave
      || target.dataset.runtimeCopy
      || target.dataset.runtimeScroll
      || target.dataset.runtimeTranslate
      || target.dataset.runtimeSource
      || target.dataset.runtimeOpen
      || target.dataset.runtimeDownload
    const unsupported = target.matches('[data-toast], [data-disposition]') && !handled
    if (!handled && !unsupported) return

    event.preventDefault()
    event.stopImmediatePropagation()
    if (unsupported) {
      showToast('当前操作暂无后端接口，暂不支持')
      return
    }
    try {
      if (target.dataset.runtimeExport) {
        exportTable(state.tables.get(target.dataset.runtimeExport))
      } else if (target.dataset.runtimeRefresh) {
        await state.refresh?.()
        showToast('实时数据已刷新')
      } else if (target.dataset.runtimeFilter) {
        const input = query(root, target.dataset.runtimeFilter)
        if (input) {
          input.value = target.dataset.runtimeFilterValue || ''
          input.dispatchEvent(new Event('input', { bubbles: true }))
        }
      } else if (target.dataset.runtimeReviewStatus) {
        state.pendingReviewStatus = target.dataset.runtimeReviewStatus
        queryAll(root, '[data-runtime-review-status]').forEach((button) => button.classList.toggle('btn-primary', button === target))
        const status = query(root, '[data-review-state]')
        if (status) status.textContent = target.dataset.disposition || target.textContent.trim()
        showToast('已选择复核结论，请保存')
      } else if (target.dataset.runtimeReviewSave) {
        await state.saveReview?.()
      } else if (target.dataset.runtimeCopy) {
        await navigator.clipboard.writeText(target.dataset.runtimeCopy || state.copyText || '')
        showToast('已复制到剪贴板')
      } else if (target.dataset.runtimeScroll) {
        query(root, target.dataset.runtimeScroll)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      } else if (target.dataset.runtimeTranslate) {
        await state.toggleTranslation?.()
      } else if (target.dataset.runtimeSource) {
        const source = target.dataset.runtimeSource
        queryAll(root, '[data-runtime-source]').forEach((button) => button.classList.toggle('active', button === target))
        if (state.sourceTable) {
          state.sourceTable.dataset.activeTab = source
          state.sourceTable.dataset.page = '1'
          state.sourceTable.dispatchEvent(new CustomEvent('prototype:rows-updated'))
        }
      } else if (target.dataset.runtimeOpen) {
        window.open(target.dataset.runtimeOpen, '_blank', 'noopener,noreferrer')
      } else if (target.dataset.runtimeDownload) {
        const link = document.createElement('a')
        link.href = target.dataset.runtimeDownload
        link.download = ''
        link.target = '_blank'
        link.rel = 'noopener noreferrer'
        link.click()
      }
    } catch (error) {
      showToast(error.message || '操作失败')
    }
  }, { capture: true, signal: controller.signal })
}

function showLoadError(root, error) {
  const message = error?.message || '数据加载失败'
  setDataState(root, 'error', `真实数据加载失败：${message}`)
  const title = query(root, '.detail-hero h1')
  if (title) title.textContent = '记录加载失败'
  showToast(message)
}

async function hydrateDashboard(root, state) {
  const table = clearTable(root, '#dashboard-events-table')
  const range = state.dashboardRange || query(root, '.situation-range .tab.active')?.dataset.tab || '7d'
  const days = { today: 1, '7d': 7, '30d': 30 }[range] || 7
  state.dashboardRange = range
  const payload = await requestJson(`/api/intelligence/dashboard?days=${days}`)
  const kpis = payload.kpis || []
  setCounts(query(root, '.situation-kpi-grid'), kpis.map((item) => item.value || 0))

  const dashboardCards = queryAll(root, '.situation-kpi-grid .situation-kpi')
  dashboardCards.forEach((card, index) => {
    setText(card, '.situation-kpi-head b', kpis[index]?.highlight || '本期无新增')
  })
  kpis.forEach((item, index) => {
    const path = query(dashboardCards[index], '.situation-spark path')
    if (!path) return
    const points = chartPoints(item.trend || [], { xStart: 2, xEnd: 118, yTop: 4, yBottom: 24 })
    path.setAttribute('d', linePath(points))
  })

  const events = payload.priorityEvents || []
  replaceRows(table, events, (row, item) => {
    const cells = queryAll(row, 'td')
    const type = eventType(item)
    row.dataset.category = type === 'data-leak' ? 'leak' : type
    row.dataset.severity = severityOf(item)
    setCell(cells[0], formatDate(item.updatedTimeRaw || item.disclosureTimeRaw || item.disclosureDate))
    setCell(cells[1], item.title, excerpt(item.summary, 120) || item.category || '暂无摘要')
    setCell(cells[2], eventTypeLabel(type))
    setCell(cells[3], item.region || item.country)
    setCell(cells[4], item.industry, item.vendor || item.product || item.victim)
    setBadgeCell(cells[5], severityLabel(severityOf(item)), severityOf(item))
    setCell(cells[6], item.monitoringPriority || (item.isExploited ? '已利用' : '—'))
    setActionCell(cells[7], '查看', detailHref(item))
  })

  const mapFallback = Boolean(payload.fallback?.geo)
  setText(root, '.situation-live-label span', mapFallback ? '累计地域分布' : '本期地域分布')
  setText(root, '.situation-region-rank .region-rank-head span:last-child', '事件数')
  const countries = payload.geo?.countries || []
  const maxCountryValue = Math.max(1, ...countries.map((item) => Number(item.value || 0)))
  queryAll(root, '.situation-region-rank .compact-bar').forEach((row, index) => {
    const item = countries[index]
    row.hidden = !item
    if (!item) return
    setText(row, ':scope > span', item.name)
    setText(row, ':scope > b', number(item.value))
    query(row, '.bar-fill-v2')?.style.setProperty('--bar', `${Math.round(Number(item.value || 0) / maxCountryValue * 100)}%`)
  })
  const positionedCountries = countries.filter((item) => COUNTRY_COORDINATES[String(item.code || '').toUpperCase()]).slice(0, 5)
  const mapPoints = queryAll(root, '.situation-world .map-point')
  const mapLabels = queryAll(root, '.situation-map-label')
  mapPoints.forEach((point, index) => {
    const item = positionedCountries[index]
    point.hidden = !item
    if (!item) return
    point.title = `${item.name}：${number(item.count)} 条，风险指数 ${number(item.risk)}`
  })
  mapLabels.forEach((label, index) => {
    const item = positionedCountries[index]
    label.hidden = !item
    if (!item) return
    label.style.right = 'auto'
    label.textContent = `${item.name} · ${number(item.count)}`
  })
  const mapWorld = query(root, '.situation-world')
  const mapImage = query(root, '.situation-world-map')
  const positionMapAnnotations = () => {
    if (!mapWorld || !mapImage) return
    const boxWidth = mapImage.clientWidth
    const boxHeight = mapImage.clientHeight
    const imageRatio = (mapImage.naturalWidth || 1200) / (mapImage.naturalHeight || 540)
    const boxRatio = boxWidth / Math.max(1, boxHeight)
    const renderedWidth = boxRatio > imageRatio ? boxHeight * imageRatio : boxWidth
    const renderedHeight = boxRatio > imageRatio ? boxHeight : boxWidth / imageRatio
    const originLeft = mapImage.offsetLeft + (boxWidth - renderedWidth) / 2
    const originTop = mapImage.offsetTop + (boxHeight - renderedHeight) / 2
    mapPoints.forEach((point, index) => {
      const item = positionedCountries[index]
      if (!item) return
      const [longitude, latitude] = COUNTRY_COORDINATES[String(item.code).toUpperCase()]
      point.style.left = `${originLeft + (longitude + 180) / 360 * renderedWidth}px`
      point.style.top = `${originTop + (90 - latitude) / 180 * renderedHeight}px`
      point.style.transform = 'translate(-50%, -50%)'
    })
    mapLabels.forEach((label, index) => {
      const item = positionedCountries[index]
      if (!item) return
      const [longitude, latitude] = COUNTRY_COORDINATES[String(item.code).toUpperCase()]
      const pointLeft = originLeft + (longitude + 180) / 360 * renderedWidth
      const pointTop = originTop + (90 - latitude) / 180 * renderedHeight
      const code = String(item.code).toUpperCase()
      let desiredLeft = pointLeft - label.offsetWidth / 2
      let desiredTop = pointTop - label.offsetHeight - 12
      if (code === 'CA') {
        desiredLeft = pointLeft - label.offsetWidth - 10
        desiredTop = pointTop - label.offsetHeight - 4
      } else if (code === 'US') {
        desiredLeft = pointLeft + 10
        desiredTop = pointTop + 4
      }
      const left = Math.max(4, Math.min(mapWorld.clientWidth - label.offsetWidth - 4, desiredLeft))
      const top = Math.max(4, Math.min(mapWorld.clientHeight - label.offsetHeight - 4, desiredTop))
      label.style.left = `${left}px`
      label.style.top = `${top}px`
    })
  }
  root.__situationMapObserver?.disconnect()
  if (typeof ResizeObserver !== 'undefined' && mapWorld) {
    root.__situationMapObserver = new ResizeObserver(positionMapAnnotations)
    root.__situationMapObserver.observe(mapWorld)
  }
  if (mapImage?.complete) positionMapAnnotations()
  else mapImage?.addEventListener('load', positionMapAnnotations, { once: true })
  queryAll(root, '.situation-route').forEach((routeNode) => { routeNode.hidden = true })
  setText(root, '.situation-map-foot > b strong', number(payload.geo?.averageRisk || 0))
  const industries = payload.industries || []
  queryAll(root, '.industry-heat-list > div').forEach((row, index) => {
    const item = industries[index]
    row.hidden = !item
    if (!item) return
    setText(row, 'b', String(index + 1).padStart(2, '0'))
    setText(row, 'strong', item.name)
    setText(row, 'small', `${number(item.count)} 条真实事件`)
    setText(row, 'em', number(item.value))
  })
  queryAll(root, '.situation-watch-list a').forEach((link, index) => {
    const item = events[index]
    link.hidden = !item
    if (!item) return
    const type = eventType(item)
    link.href = detailHref(item)
    const kind = query(link, '.watch-kind')
    if (kind) kind.dataset.kind = type || 'intelligence'
    setText(link, '.watch-kind', eventTypeLabel(type))
    setText(link, 'div strong', item.title || '未命名事件')
    setText(link, 'div small', [item.region || item.country, item.industry].filter(Boolean).join(' · ') || '实时情报')
    setText(link, ':scope > b', severityLabel(severityOf(item)))
  })
  setText(root, '.situation-watch-card .panel-header .badge', number(Math.min(4, events.length)))
  const distribution = payload.distribution24h || [0, 0, 0, 0]
  queryAll(root, '.situation-donut-legend .legend-item b').forEach((node, index) => {
    node.textContent = number(distribution[index] ?? 0)
  })
  setText(root, '.situation-donut-legend .legend-item:nth-child(4) span', '文件监测')
  const distributionTotal = distribution.reduce((sum, value) => sum + value, 0)
  setText(root, '.situation-donut .donut-core strong', number(distributionTotal))
  const donut = query(root, '.situation-donut')
  if (donut) {
    donut.setAttribute('aria-label', `近 24 小时情报类型分布：勒索 ${distribution[0]}，数据泄露 ${distribution[1]}，漏洞 ${distribution[2]}，文件监测 ${distribution[3]}`)
    setConicChart(donut, distribution, ['var(--danger)', 'var(--warning)', 'var(--accent)', 'var(--secondary)'], '--runtime-donut')
  }
  const trend = payload.threatTrend || {}
  const labels = trend.labels || []
  const totalTrend = trend.total || []
  const highTrend = trend.highRisk || []
  const totalPoints = chartPoints(totalTrend, { xStart: 36, xEnd: 602, yTop: 28, yBottom: 160 })
  const highPoints = chartPoints(highTrend, { xStart: 36, xEnd: 602, yTop: 28, yBottom: 160 })
  query(root, '.situation-trend-chart .trend-line.total')?.setAttribute('d', linePath(totalPoints))
  query(root, '.situation-trend-chart .trend-line.critical')?.setAttribute('d', linePath(highPoints))
  query(root, '.situation-trend-chart .trend-area')?.setAttribute('d', areaPath(highPoints, 160))
  const trendTotals = trend.severityTotals || [0, 0, 0]
  queryAll(root, '.trend-summary > div strong').forEach((node, index) => { node.textContent = number(trendTotals[index] || 0) })
  const trendLabels = ['严重', '高危', '中低危']
  queryAll(root, '.trend-summary > div span').forEach((node, index) => { node.textContent = trendLabels[index] || node.textContent })
  const axisNodes = queryAll(root, '.trend-axis-labels span')
  axisNodes.forEach((node, index) => {
    if (!labels.length) {
      node.textContent = '—'
      return
    }
    const labelIndex = axisNodes.length === 1 ? labels.length - 1 : Math.round(index * (labels.length - 1) / (axisNodes.length - 1))
    node.textContent = labels[labelIndex] || '—'
  })
  const monitoring = payload.monitoringStatus || {}
  setText(root, '.situation-status-strip > div:first-child strong', monitoring.statusLabel || monitoring.statusValue || '监测状态未提供')
  setText(root, '.situation-status-strip > div:first-child small', monitoring.subtitle || monitoring.refreshedValue || '实时接口数据')
  const statusValues = payload.statusCounts || [countries.length, industries.length, 0]
  queryAll(root, '.situation-status-strip > div').slice(1).forEach((item, index) => {
    setText(item, 'strong', number(statusValues[index] || 0))
  })

  const cards = queryAll(root, '.rank-card')
  fillRankCard(cards[0], payload.rankings?.ransomwareActors || [], payload.fallback?.ransomware ? '当前库累计' : '当前周期最活跃')
  fillRankCard(cards[1], payload.rankings?.sensitiveTypes || [], payload.fallback?.dataLeak ? '当前库累计' : '当前周期占比最高')
  fillRankCard(cards[2], payload.rankings?.vulnerabilityVendors || [], '当前周期重点厂商')
  const refresh = queryAll(root, 'button[data-toast]').find((button) => button.textContent.includes('刷新总览'))
  if (refresh) {
    refresh.dataset.runtimeRefresh = 'dashboard'
    setActionAvailable(refresh, true)
  }
  queryAll(root, '.situation-range .tab').forEach((button) => {
    if (button.dataset.runtimeRangeBound) return
    button.dataset.runtimeRangeBound = '1'
    button.addEventListener('click', async () => {
      state.dashboardRange = button.dataset.tab || '7d'
      setDataState(root, 'loading', '正在按统计周期刷新真实数据…')
      try {
        await hydrateDashboard(root, state)
        setDataState(root, 'ready')
      } catch (error) {
        showLoadError(root, error)
      }
    })
  })
  state.refresh = () => hydrateDashboard(root, state)
}

function renderIntelligenceItems(root, events, counts = null) {
  const list = query(root, '#intel-results')
  if (!list) return
  const template = list.__runtimeItemTemplate?.cloneNode(true)
    || query(list, '.intel-result-item')?.cloneNode(true)
  if (!template) return
  const rows = events.map((item) => {
    const row = template.cloneNode(true)
    const type = eventType(item)
    const severity = severityOf(item)
    const eventTime = item.updatedTimeRaw || item.updated_time_raw || item.disclosureTimeRaw || item.disclosure_time_raw || item.disclosure_time || ''
    row.hidden = false
    row.dataset.category = type
    row.dataset.severity = severity
    row.dataset.industry = item.industry || ''
    row.dataset.status = item.is_exploited || item.isExploited ? 'exploited' : 'new'
    row.dataset.date = String(Date.parse(eventTime) || 0)
    row.dataset.severityRank = String({ critical: 4, high: 3, medium: 2, low: 1 }[severity] || 0)
    const thumb = query(row, '.intel-result-thumb')
    if (thumb) {
      const thumbType = type === 'data-leak' ? 'leak' : type
      thumb.className = `intel-result-thumb thumb-${thumbType}`
      thumb.innerHTML = type === 'vulnerability'
        ? '<svg viewBox="0 0 24 24" fill="none"><rect x="7" y="6" width="10" height="13" rx="4"/><path d="M9 6V4m6 2V4M4 10h3m10 0h3M4 15h3m10 0h3M9 12h6m-6 3h6"/></svg>'
        : type === 'ransomware'
          ? '<svg viewBox="0 0 24 24" fill="none"><path d="M6.5 3.5h7l4 4V20h-11Z"/><path d="M13.5 3.5V8h4"/><rect x="9" y="12" width="6.5" height="5.5" rx="1.2"/><path d="M10.6 12v-1a1.65 1.65 0 0 1 3.3 0v1M12.25 14.2v1.2"/></svg>'
          : '<svg viewBox="0 0 24 24" fill="none"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/></svg>'
    }
    const time = query(row, 'time')
    if (time) {
      time.textContent = formatDate(eventTime)
      if (eventTime) time.dateTime = new Date(eventTime).toISOString()
      else time.removeAttribute('datetime')
    }
    const relative = queryAll(row, '.intel-result-meta > span').find((node) => !node.classList.contains('badge'))
    if (relative) relative.textContent = relativeTime(eventTime)
    const badges = queryAll(row, '.intel-result-meta .badge')
    if (badges[0]) badges[0].textContent = severityLabel(severity)
    if (badges[1]) badges[1].textContent = eventTypeLabel(type)
    const title = query(row, 'h2 a')
    if (title) {
      title.textContent = item.title || '未命名事件'
      title.href = detailHref(item)
    }
    setText(row, 'p', excerpt(item.summary || item.detail_text, 260) || '暂无摘要')
    const context = queryAll(row, '.intel-result-context > *')
    const values = [item.attacker || item.vendor || item.source, item.cveId || item.cve_id || item.category, item.industry, item.region || item.country]
    context.forEach((node, index) => { node.textContent = values[index] || '—' })
    return row
  })
  list.replaceChildren(...rows)
  list.dispatchEvent(new CustomEvent('prototype:rows-updated'))
  const resolvedCounts = counts || {
    all: rows.length,
    ransomware: rows.filter((row) => row.dataset.category === 'ransomware').length,
    'data-leak': rows.filter((row) => row.dataset.category === 'data-leak').length,
    vulnerability: rows.filter((row) => row.dataset.category === 'vulnerability').length,
  }
  for (const type of ['all', 'ransomware', 'data-leak', 'vulnerability']) {
    setText(root, `.intel-result-tabs [data-tab="${type}"] b`, Number(resolvedCounts[type] || 0))
  }
  setText(root, '[data-intel-total]', Number(resolvedCounts.all || 0))
}

async function hydrateIntelligence(root) {
  const list = query(root, '#intel-results')
  if (list) {
    list.__runtimeItemTemplate ||= query(list, '.intel-result-item')?.cloneNode(true)
  }
  if (!list) return
  const request = {}
  root.__intelligenceRequest = request
  const account = localStorage.getItem('dwti-current-user') || ''
  if (list.__searchAccount !== account) {
    delete list.dataset.loaded
    list.__searchAccount = account
  }
  const current = () => root.__intelligenceRequest === request && root.contains(list)
    && account === (localStorage.getItem('dwti-current-user') || '')
  if (!list.dataset.loaded) {
    list.replaceChildren()
    queryAll(root, '.intel-result-tabs b, [data-intel-total]').forEach((node) => { node.textContent = '—' })
  }
  setDataState(root, 'loading', list.dataset.loaded ? '正在更新查询结果，暂时显示上次结果…' : '正在查询情报…')
  const empty = query(root, '[data-table-empty="intel-results"]')
  if (empty) empty.hidden = true
  list.inert = true
  list.setAttribute('aria-busy', 'true')
  const pagination = query(root, '[data-pagination-for="intel-results"]')
  if (pagination) pagination.inert = true

  const locationParameters = new URLSearchParams(window.location.search)
  const searchQuery = locationParameters.get('q')?.trim() || ''
  const requestedPage = Math.max(1, Number(locationParameters.get('page') || 1) || 1)
  const requestedType = ['ransomware', 'data-leak', 'vulnerability'].includes(locationParameters.get('type'))
    ? locationParameters.get('type')
    : 'all'
  const requestedSort = ['oldest', 'severity'].includes(locationParameters.get('sort'))
    ? locationParameters.get('sort')
    : 'latest'

  const searchInput = query(root, '[data-table-search="intel-results"]')
  if (searchInput) searchInput.value = searchQuery
  const sortControl = query(root, '[data-intel-sort]')
  if (sortControl) sortControl.value = requestedSort
  list.dataset.activeTab = requestedType
  queryAll(root, '.intel-result-tabs .tab').forEach((button) => {
    const active = button.dataset.tab === requestedType
    button.classList.toggle('active', active)
    button.setAttribute('aria-selected', String(active))
  })

  const navigate = (changes, resetPage = false) => {
    const url = new URL(window.location.href)
    Object.entries(changes).forEach(([key, value]) => {
      if (value == null || value === '' || value === 'all' || (key === 'sort' && value === 'latest')) {
        url.searchParams.delete(key)
      } else {
        url.searchParams.set(key, String(value))
      }
    })
    if (resetPage) url.searchParams.delete('page')
    const target = `${url.pathname}${url.search}`
    if (target === `${window.location.pathname}${window.location.search}`) return
    const link = document.createElement('a')
    link.href = target
    link.hidden = true
    root.appendChild(link)
    link.click()
    link.remove()
  }

  if (!list.__searchNavigationBound) {
    list.__searchNavigationBound = true
    list.addEventListener('prototype:server-refresh', () => hydrateIntelligence(root))
    list.addEventListener('prototype:server-page', (event) => {
      navigate({ page: Math.max(1, Number(event.detail?.page || 1)) })
    })
    list.addEventListener('prototype:server-filter', (event) => {
      navigate({ type: event.detail?.eventType || 'all' }, true)
    })
    list.addEventListener('prototype:server-sort', (event) => {
      navigate({ sort: event.detail?.sort || 'latest' }, true)
    })
  }

  const parameters = new URLSearchParams({
    page: String(requestedPage),
    page_size: String(INTELLIGENCE_PAGE_SIZE),
    event_type: requestedType,
    sort: requestedSort,
  })
  if (searchQuery) parameters.set('q', searchQuery)
  let payload
  try {
    payload = await requestSearch(`/api/events/search?${parameters}`)
  } catch (error) {
    if (current()) {
      list.setAttribute('aria-busy', 'false')
      setDataState(root, 'error', `查询失败：${error.message}。请重新提交查询。`)
    }
    return
  }
  if (!current()) return
  const events = (payload.items || []).filter((item) => eventType(item))
  list.dataset.serverTotal = String(payload.total || 0)
  list.dataset.serverPage = String(payload.page || 1)
  list.dataset.serverPageSize = String(payload.page_size || INTELLIGENCE_PAGE_SIZE)
  list.dataset.serverPageCount = String(payload.page_count || 1)
  if (Number(payload.page || 1) !== requestedPage) {
    const normalizedUrl = new URL(window.location.href)
    if (Number(payload.page || 1) > 1) normalizedUrl.searchParams.set('page', String(payload.page))
    else normalizedUrl.searchParams.delete('page')
    window.history.replaceState({}, '', `${normalizedUrl.pathname}${normalizedUrl.search}`)
  }
  renderIntelligenceItems(root, events, payload.counts || {})
  if (empty) empty.hidden = events.length > 0
  const cutoff = Date.now() - 24 * 60 * 60 * 1000
  const recent = events.filter((item) => {
    const timestamp = new Date(item.updatedTimeRaw || item.updated_time_raw || item.disclosureTimeRaw || item.disclosure_time_raw || 0).getTime()
    return Number.isFinite(timestamp) && timestamp >= cutoff
  })
  const values = [
    recent.filter((item) => eventType(item) === 'ransomware').length,
    recent.filter((item) => eventType(item) === 'data-leak').length,
    recent.filter((item) => eventType(item) === 'vulnerability' && (item.is_exploited || item.isExploited)).length,
    new Set(recent.flatMap((item) => [item.victim, item.attacker, item.vendor]).filter(Boolean)).size,
  ]
  queryAll(root, '.intel-corpus-item b').forEach((node, index) => { node.textContent = number(values[index]) })
  list.dataset.loaded = 'true'
  list.inert = false
  list.setAttribute('aria-busy', 'false')
  if (pagination) pagination.inert = false
  setDataState(root, 'ready')
}

async function hydrateRansomware(root, state) {
  const table = clearTable(root, '#ransomware-table')
  const payload = await requestJson(`/api/intelligence/ransomware?limit=${PAGE_EVENT_LIMIT}`)
  const items = payload.ransomwareEvents || []
  replaceFilterOptions(
    root,
    '[data-filter-target="ransomware-table"][data-filter-key="industry"]',
    '全部行业',
    items.map((item) => item.industry).filter(Boolean),
  )
  const stageOf = (item) => {
    const stage = String(`${item.category || ''} ${item.title || ''}`).toLowerCase()
    if (/发布|公开|published|released|leak/.test(stage)) return { key: 'published', label: item.category || '已发布', tone: 'critical' }
    if (/倒计时|谈判|countdown|negotiat/.test(stage)) return { key: 'countdown', label: item.category || '倒计时', tone: 'high' }
    return { key: 'disclosed', label: item.category || '新披露', tone: '' }
  }
  replaceRows(table, items, (row, item) => {
    const cells = queryAll(row, 'td')
    const stage = stageOf(item)
    row.dataset.category = stage.key
    row.dataset.industry = item.industry || ''
    setCell(cells[0], formatDate(item.disclosureTimeRaw || item.disclosureDate))
    setCell(cells[1], item.victim || item.title, item.title)
    setCell(cells[2], item.attacker || item.sourceSite)
    setBadgeCell(cells[3], stage.label, stage.tone)
    setCell(cells[4], item.industry)
    setCell(cells[5], item.region || item.country)
    setActionCell(cells[6], '查看', detailHref(item))
  })
  const actorCounts = new Map()
  for (const actor of payload.ransomwareActorRanking || []) {
    const name = String(actor.name || '').trim()
    if (!name) continue
    const key = name.toLocaleLowerCase()
    const current = actorCounts.get(key) || { name, value: 0 }
    current.value += Number(actor.value || 0)
    actorCounts.set(key, current)
  }
  const actors = [...actorCounts.values()].sort((a, b) => b.value - a.value).slice(0, 4)
  const actorRows = queryAll(root, '.actor-rank')
  setText(root, '.actor-focus .panel-header .meta', `累计 ${number(items.length)} 条`)
  actorRows.forEach((row, index) => {
    const item = actors[index]
    row.hidden = !item
    if (!item) return
    setText(row, 'b', String(index + 1).padStart(2, '0'))
    setText(row, 'strong', item.name)
    setText(row, 'span', `${number(item.value)} 起 · 占比 ${Math.round(item.value / Math.max(1, items.length) * 100)}%`)
    query(row, 'i')?.style.setProperty('--score', `${Math.round(item.value / Math.max(1, actors[0].value) * 100)}%`)
  })
  if (!actors.length && actorRows[0]) {
    actorRows[0].hidden = false
    setText(actorRows[0], 'b', '—')
    setText(actorRows[0], 'strong', '暂无团伙统计')
    setText(actorRows[0], 'span', '尚未同步包含团伙字段的勒索记录')
    query(actorRows[0], 'i')?.style.setProperty('--score', '0%')
  }
  queryAll(root, '.timeline-feed li').forEach((row, index) => {
    const item = items[index]
    row.hidden = !item
    if (!item) return
    setText(row, 'time', formatDate(item.updatedTimeRaw || item.disclosureTimeRaw))
    setText(row, 'strong', item.title)
    setText(row, 'span', item.category || item.region || '—')
  })
  setText(root, '.action-feed .pulse-label', '接口数据')
  markExports(root, state, ['#ransomware-table'])
}

function leakSource(item) {
  const raw = String(item.raw_source_type || item.event_type || item.sourceSite || '').toLowerCase()
  if (/telegram|chat|即时/.test(raw)) return 'chat'
  if (/victim|ransom|勒索/.test(raw)) return 'ransom'
  if (/forum|论坛/.test(raw)) return 'forum'
  return 'public'
}

async function hydrateDataLeak(root, state) {
  const table = clearTable(root, '#data-leak-table')
  const payload = await requestJson(`/api/intelligence/data-leak?limit=${PAGE_EVENT_LIMIT}`)
  const items = payload.dataLeakEvents || []
  replaceFilterOptions(root, '[data-filter-target="data-leak-table"][data-filter-key="classification"]', '全部事件分类', items.map((item) => item.category).filter(Boolean))
  replaceFilterOptions(root, '[data-filter-target="data-leak-table"][data-filter-key="attacker"]', '全部攻击者', items.map((item) => item.attacker || item.sourceSite || '未披露'))
  replaceFilterOptions(root, '[data-filter-target="data-leak-table"][data-filter-key="industry"]', '全部行业', items.map((item) => item.industry).filter(Boolean))
  replaceRows(table, items, (row, item) => {
    const cells = queryAll(row, 'td')
    const disclosedAt = item.disclosureTimeRaw || item.disclosureDate
    const updatedAt = item.updatedTimeRaw || item.updated_time_raw || disclosedAt
    const classification = item.category || '未分类'
    const attacker = item.attacker || item.sourceSite || '未披露'
    row.dataset.discoveredAt = disclosedAt || updatedAt || ''
    row.dataset.classification = classification
    row.dataset.attacker = attacker
    row.dataset.industry = item.industry || ''
    row.dataset.source = leakSource(item)
    setCell(cells[0], formatFullDate(disclosedAt))
    setCell(cells[1], formatFullDate(updatedAt, true))
    setCell(cells[2], item.title || item.victim || '未命名事件')
    setCell(cells[3], classification)
    setCell(cells[4], attacker)
    setCell(cells[5], item.industry || '—')
    setActionCell(cells[6], '查看', detailHref(item))
  })
  const sourceRows = queryAll(root, '.source-row')
  const sourceKeys = ['forum', 'chat', 'ransom', 'public']
  const recentItems = filterByDays(items, 1)
  setText(root, '.source-monitor .panel-header .meta', '近 24 小时')
  sourceRows.forEach((button, index) => {
    const key = sourceKeys[index]
    const sourceItems = recentItems.filter((item) => leakSource(item) === key)
    const count = sourceItems.length
    const trusted = sourceItems.filter((item) => Number(item.confidenceScore || item.confidence_score || 0) >= 70).length
    const total = Math.max(1, recentItems.length)
    setText(button, 'small', `${number(count)} 条 · 可信 ${number(trusted)}`)
    setText(button, 'b', `${Math.round(count / total * 100)}%`)
    button.dataset.runtimeSource = key
    setActionAvailable(button, true)
  })
  state.sourceTable = table
  const activeSource = query(root, '.source-row.active')?.dataset.runtimeSource
  if (activeSource) {
    table.dataset.activeTab = activeSource
    table.dispatchEvent(new CustomEvent('prototype:rows-updated'))
  }
  markExports(root, state, ['#data-leak-table'])
}

async function hydrateVulnerabilities(root, state) {
  const table = clearTable(root, '#vulnerability-table')
  const days = Number(state.vulnerabilityDays || 7)
  state.vulnerabilityDays = days
  const items = await requestJson(`/api/vulnerabilities?limit=500&days=${days}`)
  replaceFilterOptions(
    root,
    '[data-filter-target="vulnerability-table"][data-filter-key="industry"]',
    '全部行业',
    items.map((item) => item.industry).filter(Boolean),
  )
  const severe = items.filter((item) => Number(item.cvss || 0) >= 9).length
  const exploited = items.filter((item) => item.isExploited || item.is_exploited).length
  const patched = items.filter((item) => item.patchAvailable || item.patch_available).length
  setCounts(query(root, '.vuln-intel-kpis'), [items.length, severe, exploited, patched])
  replaceRows(table, items, (row, item) => {
    const cells = queryAll(row, 'td')
    const severity = severityOf(item)
    row.dataset.category = severity
    row.dataset.severity = severity
    row.dataset.industry = item.industry || ''
    setCell(cells[0], formatDate(item.disclosureTimeRaw || item.disclosure_time_raw || item.disclosureDate, false))
    setCell(cells[1], item.cveId || item.cve_id || item.id, item.title)
    setCell(cells[2], item.vendor, item.product)
    setCell(cells[3], item.industry)
    setCell(cells[4], item.cvss ?? '—')
    setBadgeCell(cells[5], item.isExploited || item.is_exploited ? '已利用' : '未确认', item.isExploited || item.is_exploited ? 'critical' : '')
    setCell(cells[6], item.patchAvailable || item.patch_available ? '可用' : '暂无')
    setActionCell(cells[7], '查看', detailHref(item))
  })
  const severityCounts = ['critical', 'high', 'medium', 'low'].map((key) => ({ name: severityLabel(key), value: items.filter((item) => severityOf(item) === key).length }))
  setText(root, '.severity-donut strong', number(items.length))
  setText(root, '.severity-donut-card .meta', `${number(items.length)} 条`)
  fillNamedRows(query(root, '.severity-legend'), severityCounts)
  setConicChart(query(root, '.severity-donut'), severityCounts.map((item) => item.value), ['var(--danger)', 'var(--warning)', 'var(--accent)', 'var(--secondary)'])
  fillNamedRows(query(root, '.vendor-bars'), countBy(items, (item) => item.vendor).slice(0, 5))
  const industry = countBy(items, (item) => item.industry).slice(0, 5)
  queryAll(root, '.industry-block').forEach((button, index) => {
    const item = industry[index]
    button.hidden = !item
    if (!item) return
    setText(button, 'strong', item.name)
    setText(button, 'span', number(item.value))
    button.dataset.runtimeFilter = '[data-table-search="vulnerability-table"]'
    button.dataset.runtimeFilterValue = item.name
    button.removeAttribute('data-toast')
    setActionAvailable(button, true)
  })
  const products = countBy(items, (item) => item.product).slice(0, 5)
  queryAll(root, '.product-bubble').forEach((button, index) => {
    const item = products[index]
    button.hidden = !item
    if (!item) return
    setText(button, 'strong', item.name)
    setText(button, 'span', number(item.value))
    button.dataset.runtimeFilter = '[data-table-search="vulnerability-table"]'
    button.dataset.runtimeFilterValue = item.name
    button.removeAttribute('data-toast')
    setActionAvailable(button, true)
  })
  setText(root, '.ring-kev strong', exploited)
  setConicChart(query(root, '.ring-kev'), [exploited, Math.max(0, items.length - exploited)], ['var(--danger)', 'var(--bg)'])
  setText(root, '.ring-poc strong', '—')
  setConicChart(query(root, '.ring-poc'), [], ['var(--warning)'])
  const signalRows = queryAll(root, '.signal-source-list > div')
  const signalValues = [
    ['已确认利用', number(exploited)],
    ['补丁可用', number(patched)],
    ['PoC 数据', '—'],
  ]
  signalRows.forEach((row, index) => {
    const item = signalValues[index]
    row.hidden = !item
    if (!item) return
    setText(row, 'span', item[0])
    setText(row, 'b', item[1])
  })

  const trend = buildDailyTrend(items, days)
  const values = trend.map((item) => item.value)
  const points = chartPoints(values, { xStart: 34, xEnd: 700, yTop: 35, yBottom: 185 })
  query(root, '.vuln-line-path')?.setAttribute('d', linePath(points))
  query(root, '.vuln-area-path')?.setAttribute('d', areaPath(points, 205))
  const markerPoints = evenlySample(points, queryAll(root, '.vuln-points circle').length)
  setChartMarkers(query(root, '.vuln-points'), 'circle', markerPoints, (circle, point) => {
    circle.setAttribute('cx', point.x.toFixed(1))
    circle.setAttribute('cy', point.y.toFixed(1))
  })
  setChartMarkers(query(root, '.vuln-chart-values'), 'text', markerPoints, (node, point) => {
    node.textContent = number(point.value)
    node.setAttribute('x', point.x.toFixed(1))
    node.setAttribute('y', Math.max(20, point.y - 10).toFixed(1))
  })
  const sampledTrend = evenlySample(trend, queryAll(root, '.chart-labels text').length)
  queryAll(root, '.chart-labels text').forEach((node, index) => {
    const point = markerPoints[index]
    const item = sampledTrend[index]
    node.hidden = !item
    if (!item) return
    node.textContent = item.date.slice(5)
    node.setAttribute('x', point.x.toFixed(1))
  })
  setText(root, '.vuln-trend-card .trend-summary strong', number(items.length))
  setText(root, '.vuln-trend-card .panel-header .meta', `近 ${days} 天`)
  const chart = query(root, '.vuln-trend-chart')
  if (chart) chart.setAttribute('aria-label', `近 ${days} 天真实漏洞披露趋势，共 ${items.length} 条`)

  const periodButtons = queryAll(root, '[data-od-id="vulnerability-action-section"] .page-actions button')
  periodButtons.forEach((button) => {
    const buttonDays = button.textContent.includes('今日') ? 1 : button.textContent.includes('30') ? 30 : 7
    button.classList.toggle('btn-primary', buttonDays === days)
    button.classList.toggle('btn-secondary', buttonDays !== days)
    if (button.dataset.runtimePeriodBound) return
    button.dataset.runtimePeriodBound = '1'
    button.addEventListener('click', async () => {
      state.vulnerabilityDays = buttonDays
      setDataState(root, 'loading', '正在按统计周期刷新真实漏洞数据…')
      try {
        await hydrateVulnerabilities(root, state)
        setDataState(root, 'ready')
      } catch (error) {
        showLoadError(root, error)
      }
    })
  })
  state.refresh = () => hydrateVulnerabilities(root, state)
  markExports(root, state, ['#vulnerability-table'])
}

function fillDistribution(container, items, total, percentage = false) {
  if (!container) return
  const rows = [...container.children]
  rows.forEach((row, index) => {
    const item = items[index]
    row.hidden = !item
    if (!item) return
    const labels = queryAll(row, 'span')
    const name = labels[labels.length - 1]
    if (name) name.textContent = item.name || item.label || item.key
    const value = query(row, 'b, strong')
    if (value) value.textContent = percentage ? `${Math.round(item.value / Math.max(1, total) * 100)}%` : number(item.value)
  })
}

function renderMonitorTrend(surface, trendItems) {
  const trend = (trendItems || []).map((item) => ({ date: String(item.date || ''), value: Number(item.value || 0) }))
  const values = trend.map((item) => item.value)
  const points = chartPoints(values, { xStart: 42, xEnd: 718, yTop: 30, yBottom: 184 })
  query(surface, '.monitor-line')?.setAttribute('d', linePath(points))
  query(surface, '.monitor-area')?.setAttribute('d', areaPath(points, 184))
  setChartMarkers(query(surface, '.monitor-points'), 'circle', points, (circle, point) => {
    circle.setAttribute('cx', point.x.toFixed(1))
    circle.setAttribute('cy', point.y.toFixed(1))
  })
  setChartMarkers(query(surface, '.monitor-columns'), 'rect', points, (rect, point) => {
    rect.setAttribute('x', (point.x - 15).toFixed(1))
    rect.setAttribute('y', point.y.toFixed(1))
    rect.setAttribute('width', '30')
    rect.setAttribute('height', Math.max(0, 184 - point.y).toFixed(1))
  })
  queryAll(surface, '.monitor-chart-values text').forEach((node, index) => {
    const point = points[index]
    node.hidden = !point
    if (!point) return
    node.textContent = number(point.value)
    node.setAttribute('x', Math.min(718, Math.max(42, point.x)).toFixed(1))
    node.setAttribute('y', Math.max(18, point.y - 12).toFixed(1))
  })
  queryAll(surface, '.monitor-chart-dates text').forEach((node, index) => {
    const item = trend[index]
    const point = points[index]
    node.hidden = !item
    if (!item) return
    node.textContent = item.date.slice(5) || '—'
    node.setAttribute('x', Math.min(718, Math.max(42, point.x)).toFixed(1))
  })
  const peakValue = values.length ? Math.max(...values) : 0
  const peakIndex = peakValue > 0 ? values.indexOf(peakValue) : -1
  const peakPoint = points[peakIndex]
  const peak = query(surface, '.monitor-peak-ring')
  if (peak) {
    peak.style.opacity = peakPoint ? '1' : '0'
    if (peakPoint) {
      peak.setAttribute('cx', peakPoint.x.toFixed(1))
      peak.setAttribute('cy', peakPoint.y.toFixed(1))
    }
  }
  const total = values.reduce((sum, value) => sum + value, 0)
  const average = values.length ? Math.round(total / values.length) : 0
  const first = values[0] || 0
  const last = values.at(-1) || 0
  const change = first > 0 ? (last - first) / first * 100 : null
  const summaryCards = queryAll(surface, '.monitor-trend-summary > div')
  const summaryValues = [number(total), number(average), number(peakValue), change == null ? '—' : `${change >= 0 ? '+' : ''}${change.toFixed(1)}%`]
  summaryCards.forEach((card, index) => {
    setText(card, 'strong', summaryValues[index])
    if (index === 2) setText(card, 'small', trend[peakIndex]?.date?.slice(5) || '—')
    if (index === 3) {
      const value = query(card, 'strong')
      value?.classList.toggle('is-up', change != null && change > 0)
      value?.classList.toggle('is-down', change != null && change < 0)
    }
  })
  const chart = query(surface, '.monitor-trend-chart')
  if (chart) chart.setAttribute('aria-label', `近七天真实监测趋势：共 ${total} 条，峰值 ${peakValue}`)
}

function renderCodeTrend(root, trendItems) {
  const trend = (trendItems || []).map((item) => ({ date: String(item.date || ''), value: Number(item.value || 0) }))
  const points = chartPoints(trend.map((item) => item.value), { xStart: 42, xEnd: 678, yTop: 36, yBottom: 180 })
  query(root, '.code-line')?.setAttribute('d', linePath(points))
  setChartMarkers(query(root, '.code-dots'), 'circle', points, (circle, point) => {
    circle.setAttribute('cx', point.x.toFixed(1))
    circle.setAttribute('cy', point.y.toFixed(1))
  })
  queryAll(root, '.code-chart-values text').forEach((node, index) => {
    const point = points[index]
    node.hidden = !point
    if (!point) return
    node.textContent = number(point.value)
    node.setAttribute('x', point.x.toFixed(1))
    node.setAttribute('y', Math.max(18, point.y - 14).toFixed(1))
  })
  queryAll(root, '.code-chart-dates text').forEach((node, index) => {
    const item = trend[index]
    const point = points[index]
    node.hidden = !item
    if (!item) return
    node.textContent = item.date.slice(5) || '—'
    node.setAttribute('x', point.x.toFixed(1))
  })
  const chart = query(root, '.code-trend-chart')
  if (chart) chart.setAttribute('aria-label', `近七天真实代码监测趋势，共 ${trend.reduce((sum, item) => sum + item.value, 0)} 条`)
}

function accessStatusMeta(item) {
  const state = String(item?.accessState || '').toLowerCase()
  const label = item?.accessStateLabel || item?.reviewStatusLabel || reviewStatusLabel(item?.reviewStatus)
  if (['removed', 'forbidden', 'invalid'].includes(state)) return { label, className: 'result-status expired' }
  if (['captcha', 'login_required', 'rate_limited', 'unknown'].includes(state)) return { label, className: 'result-status pending' }
  if (state === 'public') return { label, className: 'result-status active' }
  return { label, className: 'result-status processing' }
}

const DOCUMENT_HIT_PAGE_SIZE = 20

function documentHitPageUrl(root, source, page) {
  const surface = query(root, `.${source === 'netdisk' ? 'netdisk' : 'library'}-surface`)
  const params = new URLSearchParams({
    source_family: source === 'netdisk' ? 'netdisk_aggregator' : 'document_library',
    offset: String((page - 1) * DOCUMENT_HIT_PAGE_SIZE),
    limit: String(DOCUMENT_HIT_PAGE_SIZE),
  })
  queryAll(surface, '[data-document-hit-filter]').forEach((control) => {
    const key = control.dataset.documentHitFilter
    const value = String(control.value || '').trim()
    if (!value) return
    if (key === 'recent_days') params.set('recent_hours', String(Math.max(1, Number(value)) * 24))
    else params.set(key, value)
  })
  return `/api/document-exposures/page?${params.toString()}`
}

async function reloadDocumentMonitoringData(root, state, source, pageState) {
  if (pageState.loading) return
  pageState.loading = true
  const sourceFamily = source === 'netdisk' ? 'netdisk_aggregator' : 'document_library'
  const tableSelector = source === 'netdisk' ? '#netdisk-table' : '#library-table'
  const table = clearTable(root, tableSelector)
  const surface = query(root, `.${source === 'netdisk' ? 'netdisk' : 'library'}-surface`)
  try {
    const [summary, pagePayload] = await Promise.all([
      pageState.summary || requestJson(`/api/document-exposures/summary?source_family=${sourceFamily}`),
      requestJson(documentHitPageUrl(root, source, pageState.page)),
    ])
    pageState.summary = summary
    const items = pagePayload.items || []
    setCodeServerPage(table, pagePayload)
    replaceFilterOptions(
      root,
      `[data-filter-target="${source === 'netdisk' ? 'netdisk-table' : 'library-table'}"][data-filter-key="${source === 'netdisk' ? 'platform' : 'source'}"]`,
      source === 'netdisk' ? '全部平台' : '全部来源',
      summary.platformOptions || [],
    )
    const kpis = source === 'netdisk'
      ? [summary.totalHits, summary.highRiskCount, summary.passwordShareCount, summary.invalidCount]
      : [summary.publicCount, summary.totalHits, summary.highRiskCount, summary.recentCount]
    setCounts(query(surface, '.monitor-kpi-grid'), kpis)
    replaceRows(table, items, (row, item) => {
      const cells = queryAll(row, 'td')
      const severity = severityOf(item)
      row.dataset.platform = item.platform
      if (source === 'library') row.dataset.source = item.platform
      row.dataset.severity = severity
      row.dataset.discoveredAt = item.lastSeenAt || item.firstSeenAt || ''
      if (source === 'netdisk') {
        setCell(cells[0], item.primaryFileName || item.title)
        setDocumentSourceCell(cells[1], item.platform, item.platformLabel)
        setClassTextCell(cells[2], item.shareCode ? '口令分享' : '公开分享', `share-type ${item.shareCode ? 'password' : 'public'}`)
        setCell(cells[3], item.shareCode || '—')
        setCell(cells[4], item.primaryFileSize || '—')
        setCell(cells[5], (item.matchedTerms || []).map((term) => term.term).join('、'))
        setBadgeCell(cells[6], severityLabel(severity), severity)
        setCell(cells[7], formatDate(item.lastSeenAt || item.firstSeenAt))
        const status = accessStatusMeta(item)
        setClassTextCell(cells[8], status.label, status.className)
        setActionCell(cells[9], '查看', `/document-exposure/detail/netdisk_aggregator/${encodeURIComponent(item.id)}`)
      } else {
        setDocumentTitleCell(cells[0], item.title, item.primaryFileType)
        setDocumentSourceCell(cells[1], item.platform, item.platformLabel)
        setCell(cells[2], item.primaryFileType || '—')
        setCell(cells[3], '—')
        setCell(cells[4], (item.matchedTerms || []).map((term) => term.term).join('、'))
        setCell(cells[5], item.shareOwner || '—')
        setBadgeCell(cells[6], severityLabel(severity), severity)
        setCell(cells[7], formatDate(item.lastSeenAt || item.firstSeenAt))
        const review = item.reviewStatusLabel || reviewStatusLabel(item.reviewStatus)
        const access = item.accessStateLabel || ''
        setResultStatusCell(cells[8], [review, access && access !== review ? access : ''].filter(Boolean).join(' · '))
        setActionCell(cells[9], '详情', `/document-exposure/detail/document_library/${encodeURIComponent(item.id)}`)
      }
    })
    setText(surface, '.monitor-donut strong', number(summary.totalHits))
    setText(surface, '.monitor-donut-card .meta', `总计 ${number(summary.totalHits)}`)
    const distribution = summary.platformDistribution || []
    fillSourceDistribution(query(surface, '.monitor-donut-legend'), distribution, summary.totalHits, source === 'library')
    setConicChart(query(surface, '.monitor-donut'), distribution.map((item) => item.value), ['var(--accent)', 'var(--warning)', 'var(--secondary)', 'var(--success)', 'var(--violet)'])
    renderMonitorTrend(surface, summary.trend || [])
    markExports(surface, state, [tableSelector])
    if (source === 'library') {
      const batchReview = queryAll(surface, 'button[data-toast]').find((button) => button.textContent.includes('批量复核'))
      if (batchReview) setActionAvailable(batchReview, false, '后端未提供批量复核接口')
    }
  } finally {
    pageState.loading = false
  }
}

function setupDocumentMonitoringFilters(root, source, pageState, reload) {
  const surface = query(root, `.${source === 'netdisk' ? 'netdisk' : 'library'}-surface`)
  let searchTimer = null
  queryAll(surface, '[data-document-hit-filter]').forEach((control) => {
    const eventName = control.dataset.documentHitFilter === 'query' ? 'input' : 'change'
    control.addEventListener(eventName, () => {
      window.clearTimeout(searchTimer)
      searchTimer = window.setTimeout(() => {
        pageState.page = 1
        reload()
      }, eventName === 'input' ? 300 : 0)
    })
  })
  const table = query(root, source === 'netdisk' ? '#netdisk-table' : '#library-table')
  table?.addEventListener('prototype:server-page', (event) => {
    pageState.page = Math.max(1, Number(event.detail?.page || 1))
    reload()
  })
}

async function hydrateDocumentMonitoring(root, state, source) {
  const pageState = { page: 1, loading: false, summary: null }
  const reload = () => reloadDocumentMonitoringData(root, state, source, pageState)
  setupDocumentMonitoringFilters(root, source, pageState, reload)
  await reload()
}

const CODE_CONTINUOUS_INTERVAL_SECONDS = 3600
const CODE_HIT_PAGE_SIZE = 20

function renderCodeContinuousStatus(root, status = {}, errorMessage = '') {
  const stateNode = query(root, '[data-code-scan-state]')
  const toggle = query(root, '[data-code-scan-toggle]')
  const lastSuccess = query(root, '[data-code-scan-last-success]')
  const result = query(root, '[data-code-scan-result]')
  const evidence = query(root, '[data-code-scan-evidence]')
  const error = query(root, '[data-code-scan-error]')
  const enabled = Boolean(status.enabled)
  const running = Boolean(status.running)
  const configurationMissing = Boolean(status.configuration_missing)

  if (stateNode) {
    stateNode.textContent = configurationMissing ? '待配置' : errorMessage ? '状态异常' : running ? '扫描中' : enabled ? '运行中' : '未启动'
    stateNode.className = `badge ${configurationMissing ? 'badge-info' : errorMessage ? 'badge-high' : enabled ? 'badge-success' : 'badge-info'}`
  }
  if (lastSuccess) lastSuccess.textContent = status.last_success_at ? formatDate(status.last_success_at) : '暂无'
  if (result) result.textContent = `主表 ${number(status.new_primary_hit_count)} / 压制 ${number(status.new_suppressed_hit_count)} / 更新 ${number(status.updated_hit_count)}`
  if (evidence) evidence.textContent = `敏感 ${number(status.new_sensitive_hit_count)} / 线索 ${number(status.new_clue_hit_count)}`
  if (toggle) {
    toggle.dataset.enabled = enabled ? '1' : '0'
    toggle.textContent = configurationMissing ? '请先配置' : enabled ? '停止扫描' : '开始扫描'
    toggle.classList.toggle('btn-primary', !enabled)
    toggle.classList.toggle('btn-danger', enabled)
  }
  if (error) {
    const message = errorMessage || status.last_error || ''
    error.textContent = message
    error.hidden = !message
  }
}

async function setupCodeContinuousScan(root, watchlists = [], onScanCompleted = null) {
  const panel = query(root, '[data-code-scan-panel]')
  const select = query(root, '[data-code-scan-watchlist]')
  const toggle = query(root, '[data-code-scan-toggle]')
  if (!panel || !select || !toggle) return
  window.clearInterval(root.__codeContinuousStatusTimer)
  root.__codeContinuousStatusTimer = null

  const enabledWatchlists = watchlists.filter((item) => item.enabled !== false)
  select.replaceChildren(...enabledWatchlists.map((item) => new Option(item.name || `监测对象 ${item.id}`, String(item.id))))
  if (!enabledWatchlists.length) {
    select.replaceChildren(new Option('请先配置监测对象', ''))
    toggle.disabled = true
    renderCodeContinuousStatus(root, { configuration_missing: true }, '请先在设置中心创建并启用代码监测对象。')
    return
  }

  let loading = false
  const lastSuccessByWatchlist = new Map()
  const refreshStatus = async (preferredStatus = null) => {
    const watchlistId = Number(select.value || 0)
    if (!watchlistId || loading) return
    try {
      const status = preferredStatus || await requestJson(`/api/code-monitoring/continuous-status?watchlist_id=${encodeURIComponent(watchlistId)}`)
      renderCodeContinuousStatus(root, status)
      const currentSuccess = String(status.last_success_at || '')
      const hadBaseline = lastSuccessByWatchlist.has(watchlistId)
      const previousSuccess = lastSuccessByWatchlist.get(watchlistId) || ''
      lastSuccessByWatchlist.set(watchlistId, currentSuccess)
      if (hadBaseline && currentSuccess && previousSuccess !== currentSuccess && onScanCompleted) {
        await onScanCompleted()
      }
    } catch (error) {
      renderCodeContinuousStatus(root, {}, error.message || '长期扫描状态加载失败')
    } finally {
      toggle.disabled = false
    }
  }

  try {
    const activeStatus = await requestJson('/api/code-monitoring/continuous-status')
    const activeId = Number(activeStatus.target_watchlist_id || 0)
    if (activeId && enabledWatchlists.some((item) => Number(item.id) === activeId)) select.value = String(activeId)
    await refreshStatus(activeId === Number(select.value) ? activeStatus : null)
  } catch (error) {
    renderCodeContinuousStatus(root, {}, error.message || '长期扫描状态加载失败')
    toggle.disabled = false
  }

  if (!root.isConnected) return
  select.addEventListener('change', () => { refreshStatus() })
  toggle.addEventListener('click', async () => {
    const watchlistId = Number(select.value || 0)
    if (!watchlistId || loading) return
    loading = true
    toggle.disabled = true
    toggle.textContent = toggle.dataset.enabled === '1' ? '正在停止…' : '正在启动…'
    try {
      const enabled = toggle.dataset.enabled === '1'
      const endpoint = enabled ? '/api/code-monitoring/continuous/stop' : '/api/code-monitoring/continuous/start'
      const status = await requestJson(endpoint, {
        method: 'POST',
        body: JSON.stringify(enabled
          ? { watchlist_id: watchlistId }
          : { watchlist_id: watchlistId, interval_seconds: CODE_CONTINUOUS_INTERVAL_SECONDS }),
      })
      renderCodeContinuousStatus(root, status)
      showToast(status.message || (enabled ? '长期扫描已停止' : '长期扫描已启动'))
    } catch (error) {
      renderCodeContinuousStatus(root, { enabled: toggle.dataset.enabled === '1' }, error.message || '长期扫描操作失败')
    } finally {
      loading = false
      toggle.disabled = false
    }
  })

  root.__codeContinuousStatusTimer = window.setInterval(() => {
    if (!root.isConnected || !query(root, '[data-code-scan-panel]')) {
      window.clearInterval(root.__codeContinuousStatusTimer)
      root.__codeContinuousStatusTimer = null
      return
    }
    refreshStatus()
  }, 15_000)
}

function codeHitPageUrl(root, codeState, bucket) {
  const params = new URLSearchParams({
    bucket,
    offset: String((codeState.pages[bucket] - 1) * CODE_HIT_PAGE_SIZE),
    limit: String(CODE_HIT_PAGE_SIZE),
  })
  queryAll(root, '[data-code-hit-filter]').forEach((control) => {
    const value = String(control.value || '').trim()
    if (value) params.set(control.dataset.codeHitFilter, value)
  })
  return `/api/code-monitoring/hits/page?${params.toString()}`
}

function setCodeServerPage(table, payload) {
  if (!table) return
  const total = Math.max(0, Number(payload.total || 0))
  const limit = Math.max(1, Number(payload.limit || CODE_HIT_PAGE_SIZE))
  const offset = Math.max(0, Number(payload.offset || 0))
  table.dataset.serverPagination = 'true'
  table.dataset.serverTotal = String(total)
  table.dataset.serverPageSize = String(limit)
  table.dataset.serverPage = String(Math.floor(offset / limit) + 1)
  table.dataset.serverPageCount = String(Math.max(1, Math.ceil(total / limit)))
}

function fillPrimaryCodeRows(table, items) {
  replaceRows(table, items, (row, item) => {
    const cells = queryAll(row, 'td')
    const severity = severityOf(item)
    row.dataset.target = item.watchlistName || item.organizationName || ''
    row.dataset.platform = item.platform
    row.dataset.severity = severity === 'critical' ? 'high' : severity
    row.dataset.hit = item.resultLayer
    row.dataset.type = item.sensitiveType
    row.dataset.discoveredAt = item.firstSeenAt || ''
    setCell(cells[0], item.repositoryFullName || item.repositoryName)
    setDocumentSourceCell(cells[1], item.platform, item.platformLabel)
    setCell(cells[2], item.filePath)
    if (cells[2]) cells[2].title = item.filePath || ''
    setCell(cells[3], item.sensitiveLabel)
    setCell(cells[4], item.matchedTerm)
    setClassTextCell(cells[5], item.resultLayerLabel, `hit-level ${item.resultLayer || ''}`)
    setBadgeCell(cells[6], severityLabel(severity), severity)
    setCell(cells[7], formatDate(item.firstSeenAt))
    setCell(cells[8], reviewStatusLabel(item.reviewStatus))
    setActionCell(cells[9], '详情', `/document-exposure/code-monitoring/detail/${encodeURIComponent(item.id)}`)
  })
}

function fillSuppressedCodeRows(table, items) {
  if (!table) return
  replaceRows(table, items, (row, item) => {
    const cells = queryAll(row, 'td')
    row.dataset.target = item.watchlistName || item.organizationName || ''
    setCell(cells[0], item.repositoryFullName || item.repositoryName)
    row.dataset.discoveredAt = item.firstSeenAt || ''
    setDocumentSourceCell(cells[1], item.platform, item.platformLabel)
    setCell(cells[2], item.filePath)
    if (cells[2]) cells[2].title = item.filePath || ''
    setCell(cells[3], item.matchedTerm)
    setCell(cells[4], item.resultLayerLabel)
    const suppressionReason = (item.suppressionReasons || []).join('；') || '规则压制'
    setCell(cells[5], suppressionReason)
    if (cells[5]) cells[5].title = suppressionReason
    setBadgeCell(cells[6], severityLabel(severityOf(item)), severityOf(item))
    setCell(cells[7], formatDate(item.firstSeenAt))
    setCell(cells[8], reviewStatusLabel(item.reviewStatus))
    setActionCell(cells[9], '详情', `/document-exposure/code-monitoring/detail/${encodeURIComponent(item.id)}`)
  })
}

async function reloadCodeMonitoringData(root, state, codeState, resetPages = false) {
  if (codeState.loading) return
  if (resetPages) codeState.pages = { primary: 1, suppressed: 1 }
  codeState.loading = true
  try {
    const [summary, primaryPage, suppressedPage] = await Promise.all([
      requestJson('/api/code-monitoring/summary'),
      requestJson(codeHitPageUrl(root, codeState, 'primary')),
      requestJson(codeHitPageUrl(root, codeState, 'suppressed')),
    ])
    const table = clearTable(root, '#code-table')
    const suppressedTable = clearTable(root, '#suppressed-code-table')
    setCodeServerPage(table, primaryPage)
    setCodeServerPage(suppressedTable, suppressedPage)
    fillPrimaryCodeRows(table, primaryPage.items || [])
    fillSuppressedCodeRows(suppressedTable, suppressedPage.items || [])
    const primaryCount = query(root, '[data-table-count="code-table"]')
    const suppressedCount = query(root, '[data-table-count="suppressed-code-table"]')
    if (primaryCount) primaryCount.textContent = number(primaryPage.total)
    if (suppressedCount) suppressedCount.textContent = number(suppressedPage.total)
    setCounts(query(root, '.code-kpi-layout'), [summary.publicRepositoryCount, summary.sensitiveSnippetCount, summary.clueHitCount, summary.highRiskRepositoryCount])
    fillSourceDistribution(query(root, '.code-source-grid'), summary.platformDistribution || [], summary.totalHits)
    const repositoryRisk = summary.repositoryRiskDistribution || []
    const repositoryCount = Number(summary.repositoryCount || 0)
    setText(root, '.code-risk-donut strong', number(repositoryCount))
    setText(root, '.code-risk-card .meta', `总仓库 ${number(repositoryCount)}`)
    fillDistribution(query(root, '.code-risk-legend'), repositoryRisk, repositoryCount, true)
    setConicChart(query(root, '.code-risk-donut'), repositoryRisk.map((item) => item.value), ['var(--danger)', 'var(--warning)', 'var(--secondary)'])
    fillNamedRows(query(root, '.code-secret-rank'), summary.sensitiveTypeTop || [])
    renderCodeTrend(root, summary.trend || [])
    markExports(root, state, ['#code-table'])
  } finally {
    codeState.loading = false
  }
}

function setupCodeHitFilters(root, codeState, reload) {
  let searchTimer = null
  queryAll(root, '[data-code-hit-filter]').forEach((control) => {
    const eventName = control.dataset.codeHitFilter === 'query' ? 'input' : 'change'
    control.addEventListener(eventName, () => {
      window.clearTimeout(searchTimer)
      searchTimer = window.setTimeout(() => { reload(true) }, eventName === 'input' ? 300 : 0)
    })
  })
  for (const [bucket, selector] of [['primary', '#code-table'], ['suppressed', '#suppressed-code-table']]) {
    query(root, selector)?.addEventListener('prototype:server-page', (event) => {
      codeState.pages[bucket] = Math.max(1, Number(event.detail?.page || 1))
      reload(false)
    })
  }
}

async function hydrateCodeMonitoring(root, state) {
  const codeState = { pages: { primary: 1, suppressed: 1 }, loading: false }
  const reload = (resetPages = false) => reloadCodeMonitoringData(root, state, codeState, resetPages)
  setupCodeHitFilters(root, codeState, reload)
  const [watchlistsPayload] = await Promise.all([
    requestJson('/api/code-monitoring/watchlists'),
    reload(false),
  ])
  const watchlists = Array.isArray(watchlistsPayload) ? watchlistsPayload : (watchlistsPayload.items || watchlistsPayload.watchlists || [])
  const watchlistFilter = query(root, '[data-code-hit-filter="watchlist_id"]')
  if (watchlistFilter) {
    watchlistFilter.replaceChildren(new Option('全部监测对象', ''), ...watchlists.map((item) => new Option(item.name || `监测对象 ${item.id}`, String(item.id))))
  }
  setupCodeContinuousScan(root, watchlists, () => reload(true)).catch((error) => {
    renderCodeContinuousStatus(root, {}, error.message || '长期扫描状态加载失败')
  })
}

function replaceRecordContainer(container, lines) {
  if (!container) return
  const values = lines.length ? lines : ['当前记录未提供结构化数据']
  const template = container.firstElementChild?.cloneNode(true)
  if (!template) {
    container.textContent = values.join('；')
    return
  }
  const rows = values.map((line, index) => {
    const row = template.cloneNode(true)
    const children = [...row.children]
    if (children[0]) children[0].textContent = index === 0 ? '实时证据' : `证据 ${index + 1}`
    if (children[1]) children[1].textContent = String(line)
    if (children[2]) children[2].textContent = ''
    if (!children.length) row.textContent = String(line)
    return row
  })
  container.replaceChildren(...rows)
}

function replaceStructuredRows(container, rows) {
  if (!container) return
  const values = (rows || []).filter((item) => item && item.value != null && item.value !== '')
  if (!values.length) {
    container.replaceChildren()
    return
  }
  const template = container.firstElementChild?.cloneNode(true) || document.createElement('div')
  container.replaceChildren(...values.map((item) => {
    const row = template.cloneNode(true)
    row.hidden = false
    const children = [...row.children]
    if (children[0]) children[0].textContent = item.label || '实时数据'
    if (children[1]) children[1].textContent = String(item.value)
    if (children[2]) children[2].textContent = item.note || ''
    if (!children.length) row.textContent = `${item.label ? `${item.label}：` : ''}${item.value}`
    return row
  }))
}

function setDefinitionPairs(container, pairs) {
  if (!container) return
  const rows = queryAll(container, ':scope > div')
  rows.forEach((row, index) => {
    const pair = pairs[index]
    const value = pair?.value
    const available = value != null && value !== '' && (!Array.isArray(value) || value.length > 0)
    row.hidden = !pair || !available
    if (!pair || !available) return
    const labelNode = query(row, ':scope > span, :scope > dt')
    const valueNode = query(row, ':scope > strong, :scope > a, :scope > dd')
    if (labelNode) labelNode.textContent = pair.label
    if (!valueNode) return
    if (pair.url) {
      const link = document.createElement('a')
      link.className = valueNode.className
      link.href = pair.url
      link.target = '_blank'
      link.rel = 'noopener noreferrer'
      link.textContent = String(value)
      valueNode.replaceWith(link)
    } else {
      valueNode.textContent = Array.isArray(value) ? value.join(' / ') : String(value)
    }
  })
}

function setDetailSection(root, id, visible) {
  const section = query(root, `[data-od-id="${id}"]`)
  if (section) section.hidden = !visible
  return section
}

function hideDetailRail(root, id) {
  const rail = setDetailSection(root, id, false)
  rail?.parentElement?.classList.add('runtime-single-column')
}

function normalizedResourceList(...groups) {
  const resources = []
  const seen = new Set()
  groups.flat(Infinity).forEach((item) => {
    const url = typeof item === 'string' ? item : item?.url || item?.href || ''
    if (!url || (!/^https?:\/\//i.test(url) && !String(url).startsWith('/')) || seen.has(url)) return
    seen.add(url)
    resources.push({
      url: String(url),
      label: typeof item === 'object' ? (item.label || item.kind || item.name || '证据资源') : '证据资源',
      kind: typeof item === 'object' ? (item.kind || '') : '',
    })
  })
  return resources
}

function detailRiskLines(detail) {
  const monitoring = (detail.monitoring_matches || detail.monitoringMatches || []).map((item) =>
    typeof item === 'string' ? item : item?.reason || item?.label || item?.name,
  )
  return [
    ...(detail.risk_reasons || detail.riskReasons || []),
    ...(detail.riskAnalysis?.reasons || []),
    ...monitoring,
  ].filter(Boolean)
}

function setHeroSourceLogo(root, platform) {
  const image = query(root, '.detail-source-logo img')
  if (!image) return
  const key = sourceLogoKey(platform)
  const assets = {
    github: '/assets/logos/github.png',
    gitlab: '/assets/logos/gitlab.png',
    gitee: '/assets/logos/gitee.png',
    'baidu-doc': '/assets/logos/baidu-wenku.svg',
    'baidu-disk': '/assets/logos/baidu-netdisk.png',
    aliyun: '/assets/logos/alipan.png',
    quark: '/assets/logos/quark.png',
    onedrive: '/assets/logos/onedrive.png',
    doc88: '/assets/logos/doc88.png',
    docin: '/assets/logos/docin.png',
    csdn: '/assets/logos/csdn.png',
  }
  const asset = assets[key]
  image.hidden = !asset
  if (asset) {
    image.src = asset
    image.alt = `${platform || '来源平台'}标志`
  }
}

function configureSourceAccess(root, config) {
  const {
    sectionId,
    openId,
    viewId,
    downloadId,
    sourceUrl = '',
    resources = [],
    fetchedAt = '',
  } = config
  const section = query(root, `[data-od-id="${sectionId}"]`)
  if (!section) return
  const normalized = normalizedResourceList(resources)
  const directSource = /^https?:\/\//i.test(sourceUrl) || String(sourceUrl).startsWith('/') ? sourceUrl : ''
  const source = directSource || normalized.find((item) => /原始|通告|仓库|文件/.test(item.label))?.url || ''
  const mirror = normalized.find((item) => /screenshot|image/i.test(item.kind))
    || normalized.find((item) => /截图|image/i.test(item.label))
    || normalized.find((item) => /mirror/i.test(item.kind))
    || normalized.find((item) => /镜像/.test(item.label))
  const downloadable = normalized.find((item) => /artifact|html|json/i.test(item.kind))
    || normalized.find((item) => /镜像|原始抓取|JSON/i.test(item.label))

  const open = query(root, `[data-od-id="${openId}"]`)
  if (open) {
    open.hidden = !source
    if (source) open.href = source
    else open.removeAttribute('href')
  }
  const sourceLine = query(section, '.source-link-line')
  const sourceLink = query(sourceLine, 'a')
  const copy = query(sourceLine, 'button')
  if (sourceLine) sourceLine.hidden = !source
  if (sourceLink) {
    sourceLink.hidden = !source
    if (source) {
      sourceLink.href = source
      sourceLink.textContent = source
    }
  }
  if (copy) {
    copy.dataset.runtimeCopy = source
    setActionAvailable(copy, Boolean(source), source ? '' : '接口未提供原始链接')
  }

  const view = query(root, `[data-od-id="${viewId}"]`)
  if (view) {
    delete view.dataset.toast
    view.dataset.runtimeOpen = mirror?.url || ''
    setActionAvailable(view, Boolean(mirror), mirror ? '' : '接口未提供镜像资源')
  }
  const download = query(root, `[data-od-id="${downloadId}"]`)
  if (download) {
    delete download.dataset.toast
    download.dataset.runtimeDownload = downloadable?.url || ''
    setActionAvailable(download, Boolean(downloadable), downloadable ? '' : '接口未提供可下载镜像')
  }

  const figure = query(section, '.mirror-frame')
  if (figure) {
    figure.hidden = !mirror
    const slot = query(figure, '.mirror-image-slot')
    if (slot && mirror) {
      slot.replaceChildren()
      if (shouldRenderResourceAsImage(mirror)) {
        const image = document.createElement('img')
        image.className = 'runtime-mirror-image'
        image.src = mirror.url
        image.alt = mirror.label
        slot.appendChild(image)
      } else {
        const label = document.createElement('strong')
        label.textContent = mirror.label
        slot.appendChild(label)
      }
    }
    setText(figure, 'figcaption strong', mirror?.label || '—')
    setText(figure, 'figcaption span', normalized.length ? `${normalized.length} 个真实资源` : '—')
    setText(figure, 'figcaption code', '')
    setText(figure, '.mirror-frame-bar time', formatDate(fetchedAt))
  }
  section.hidden = !source && !normalized.length
}

function bindDetailBase(root, detail, summaryPairs, kpiPairs) {
  setText(root, 'main h1', detail.title || detail.repositoryFullName || detail.repositoryName || '未命名记录')
  setText(root, '[data-detail-record-id]', detail.identifier || detail.id)
  setText(root, '.lead', usableText(detail.summary) || usableText(detail.detail_text) || usableText(detail.codePreview) || '暂无摘要')
  setSummary(query(root, '.detail-summary'), summaryPairs)
  const kpis = queryAll(root, '.detail-kpi')
  kpis.forEach((card, index) => {
    if (!kpiPairs[index]) return
    const [label, value, note] = kpiPairs[index]
    setText(card, 'span', label)
    setText(card, 'strong', value)
    setText(card, 'small', note || '实时数据')
  })
  const badge = query(root, '.detail-hero .badge')
  if (badge) badge.textContent = severityLabel(severityOf(detail))
}

function reviewerName() {
  try {
    const user = JSON.parse(localStorage.getItem('dwti-current-user') || 'null')
    return user?.display_name || user?.username || ''
  } catch {
    return ''
  }
}

function hydrateAccount(root) {
  try {
    const user = JSON.parse(localStorage.getItem('dwti-current-user') || 'null')
    const label = user?.display_name || user?.username || '个人'
    queryAll(root, '.avatar').forEach((node) => { node.textContent = label })
  } catch {
    queryAll(root, '.avatar').forEach((node) => { node.textContent = '个人' })
  }
}

function openCollectorRemoteLogin(site, options = {}) {
  const platform = String(options.platform || site?.auth_platform || '').trim()
  if (!platform || document.querySelector('.collector-browser-overlay')) return
  const displayLabel = String(options.label || site?.display_name || site?.site_name || platform).trim()

  const overlay = document.createElement('div')
  overlay.className = 'collector-browser-overlay'
  overlay.innerHTML = `
    <section class="collector-browser-dialog" role="dialog" aria-modal="true" aria-labelledby="collector-browser-title">
      <header class="collector-browser-head">
        <div>
          <h2 id="collector-browser-title" data-browser-dialog-title>登录</h2>
        </div>
        <div class="collector-browser-head-actions">
          <span class="badge" data-browser-status hidden>启动中</span>
          <button class="btn btn-secondary" type="button" data-browser-captcha hidden>识别验证码</button>
          <button class="btn btn-secondary" type="button" data-browser-captcha-report hidden>报错返分</button>
          <button class="btn btn-primary" type="button" data-browser-save>保存会话</button>
          <button class="btn btn-secondary" type="button" data-browser-close>关闭</button>
        </div>
      </header>
      <div class="collector-browser-layout">
        <div class="collector-browser-workspace">
          <div class="collector-browser-canvas" data-browser-canvas tabindex="0" aria-label="内部浏览器画面，点击可操作页面">
            <img data-browser-screenshot alt="内部浏览器登录页面" hidden>
            <div class="collector-browser-empty" data-browser-empty>正在通过 Tor 启动内部浏览器…</div>
          </div>
          <p class="collector-browser-error" data-browser-error hidden></p>
        </div>
      </div>
    </section>`
  document.body.appendChild(overlay)

  let sessionId = ''
  let browserState = null
  let closed = false
  let busy = false
  let refreshTimer = null
  let browserStream = null
  let streamPath = ''
  const statusNode = query(overlay, '[data-browser-status]')
  const screenshot = query(overlay, '[data-browser-screenshot]')
  const empty = query(overlay, '[data-browser-empty]')
  const errorNode = query(overlay, '[data-browser-error]')
  const canvas = query(overlay, '[data-browser-canvas]')
  const captchaButton = query(overlay, '[data-browser-captcha]')
  const captchaReportButton = query(overlay, '[data-browser-captcha-report]')

  const setStatus = (label, tone = '') => {
    statusNode.textContent = label
    statusNode.className = `badge ${tone}`.trim()
  }

  const connectStream = (path) => {
    if (!path || path === streamPath) return
    browserStream?.close()
    streamPath = path
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
    browserStream = createRemoteBrowserStream({
      image: screenshot,
      focusTarget: canvas,
      websocketUrl: `${scheme}://${window.location.host}${path}`,
      onStatus: (status) => {
        if (status === 'connected') {
          empty.hidden = true
          setStatus('实时浏览器已连接', 'badge-success')
        } else if (status === 'connecting') {
          setStatus('正在连接实时浏览器')
        } else if (!closed) {
          setStatus('实时浏览器已断开', 'badge-high')
        }
      },
      onError: (message) => {
        errorNode.hidden = false
        errorNode.textContent = message
      },
    })
  }

  const renderState = (payload) => {
    browserState = payload || browserState
    if (!browserState) return
    captchaButton.hidden = !browserState.captcha_recognition_available
    captchaReportButton.hidden = !browserState.captcha_error_report_available
    setText(overlay, '[data-browser-dialog-title]', `${displayLabel}登录`)
    if (browserState.stream_ws_path) connectStream(browserState.stream_ws_path)
    if (browserState.screenshot) {
      screenshot.src = browserState.screenshot
      screenshot.hidden = false
      empty.hidden = true
    } else if (!browserState.stream_ws_path) {
      screenshot.hidden = true
      empty.hidden = false
      empty.textContent = browserState.last_error ? '目标页面暂时无法加载，可点击重新加载页面' : '等待内部浏览器画面'
    }
    const lastError = String(browserState.last_error || '').trim()
    errorNode.hidden = !lastError
    errorNode.textContent = lastError ? `页面加载提示：${lastError}` : ''
    setStatus(lastError ? '页面待重试' : '浏览器已连接', lastError ? 'badge-high' : 'badge-success')
  }

  const control = async (action, payload = {}) => {
    if (!sessionId || busy) return null
    busy = true
    try {
      const state = await requestJson(`/api/platform-sessions/remote-login/${encodeURIComponent(sessionId)}/control`, {
        method: 'POST',
        body: JSON.stringify({ action, ...payload }),
      })
      renderState(state)
      return state
    } catch (error) {
      setStatus('操作失败', 'badge-high')
      errorNode.hidden = false
      errorNode.textContent = error.message || '内部浏览器操作失败'
      return null
    } finally {
      busy = false
    }
  }

  const refreshState = async () => {
    if (!sessionId || busy || closed) return
    busy = true
    try {
      renderState(await requestJson(`/api/platform-sessions/remote-login/${encodeURIComponent(sessionId)}`))
    } catch (error) {
      setStatus('连接中断', 'badge-high')
      errorNode.hidden = false
      errorNode.textContent = error.message || '无法刷新内部浏览器画面'
    } finally {
      busy = false
    }
  }

  const stopPolling = () => {
    if (refreshTimer) window.clearInterval(refreshTimer)
    refreshTimer = null
  }

  const closeDialog = async (closeSession = true) => {
    if (closed) return
    closed = true
    stopPolling()
    browserStream?.close()
    browserStream = null
    streamPath = ''
    if (closeSession && sessionId) {
      await requestJson(`/api/platform-sessions/remote-login/${encodeURIComponent(sessionId)}`, { method: 'DELETE' }).catch(() => null)
    }
    overlay.remove()
  }

  query(overlay, '[data-browser-close]').addEventListener('click', () => closeDialog())
  query(overlay, '[data-browser-captcha]').addEventListener('click', async () => {
    setStatus('正在识别验证码')
    const state = await control('solve_captcha')
    if (state?.action_result?.captcha_filled) {
      setStatus('验证码已填入', 'badge-success')
      showToast('验证码识别结果已填入登录页面')
    }
  })
  query(overlay, '[data-browser-captcha-report]').addEventListener('click', async () => {
    setStatus('正在报错返分')
    const state = await control('report_captcha_error')
    if (state?.action_result?.reported) {
      setStatus('已报错返分', 'badge-success')
      showToast('该次验证码识别已向超级鹰报错')
    }
  })
  overlay.addEventListener('click', (event) => {
    if (event.target === overlay) closeDialog()
  })
  screenshot.addEventListener('click', (event) => {
    if (streamPath) return
    const viewport = browserState?.viewport || {}
    const bounds = screenshot.getBoundingClientRect()
    if (!bounds.width || !bounds.height || !viewport.width || !viewport.height) return
    control('click', {
      x: Math.round((event.clientX - bounds.left) * Number(viewport.width) / bounds.width),
      y: Math.round((event.clientY - bounds.top) * Number(viewport.height) / bounds.height),
    })
  })
  query(overlay, '[data-browser-save]').addEventListener('click', async () => {
    if (!sessionId || busy) return
    busy = true
    setStatus('正在校验会话')
    try {
      await requestJson(`/api/platform-sessions/remote-login/${encodeURIComponent(sessionId)}/finish`, {
        method: 'POST',
        body: JSON.stringify({ account_label: displayLabel }),
      })
      sessionId = ''
      if (options.runSiteOnSave !== false && site?.site_name) {
        const runResult = await requestJson('/api/jobs/run-site', {
          method: 'POST',
          body: JSON.stringify({ site_name: site.site_name, force: true }),
        })
        if (runResult?.reason === 'auth_required') throw new Error(runResult.message || '登录会话尚未生效')
        setStatus('已保存并重新运行', 'badge-success')
        showToast('登录会话已保存，站点任务已重新运行')
        const url = new URL(window.location.href)
        url.searchParams.delete('login')
        window.history.replaceState({}, '', url)
      } else {
        setStatus('会话已保存', 'badge-success')
        showToast('平台登录会话已保存')
      }
      window.setTimeout(() => window.location.reload(), 900)
    } catch (error) {
      setStatus('保存失败', 'badge-high')
      errorNode.hidden = false
      errorNode.textContent = error.message || '登录会话保存失败'
    } finally {
      busy = false
    }
  })

  ;(async () => {
    try {
      if (options.initialState?.session_id) {
        sessionId = String(options.initialState.session_id)
        renderState(options.initialState)
        refreshTimer = window.setInterval(refreshState, 3000)
        return
      }
      if (platform === 'changan') {
        let tor = await requestJson('/api/tor-bridge/status')
        if (!tor.connected) {
          setStatus('正在连接 Tor')
          tor = await requestJson('/api/tor-bridge/start', { method: 'POST' })
          const deadline = Date.now() + 45_000
          while (!tor.connected && Date.now() < deadline) {
            if (tor.connection_state === 'error') throw new Error(tor.last_error || 'Tor 连接失败')
            await new Promise((resolve) => window.setTimeout(resolve, 1200))
            tor = await requestJson('/api/tor-bridge/status')
          }
          if (!tor.connected) throw new Error('Tor 尚未完成连接，请检查网桥状态后重试')
        }
      }
      const state = await requestJson(`/api/platform-sessions/${encodeURIComponent(platform)}/remote-login/start`, { method: 'POST' })
      sessionId = String(state.session_id || '')
      renderState(state)
      refreshTimer = window.setInterval(refreshState, 3000)
    } catch (error) {
      setStatus('启动失败', 'badge-high')
      empty.textContent = '内部浏览器启动失败'
      errorNode.hidden = false
      errorNode.textContent = error.message || '无法创建内部浏览器会话'
    }
  })()
}

export function openPlatformRemoteLogin(platform, initialState, options = {}) {
  const normalizedPlatform = String(platform || '').trim()
  if (!normalizedPlatform) return
  openCollectorRemoteLogin(
    {
      auth_platform: normalizedPlatform,
      display_name: options.label || initialState?.label || normalizedPlatform,
    },
    {
      ...options,
      platform: normalizedPlatform,
      initialState,
      runSiteOnSave: false,
    },
  )
}

async function hydrateCollectorRunDetail(root, route) {
  const payload = await requestJson('/api/jobs')
  const siteName = String(route?.query?.site || '')
  const jobType = String(route?.query?.job || '采集任务')
  const site = (payload.site_health || []).find((item) =>
    [item.site_name, item.display_name].map(String).includes(siteName),
  ) || null
  if (!site) throw new Error(siteName ? `未找到站点运行摘要：${siteName}` : '当前链接未指定可核验的站点')
  const failure = (payload.recent_failures || []).find((item) =>
    String(item.site_name || '') === String(site?.site_name || siteName),
  ) || null
  const status = site?.overall_status || (failure ? '异常' : '未运行')
  setText(root, '[data-detail-record-id]', site?.site_name || String(route?.params?.runId || 'latest'))
  setText(root, 'main h1', `${site?.display_name || siteName || '采集任务'} · ${jobType}`)
  setText(root, '.lead', failure?.error_message || site?.last_error || '后端当前仅提供站点级运行摘要，未提供单任务进度、日志和控制接口。')
  setText(root, '.detail-hero .badge', status)
  setSummary(query(root, '.detail-summary'), [
    ['运行状态', status],
    ['种子任务', site?.seed_status || '未运行'],
    ['已处理', number((site?.forum_details_count || 0) + (site?.victims_count || 0))],
    ['详情任务', site?.detail_status || '未运行'],
  ])
  const kpiValues = [
    ['最近成功', site?.last_success_at || '—', '站点级状态'],
    ['运行任务', number(site?.running_jobs || 0), '站点级状态'],
    ['连续失败', number(site?.consecutive_failures || 0), `阈值 ${number(site?.failure_threshold || 0)}`],
    ['授权状态', site?.auth_required ? (site?.auth_message || site?.auth_status || '需登录') : '无需登录', '站点级状态'],
  ]
  queryAll(root, '.detail-kpi').forEach((card, index) => {
    const item = kpiValues[index]
    if (!item) return
    setText(card, 'span', item[0])
    setText(card, 'strong', item[1])
    setText(card, 'small', item[2])
  })
  const frontier = site?.frontier
  const progress = setDetailSection(root, 'collector-run-progress', Boolean(frontier?.enabled))
  if (frontier?.enabled) {
    setText(progress, '.panel-header h2', '详情队列与历史回补')
    setText(progress, '.panel-header p', '统计已发现任务；队列已完成不代表站点全部历史数据已抓取。')
    const progressBar = query(progress, '.detail-progress')
    if (progressBar) progressBar.hidden = true
    const progressBadge = query(progress, '.panel-header .badge')
    if (progressBadge) {
      progressBadge.textContent = site.enabled === false ? '站点已停用' : frontier.backfill_paused ? '积压暂停回补' : '最新页优先'
      progressBadge.className = `badge ${frontier.backfill_paused ? 'badge-high' : 'badge-success'}`
    }
    const pageCursors = Array.isArray(frontier.page_cursors) ? frontier.page_cursors : []
    replaceStructuredRows(query(progress, '.detail-list'), [
      { label: '待抓', value: number(frontier.pending || 0), note: '包括等待自动重试的任务' },
      { label: '执行中', value: number(frontier.inflight || 0), note: '已领取或排队等待执行' },
      { label: '队列已完成', value: number(frontier.completed || 0), note: '已发现任务的当前版本已补齐' },
      { label: '历史回补', value: site.enabled === false ? '站点已停用，保留进度' : frontier.backfill_paused ? '积压达到上限，暂停回补' : `每轮最多 ${number(frontier.backfill_pages_per_run || 0)} 页`, note: site.enabled === false ? '' : '继续检查最新页' },
      ...pageCursors.map((cursor, index) => ({
        label: `分区 ${index + 1}`,
        value: cursor.completed_at ? '本轮列表已扫描至末页' : `下次回补第 ${number(cursor.next_page || 2)} 页`,
        note: cursor.source_url || '',
      })),
      ...(!pageCursors.length ? [{ label: '分页游标', value: '尚无历史回补记录', note: '' }] : []),
    ])
  }
  setDetailSection(root, 'collector-run-configuration', false)
  setDetailSection(root, 'collector-run-log', false)
  hideDetailRail(root, 'collector-action-rail')
  const health = setDetailSection(root, 'collector-run-health', Boolean(site))
  const healthBadge = query(health, '.panel-header .badge')
  if (healthBadge) {
    healthBadge.textContent = status
    healthBadge.classList.remove('badge-success', 'badge-high', 'badge-critical')
    healthBadge.classList.add(failure || Number(site?.consecutive_failures || 0) > 0 ? 'badge-high' : 'badge-success')
  }
  replaceStructuredRows(query(health, '.detail-list'), [
    { label: '站点状态', value: status, note: payload.updated_at || '' },
    { label: '授权状态', value: site?.auth_required ? (site?.auth_status || '需登录') : '无需登录', note: site?.auth_platform || '' },
    { label: '熔断器', value: site?.circuit_breaker_open ? '已开启' : '未开启', note: site?.failure_cooldown_until || '' },
    { label: '阻塞原因', value: site?.blockingReason || '无', note: site?.error_category || '' },
  ])
  if (site?.auth_required && site?.auth_platform) {
    const header = query(health, '.panel-header')
    const actions = document.createElement('div')
    actions.className = 'collector-auth-actions'
    if (healthBadge) actions.appendChild(healthBadge)
    const loginButton = document.createElement('button')
    loginButton.type = 'button'
    loginButton.className = 'btn btn-primary'
    loginButton.textContent = '打开内部浏览器登录'
    loginButton.addEventListener('click', () => openCollectorRemoteLogin(site))
    actions.appendChild(loginButton)
    header?.appendChild(actions)
    if (String(route?.query?.login || '') === '1') openCollectorRemoteLogin(site)
  }
  const failures = (payload.recent_failures || []).filter((item) =>
    String(item.site_name || '') === String(site?.site_name || siteName),
  )
  const retrySection = setDetailSection(root, 'collector-run-retries', failures.length > 0)
  const retryBadge = query(retrySection, '.panel-header .badge')
  if (retryBadge) {
    retryBadge.textContent = failures.length ? `${number(failures.length)} 条失败记录` : '无失败记录'
    retryBadge.classList.remove('badge-success', 'badge-high', 'badge-critical')
    retryBadge.classList.add(failures.length ? 'badge-high' : 'badge-success')
  }
  replaceStructuredRows(query(retrySection, '.detail-list'), failures.map((item) => ({
    label: item.finished_at || '最近失败',
    value: item.error_message || item.status || '采集失败',
    note: item.error_category || item.job_type || '',
  })))
}

async function hydrateIncidentDetail(root, state, file, id) {
  const vulnerability = file === 'vulnerability-detail.html'
  const endpoint = vulnerability ? `/api/vulnerabilities/${encodeURIComponent(id)}` : `/api/events/${encodeURIComponent(id)}`
  const detail = await requestJson(endpoint)
  state.incidentDetail = detail
  const riskLines = [...new Set(detailRiskLines(detail))]
  const referenceResources = normalizedResourceList(
    detail.reference_urls,
    detail.mirror_resources,
    detail.screenshot_resources,
    detail.sample_links,
    detail.json_preview_url ? [{ label: 'JSON 记录', url: detail.json_preview_url, kind: 'artifact' }] : [],
  )
  const sourceUrl = detail.disclosure_url || detail.source_url || detail.advisory_url || referenceResources[0]?.url || ''
  const affectedVersions = (detail.affected_version_items || detail.affected_versions || [])
    .map((item) => typeof item === 'string' ? item : item?.display || item?.raw || item?.version || item?.label || item?.value)
    .filter(Boolean)

  if (file === 'event-detail.html') {
    bindDetailBase(root, detail, [
      ['风险等级', severityLabel(severityOf(detail))],
      ['来源', detail.source || detail.raw_source_type_label || '—'],
      ['披露时间', formatDate(detail.disclosure_time)],
      ['风险评分', detail.risk_score != null ? `${number(detail.risk_score)} / 100` : '—'],
    ], [])
    setDefinitionPairs(query(root, '[data-od-id="detail-key-information"] .definition-grid'), [
      { label: '事件类型', value: eventTypeLabel(eventType(detail)) },
      { label: '来源', value: detail.source || detail.raw_source_type_label },
      { label: '披露时间', value: formatFullDate(detail.disclosure_time) },
      { label: '地区', value: detail.region || detail.country },
      { label: '所属行业', value: detail.industry },
      { label: '关联对象', value: detail.victim || detail.vendor || detail.product || detail.attacker },
    ])
    const riskSection = setDetailSection(root, 'detail-risk-reasoning', riskLines.length > 0)
    replaceStructuredRows(query(riskSection, '.queue-list'), riskLines.slice(0, 6).map((line, index) => ({
      label: `判断依据 ${index + 1}`,
      value: line,
      note: '接口返回的风险依据',
    })))
    const evidence = query(root, '[data-od-id="detail-evidence"]')
    const evidenceText = usableText(detail.detail_text) || usableText(detail.summary) || '当前接口未提供正文证据'
    setText(evidence, 'pre', evidenceText)
    setDefinitionPairs(query(evidence, '.definition-grid'), [
      { label: '来源类别', value: detail.raw_source_type_label || detail.source || '未标注' },
      { label: '参考链接', value: referenceResources[0]?.label || sourceUrl, url: referenceResources[0]?.url || sourceUrl },
      { label: '样本证据', value: detail.has_sample_evidence ? `${number(detail.sample_link_count || detail.sample_links?.length)} 个` : '未提供' },
    ])
    hideDetailRail(root, 'detail-action-rail')
    const translate = queryAll(evidence, 'button[data-toast]').find((button) => button.textContent.includes('切换原文'))
    if (translate && usableText(detail.detail_text)) {
      delete translate.dataset.toast
      translate.dataset.runtimeTranslate = '1'
      setActionAvailable(translate, true)
      const original = usableText(detail.detail_text)
      let translated = ''
      let showingTranslated = false
      state.toggleTranslation = async () => {
        if (!translated) {
          const payload = await requestJson(`/api/events/${encodeURIComponent(id)}?translate_detail=true`)
          translated = usableText(payload.detail_text) || original
          if (payload.translation_applied === false || translated === original) {
            throw new Error(payload.translation_error === 'rate_limited' ? '翻译服务请求过于频繁，请稍后重试' : '翻译服务暂时不可用，请稍后重试')
          }
        }
        showingTranslated = !showingTranslated
        setText(evidence, 'pre', showingTranslated ? translated : original)
        translate.textContent = showingTranslated ? '显示原文' : '显示译文'
      }
    } else if (translate) {
      setActionAvailable(translate, false, '当前记录没有可切换正文')
    }
    return
  }

  if (vulnerability) {
    bindDetailBase(root, detail, [
      ['行动优先级', ['critical', 'high'].includes(severityOf(detail)) ? '优先核查' : '持续跟踪'],
      ['CVSS', detail.cvss ?? '—'],
      ['补丁状态', detail.patch_available ? '已有补丁' : '未确认有补丁'],
      ['利用状态', detail.is_exploited ? '已确认在野利用' : '未确认在野利用'],
    ], [
      ['风险评分', detail.risk_score != null ? `${number(detail.risk_score)} / 100` : '—', '接口评分'],
      ['在野利用', detail.is_exploited ? '已确认' : '未确认', '公开情报记录'],
      ['受影响版本', affectedVersions.length ? `${affectedVersions.length} 项` : '未提供', ''],
      ['披露时间', formatDate(detail.disclosure_time), detail.source || '公开源'],
    ])
    setDefinitionPairs(query(root, '[data-od-id="vulnerability-affected-scope"] .definition-grid'), [
      { label: '厂商', value: detail.vendor },
      { label: '产品', value: detail.product },
      { label: '影响版本', value: affectedVersions },
      { label: '在野利用', value: detail.is_exploited ? '已确认' : '未确认' },
      { label: '补丁状态', value: detail.patch_available ? '已有补丁' : '未确认有补丁' },
      { label: 'PoC 状态', value: Object.prototype.hasOwnProperty.call(detail, 'has_poc') ? (detail.has_poc ? '已记录' : '未记录') : '' },
    ])
    const evidenceSection = setDetailSection(root, 'vulnerability-exploit-evidence', riskLines.length > 0)
    replaceStructuredRows(query(evidenceSection, '.detail-list'), riskLines.slice(0, 6).map((line, index) => ({
      label: `利用依据 ${index + 1}`,
      value: line,
      note: detail.source || '公开源',
    })))
    setDetailSection(root, 'vulnerability-asset-plan', false)
    const remediation = setDetailSection(root, 'vulnerability-remediation', Boolean(detail.patch_available))
    replaceStructuredRows(query(remediation, '.timeline'), detail.patch_available ? [{
      label: '补丁状态',
      value: '接口记录已有补丁',
      note: sourceUrl ? '具体版本与操作步骤请核对原始通告' : '接口未提供补丁链接',
    }] : [])
    const sourceSection = setDetailSection(root, 'vulnerability-sources', Boolean(sourceUrl || referenceResources.length))
    replaceStructuredRows(query(sourceSection, '.detail-list'), referenceResources.slice(0, 6).map((item) => ({
      label: item.label,
      value: item.url,
      note: '真实接口资源',
    })))
    configureSourceAccess(root, {
      sectionId: 'vulnerability-sources', openId: 'vulnerability-open-source', viewId: 'vulnerability-view-mirror', downloadId: 'vulnerability-download-mirror',
      sourceUrl, resources: referenceResources, fetchedAt: detail.updated_time || detail.disclosure_time,
    })
    hideDetailRail(root, 'vulnerability-action-rail')
    return
  }

  if (file === 'ransomware-detail.html') {
    bindDetailBase(root, detail, [
      ['行动阶段', detail.category || detail.leak_type || '已披露'],
      ['团伙', detail.attacker || '未标注'],
      ['可信度', detail.confidence_score != null ? `${number(detail.confidence_score)} / 100` : '未提供'],
      ['披露时间', formatDate(detail.disclosure_time)],
    ], [
      ['受害地区', detail.region || detail.country || '—', detail.industry || '—'],
      ['样本证据', number(detail.sample_link_count || detail.sample_links?.length || 0), detail.has_sample_evidence ? '已记录' : '未记录'],
      ['首次披露', formatDate(detail.disclosure_time), detail.source || '泄露站点'],
      ['风险评分', detail.risk_score != null ? `${number(detail.risk_score)} / 100` : '—', '接口评分'],
    ])
    setDefinitionPairs(query(root, '[data-od-id="ransomware-victim-profile"] .definition-grid'), [
      { label: '受害组织', value: detail.victim },
      { label: '所属行业', value: detail.industry },
      { label: '勒索团伙', value: detail.attacker },
      { label: '披露来源', value: detail.source || detail.raw_source_type_label },
      { label: '披露时间', value: formatFullDate(detail.disclosure_time) },
      { label: '公开状态', value: detail.category || detail.leak_type },
    ])
    setDetailSection(root, 'ransomware-attack-chain', false)
    setDetailSection(root, 'ransomware-artifacts', false)
    configureSourceAccess(root, {
      sectionId: 'ransomware-evidence', openId: 'ransomware-open-source', viewId: 'ransomware-view-mirror', downloadId: 'ransomware-download-mirror',
      sourceUrl, resources: referenceResources, fetchedAt: detail.updated_time || detail.disclosure_time,
    })
    hideDetailRail(root, 'ransomware-action-rail')
    return
  }

  bindDetailBase(root, detail, [
    ['核验评分', detail.confidence_score != null ? `${number(detail.confidence_score)} / 100` : '未提供'],
    ['样本证据', number(detail.sample_link_count || detail.sample_links?.length || 0)],
    ['泄露类型', detail.leak_type || detail.category || '未标注'],
    ['风险等级', severityLabel(severityOf(detail))],
  ], [
    ['来源可信度', detail.confidence_score != null ? `${number(detail.confidence_score)} / 100` : '—', '接口评分'],
    ['风险依据', number(riskLines.length), '结构化依据'],
    ['披露时间', formatDate(detail.disclosure_time), detail.source || '公开源'],
    ['影响实体', detail.victim || '未确认', detail.industry || '—'],
  ])
  setDefinitionPairs(query(root, '[data-od-id="data-leak-source-chain"] .definition-grid'), [
    { label: '来源通道', value: detail.source || detail.raw_source_type_label },
    { label: '发布者', value: detail.attacker },
    { label: '泄露类型', value: detail.leak_type || detail.category },
    { label: '采集时间', value: formatFullDate(detail.updated_time || detail.disclosure_time) },
    { label: '影响对象', value: detail.victim },
    { label: '样本证据', value: detail.has_sample_evidence ? `${number(detail.sample_link_count || detail.sample_links?.length)} 个` : '未提供' },
  ])
  setDetailSection(root, 'data-leak-field-matrix', false)
  setDetailSection(root, 'data-leak-sample-preview', false)
  setDetailSection(root, 'data-leak-dedup', false)
  const eventDetailText = usableText(detail.detail_text) || usableText(detail.summary)
  const eventDetailSection = setDetailSection(root, 'data-leak-event-detail', Boolean(eventDetailText))
  setText(eventDetailSection, 'pre', eventDetailText)
  const translate = query(eventDetailSection, 'button[data-toast]')
  if (translate && usableText(detail.detail_text)) {
    delete translate.dataset.toast
    translate.dataset.runtimeTranslate = '1'
    setActionAvailable(translate, true)
    const original = usableText(detail.detail_text)
    let translated = ''
    let showingTranslated = false
    state.toggleTranslation = async () => {
      if (!translated) {
        const payload = await requestJson(`/api/events/${encodeURIComponent(id)}?translate_detail=true`)
        translated = usableText(payload.detail_text) || original
        if (payload.translation_applied === false || translated === original) {
          throw new Error(payload.translation_error === 'rate_limited' ? '翻译服务请求过于频繁，请稍后重试' : '翻译服务暂时不可用，请稍后重试')
        }
      }
      showingTranslated = !showingTranslated
      setText(eventDetailSection, 'pre', showingTranslated ? translated : original)
      translate.textContent = showingTranslated ? '显示原文' : '显示译文'
    }
  } else if (translate) {
    setActionAvailable(translate, false, '当前记录没有可翻译正文')
  }
  configureSourceAccess(root, {
    sectionId: 'data-leak-mirror-evidence', openId: 'data-leak-open-source', viewId: 'data-leak-view-mirror', downloadId: 'data-leak-download-mirror',
    sourceUrl, resources: referenceResources, fetchedAt: detail.updated_time || detail.disclosure_time,
  })
  hideDetailRail(root, 'data-leak-action-rail')
}

function configureReviewActions(root, state, file, endpoint, currentStatus) {
  const supported = file === 'code-detail.html'
    ? new Map([['确认敏感暴露', 'confirmed'], ['标记误报', 'false_positive']])
    : file === 'netdisk-detail.html'
      ? new Map([['确认企业相关', 'confirmed'], ['标记链接失效', 'closed'], ['标记误报', 'false_positive']])
      : new Map([['确认企业文档', 'confirmed'], ['标记公开资料', 'false_positive'], ['标记误报', 'false_positive']])
  queryAll(root, '[data-disposition]').forEach((button) => {
    const status = supported.get(button.textContent.trim())
    if (status) {
      button.dataset.runtimeReviewStatus = status
      setActionAvailable(button, true)
    } else {
      setActionAvailable(button, false, '当前后端未提供此操作接口')
    }
  })
  const save = queryAll(root, 'button[data-toast]').find((button) => button.textContent.includes('保存'))
  if (save) {
    delete save.dataset.toast
    save.dataset.runtimeReviewSave = '1'
    setActionAvailable(save, true)
  }
  state.pendingReviewStatus = currentStatus || 'new'
  setText(root, '[data-review-state]', reviewStatusLabel(state.pendingReviewStatus))
  state.saveReview = async () => {
    const note = query(root, 'textarea')?.value.trim() || ''
    await requestJson(endpoint, {
      method: 'POST',
      body: JSON.stringify({ status: state.pendingReviewStatus, reviewer: reviewerName(), note }),
    })
    showToast('复核结论已保存')
    await state.refresh?.()
  }
}

function renderRuntimeFileTree(tree, files) {
  const root = { children: new Map() }
  const normalizePath = (value) => String(value || '').replace(/\\/g, '/').replace(/\/+/g, '/').replace(/\/$/, '')

  files.forEach((item, index) => {
    const path = normalizePath(item.path || item.name || `file-${index}`)
    const parts = path.split('/').filter(Boolean)
    if (/^sharelink\d+(?:-|$)/i.test(parts[0] || '')) parts.shift()
    if (!parts.length) return

    let parent = root
    let visiblePath = ''
    parts.forEach((name, partIndex) => {
      visiblePath = visiblePath ? `${visiblePath}/${name}` : name
      const leaf = partIndex === parts.length - 1
      let node = parent.children.get(name)
      if (!node) {
        node = { name, path: visiblePath, size: '', type: '', isDir: !leaf, inferred: false, children: new Map() }
        parent.children.set(name, node)
      }
      if (leaf) {
        node.path = path
        node.size = item.size || ''
        node.type = item.type || ''
        node.inferred = Boolean(item.inferred)
        node.isDir = Boolean(item.isDir || item.is_dir || ['folder', 'dir', 'directory'].includes(String(item.type || '').toLowerCase()))
      } else {
        node.isDir = true
      }
      parent = node
    })
  })

  const descendantCount = (node) => Array.from(node.children.values())
    .reduce((count, child) => count + 1 + descendantCount(child), 0)

  const fileIcon = (node) => {
    const type = String(node.type || node.name.split('.').pop() || '').toLowerCase()
    if (['xls', 'xlsx', 'csv'].includes(type)) return ['xlsx', 'XLS']
    if (['doc', 'docx'].includes(type)) return ['doc', 'DOC']
    if (['ppt', 'pptx'].includes(type)) return ['ppt', 'PPT']
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'].includes(type)) return ['image', 'IMG']
    if (['mp4', 'mov', 'm4v', 'avi', 'mkv'].includes(type)) return ['video', 'VID']
    if (['zip', 'rar', '7z'].includes(type)) return ['zip', 'ZIP']
    if (type === 'pdf') return ['pdf', 'PDF']
    return ['file', 'FILE']
  }

  const renderNode = (node, level) => {
    if (node.isDir || node.children.size) {
      const folder = document.createElement('details')
      folder.className = `tree-folder${level === 0 ? ' tree-root' : ''}`
      folder.open = level <= 1
      folder.dataset.treeEntry = ''
      folder.dataset.treeKind = 'folder'
      folder.dataset.treeLevel = String(level)

      const summary = document.createElement('summary')
      const chevron = document.createElement('span')
      chevron.className = 'tree-chevron'
      chevron.ariaHidden = 'true'
      const icon = document.createElement('span')
      icon.className = 'tree-folder-icon'
      icon.ariaHidden = 'true'
      const name = document.createElement('strong')
      name.textContent = node.name
      name.title = node.path
      const count = document.createElement('span')
      count.className = 'tree-count'
      count.textContent = `${descendantCount(node)} 项`
      summary.append(chevron, icon, name, count)

      const children = document.createElement('div')
      children.className = 'tree-children'
      children.append(...Array.from(node.children.values()).map((child) => renderNode(child, level + 1)))
      folder.append(summary, children)
      return folder
    }

    const row = document.createElement('div')
    row.className = 'tree-file'
    row.dataset.treeEntry = ''
    row.dataset.treeKind = 'file'
    row.dataset.treeLevel = String(level)
    const branch = document.createElement('span')
    branch.className = 'tree-branch'
    branch.ariaHidden = 'true'
    const [iconClass, iconLabel] = fileIcon(node)
    const icon = document.createElement('span')
    icon.className = `tree-file-icon ${iconClass}`
    icon.textContent = iconLabel
    const name = document.createElement('strong')
    name.textContent = node.name
    name.title = node.path
    const evidence = document.createElement('span')
    evidence.className = 'tree-hit'
    const size = document.createElement('span')
    size.className = 'tree-size'
    size.textContent = node.size || ''
    row.append(branch, icon, name, evidence, size)
    return row
  }

  const empty = document.createElement('div')
  empty.className = 'file-tree-empty'
  empty.dataset.treeEmpty = ''
  empty.textContent = '没有匹配的文件或目录'
  empty.hidden = root.children.size > 0
  tree.classList.remove('runtime-file-list')
  tree.replaceChildren(...Array.from(root.children.values()).map((node) => renderNode(node, 0)), empty)
  document.querySelector(`[data-tree-search="${tree.id}"]`)?.dispatchEvent(new Event('input'))
}

async function hydrateDocumentDetail(root, state, file, id) {
  const detail = await requestJson(`/api/document-exposures/${encodeURIComponent(id)}`)
  const netdisk = file === 'netdisk-detail.html'
  const platform = detail.platformLabel || detail.platform || '未知平台'
  const accessLabel = detail.accessStateLabel || detail.accessState || '未提供'
  const files = detail.fileList || []
  const terms = (detail.matchedTerms || []).map((item) => typeof item === 'string' ? item : item?.term || item?.label).filter(Boolean)
  const riskLines = [...new Set(detailRiskLines(detail))]
  const snapshot = detail.latestSnapshot || {}
  const resources = normalizedResourceList(detail.previewAssets, [
    snapshot.screenshotUrl ? { kind: 'screenshot', label: '页面截图', url: snapshot.screenshotUrl } : null,
    snapshot.htmlUrl ? { kind: 'html', label: '页面镜像', url: snapshot.htmlUrl } : null,
  ])
  bindDetailBase(root, detail, [
    ['风险等级', severityLabel(severityOf(detail))],
    [netdisk ? '链接状态' : '访问状态', accessLabel],
    [netdisk ? '文件数量' : '证据数量', number(netdisk ? files.length || detail.fileCount : detail.evidenceCount)],
    ['复核状态', reviewStatusLabel(detail.reviewStatus)],
  ], [
    ['来源平台', platform, '真实来源'],
    [netdisk ? '分享类型' : '文档类型', netdisk ? (detail.shareMeta?.shareType || '未提供') : (detail.documentMeta?.primaryFileType || '未提供'), netdisk ? (detail.fileListMeta?.label || '') : `${number(detail.evidenceCount || 0)} 条证据`],
    ['访问状态', accessLabel, `置信度 ${number(detail.confidenceScore || 0)}`],
    ['发现时间', formatDate(detail.lastSeenAt || detail.firstSeenAt), detail.discoverySourceLabel || '真实采集记录'],
  ])
  setHeroSourceLogo(root, platform)
  setText(root, '.detail-hero .badge', netdisk ? accessLabel : severityLabel(severityOf(detail)))

  if (netdisk) {
    setDefinitionPairs(query(root, '[data-od-id="netdisk-share-information"] .definition-grid'), [
      { label: '监测对象', value: detail.watchlistName || detail.organizationName },
      { label: '来源平台', value: platform },
      { label: '分享链接', value: detail.canonicalUrl, url: detail.canonicalUrl },
      { label: '提取码', value: detail.shareMeta?.shareCode ? '已保存' : '未提供' },
      { label: '分享者', value: detail.shareOwner },
      { label: '最近复检', value: formatFullDate(detail.lastSeenAt) },
    ])
    configureSourceAccess(root, {
      sectionId: 'netdisk-source-access', openId: 'netdisk-open-source', viewId: 'netdisk-view-mirror', downloadId: 'netdisk-download-mirror',
      sourceUrl: detail.canonicalUrl, resources, fetchedAt: snapshot.fetchedAt || detail.lastSeenAt,
    })
    const tree = query(root, '#netdisk-file-tree')
    if (tree) {
      renderRuntimeFileTree(tree, files)
    }
    setText(root, '.file-tree-total', `${detail.fileListMeta?.label || '文件清单'} · ${number(files.length)} 项`)
    const evidenceSection = setDetailSection(root, 'netdisk-keyword-evidence', terms.length > 0 || riskLines.length > 0)
    replaceStructuredRows(query(evidenceSection, '.detail-list'), [
      ...terms.map((term) => ({ label: '命中关键词', value: term, note: '监测对象匹配' })),
      ...riskLines.map((line) => ({ label: '风险依据', value: line, note: '接口分析' })),
    ].slice(0, 8))
    const healthSection = setDetailSection(root, 'netdisk-link-health', Boolean(detail.accessState || detail.lastSeenAt))
    replaceStructuredRows(query(healthSection, '.detail-list'), [
      { label: '访问状态', value: accessLabel, note: detail.accessState || '' },
      { label: '最近复检', value: formatFullDate(detail.lastSeenAt), note: platform },
      { label: '置信度', value: `${number(detail.confidenceScore || 0)} / 100`, note: detail.fileListMeta?.label || '' },
    ])
  } else {
    setDefinitionPairs(query(root, '[data-od-id="library-document-metadata"] .definition-grid'), [
      { label: '监测对象', value: detail.watchlistName || detail.organizationName },
      { label: '文档标题', value: detail.title },
      { label: '上传者', value: detail.shareOwner },
      { label: '文档类型', value: detail.documentMeta?.primaryFileType },
      { label: '来源链接', value: detail.canonicalUrl, url: detail.canonicalUrl },
      { label: '最近复检', value: formatFullDate(detail.lastSeenAt) },
    ])
    configureSourceAccess(root, {
      sectionId: 'library-source-access', openId: 'library-open-source', viewId: 'library-view-mirror', downloadId: 'library-download-mirror',
      sourceUrl: detail.canonicalUrl, resources, fetchedAt: snapshot.fetchedAt || detail.lastSeenAt,
    })
    const previewText = snapshot.ocrText || snapshot.previewText || detail.summary || ''
    const proofSection = setDetailSection(root, 'library-page-evidence', Boolean(previewText || terms.length))
    queryAll(proofSection, '.detail-proof').forEach((proof, index) => {
      const value = index === 0 ? previewText : ''
      proof.hidden = !value
      if (!value) return
      const label = document.createElement('span')
      label.textContent = snapshot.ocrText ? 'OCR 采集内容' : '页面采集摘要'
      const content = document.createElement('strong')
      content.textContent = value.slice(0, 700)
      const source = document.createElement('code')
      source.textContent = snapshot.pageTitle || detail.title || platform
      proof.replaceChildren(label, content, source)
    })
    replaceStructuredRows(query(proofSection, '.detail-list'), terms.map((term) => ({
      label: '命中关键词', value: term, note: '接口匹配',
    })))
    const focus = queryAll(proofSection, 'button[data-toast]').find((button) => button.textContent.includes('查看重点页'))
    if (focus && previewText) {
      delete focus.dataset.toast
      focus.dataset.runtimeScroll = '.detail-proof:not([hidden])'
      setActionAvailable(focus, true)
    }
    const ownership = setDetailSection(root, 'library-ownership-check', Boolean(detail.watchlistName || detail.organizationName || terms.length))
    replaceStructuredRows(query(ownership, '.detail-list'), [
      { label: '监测对象', value: detail.watchlistName || detail.organizationName, note: '监测配置' },
      { label: '组织名称', value: detail.organizationName, note: '企业关联' },
      { label: '命中关键词', value: terms.join(' / '), note: terms.length ? `${terms.length} 个` : '' },
    ])
    const reasoning = setDetailSection(root, 'library-risk-reasoning', riskLines.length > 0)
    replaceStructuredRows(query(reasoning, '.detail-list'), riskLines.map((line) => ({
      label: '风险依据', value: line, note: `${number(detail.riskScore || 0)} / 100`,
    })))
  }

  const exportButton = queryAll(root, 'button[data-toast]').find((button) => button.textContent.includes('导出清单'))
  if (exportButton && netdisk) {
    const virtualTable = document.createElement('table')
    const body = document.createElement('tbody')
    files.forEach((item) => {
      const row = document.createElement('tr')
      ;[item.path || item.name, item.type, item.size].forEach((value) => {
        const cell = document.createElement('td')
        cell.textContent = value || '—'
        row.appendChild(cell)
      })
      body.appendChild(row)
    })
    virtualTable.appendChild(body)
    const key = 'document-files'
    delete exportButton.dataset.toast
    exportButton.dataset.runtimeExport = key
    state.tables.set(key, virtualTable)
    setActionAvailable(exportButton, true)
  }
  configureReviewActions(root, state, file, `/api/document-exposures/${encodeURIComponent(id)}/review`, detail.reviewStatus)
}

async function hydrateCodeDetail(root, state, id) {
  const detail = await requestJson(`/api/code-monitoring/hits/${encodeURIComponent(id)}`)
  const platform = detail.platformLabel || detail.platform || '未知平台'
  const resources = normalizedResourceList(detail.previewAssets, detail.sourceLinks)
  const riskLines = [...new Set(detailRiskLines(detail))]
  bindDetailBase(root, detail, [
    ['命中层级', detail.resultLayerLabel || detail.resultLayer],
    ['风险等级', severityLabel(severityOf(detail))],
    ['仓库状态', detail.visibility || '—'],
    ['复核状态', reviewStatusLabel(detail.reviewStatus)],
  ], [
    ['来源平台', platform, '真实来源'],
    ['文件路径', detail.filePath || '—', detail.branch || '—'],
    ['敏感发现', `${(detail.findings || []).length} 项`, detail.sensitiveLabel || detail.matchedRule || '—'],
    ['最近发现', formatDate(detail.lastSeenAt), `${number(detail.evidenceCount || 0)} 条证据`],
  ])
  setHeroSourceLogo(root, platform)
  setDefinitionPairs(query(root, '[data-od-id="code-repository-information"] .definition-grid'), [
    { label: '监测对象', value: detail.watchlistName || detail.organizationName },
    { label: '仓库', value: detail.repositoryFullName },
    { label: '分支', value: detail.branch },
    { label: '文件路径', value: detail.filePath },
    { label: '语言', value: detail.language },
    { label: '发现时间', value: formatFullDate(detail.lastSeenAt || detail.firstSeenAt) },
  ])
  configureSourceAccess(root, {
    sectionId: 'code-source-access', openId: 'code-open-source', viewId: 'code-view-mirror', downloadId: 'code-download-mirror',
    sourceUrl: detail.fileUrl || detail.repositoryUrl, resources, fetchedAt: detail.latestSnapshot?.fetchedAt || detail.lastSeenAt,
  })
  state.copyText = detail.codePreview || ''
  const copy = queryAll(root, 'button[data-toast]').find((button) => button.textContent.includes('复制片段'))
  if (copy) {
    delete copy.dataset.toast
    copy.dataset.runtimeCopy = detail.codePreview || ''
    setActionAvailable(copy, Boolean(detail.codePreview), detail.codePreview ? '' : '接口未提供代码片段')
  }
  queryAll(root, '.detail-code').forEach((code) => { code.textContent = detail.codePreview || '暂无代码预览' })
  const findings = setDetailSection(root, 'code-sensitive-findings', (detail.findings || []).length > 0)
  replaceStructuredRows(query(findings, '.detail-list'), (detail.findings || []).map((item) => ({
    label: item.label || item.ruleLabel || '敏感发现',
    value: item.ruleKey || detail.matchedRule || '规则命中',
    note: item.secretLike ? '秘密值特征' : `权重 ${number(item.weight || 0)}`,
  })))
  const anchors = (detail.enterpriseAnchors || []).map((item) => ({
    label: typeof item === 'string' ? '企业锚点' : (item.label || item.type || '企业锚点'),
    value: typeof item === 'string' ? item : (item.value || item.term || item.name || '已匹配'),
    note: detail.enterpriseMatchLevel || '',
  }))
  const enterprise = setDetailSection(root, 'code-enterprise-context', anchors.length > 0)
  replaceStructuredRows(query(enterprise, '.detail-list'), anchors)
  const context = setDetailSection(root, 'code-context-review', true)
  replaceStructuredRows(query(context, '.detail-matrix'), [
    { label: '敏感类型', value: detail.sensitiveLabel || detail.sensitiveType || '未标注' },
    { label: '匹配规则', value: detail.matchedRule || '未标注' },
    { label: '企业关联', value: detail.enterpriseMatchLevel || 'none' },
    { label: '压制状态', value: detail.suppressed ? '已压制' : '未压制' },
  ])
  replaceStructuredRows(query(context, '.detail-list'), [
    ...riskLines.map((line) => ({ label: '风险依据', value: line, note: '接口分析' })),
    ...(detail.suppressionReasons || []).map((line) => ({ label: '压制依据', value: line, note: '接口分析' })),
  ])
  configureReviewActions(root, state, 'code-detail.html', `/api/code-monitoring/hits/${encodeURIComponent(id)}/review`, detail.reviewStatus)
}

export function disposePrototypeScreen(root) {
  if (!root) return
  root.__intelligenceRequest = null
  if (root.__codeContinuousStatusTimer) {
    window.clearInterval(root.__codeContinuousStatusTimer)
    root.__codeContinuousStatusTimer = null
  }
}

export async function hydratePrototypeScreen({ root, route, file }) {
  if (!root) return
  hydrateAccount(root)
  if (!DATA_FILES.has(file)) return
  if (file === 'intelligence.html') {
    await hydrateIntelligence(root)
    return
  }
  prepareDataPage(root, file)
  const state = { tables: new Map(), refresh: null }
  installActionGuard(root, state)
  const id = String(route?.params?.eventId || route?.params?.hitId || document.body.dataset.prototypeRecordId || '')

  try {
    if (file === 'dashboard.html') await hydrateDashboard(root, state)
    else if (file === 'intelligence.html') await hydrateIntelligence(root)
    else if (file === 'ransomware.html') await hydrateRansomware(root, state)
    else if (file === 'data-leak.html') await hydrateDataLeak(root, state)
    else if (file === 'vulnerabilities.html') await hydrateVulnerabilities(root, state)
    else if (file === 'monitoring.html') {
      const source = route?.meta?.source || document.body.dataset.prototypeSource || 'netdisk'
      if (source === 'code') await hydrateCodeMonitoring(root, state)
      else await hydrateDocumentMonitoring(root, state, source)
    } else if (INCIDENT_FILES.has(file)) {
      await hydrateIncidentDetail(root, state, file, id)
    } else if (REVIEW_FILES.has(file)) {
      state.refresh = file === 'code-detail.html'
        ? () => hydrateCodeDetail(root, state, id)
        : () => hydrateDocumentDetail(root, state, file, id)
      await state.refresh()
    } else if (file === 'collector-run-detail.html') await hydrateCollectorRunDetail(root, route)
    setDataState(root, 'ready')
  } catch (error) {
    showLoadError(root, error)
  }
}
