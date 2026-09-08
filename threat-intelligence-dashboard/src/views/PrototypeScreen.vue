<template>
  <div ref="screenRoot" class="prototype-screen" @click="handleNavigation"></div>
</template>

<script setup>
import { nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { initializePrototype } from '@/prototype/runtime'
import { disposePrototypeScreen, hydratePrototypeScreen } from '@/prototype/dataRuntime'

const screens = import.meta.glob('@/prototype/screens/*.html', {
  eager: true,
  query: '?raw',
  import: 'default',
})

const route = useRoute()
const router = useRouter()
const screenRoot = ref(null)
let renderVersion = 0
let activeFile = ''

const screenRoutes = {
  'dashboard.html': '/',
  'intelligence.html': '/intelligence',
  'ransomware.html': '/ransomware',
  'data-leak.html': '/data-leak',
  'vulnerabilities.html': '/vulnerability-alerts',
  'collector-sites.html': '/collector-control/sites',
  'collector-sync.html': '/collector-control/sync',
  'collector-runtime.html': '/collector-control/runtime',
  'collector-failures.html': '/collector-control/failures',
  'settings.html': '/settings',
}

function screenSource(file) {
  const entry = Object.entries(screens).find(([path]) => path.endsWith(`/screens/${file}`))
  if (!entry) throw new Error(`Prototype screen not found: ${file}`)
  return entry[1]
}

function rewriteHref(rawHref) {
  if (!rawHref || rawHref.startsWith('#') || /^(https?:|mailto:|tel:)/i.test(rawHref)) return rawHref
  const url = new URL(rawHref, 'https://prototype.local/')
  const file = url.pathname.split('/').pop()
  const id = url.searchParams.get('id') || ''
  if (file === 'index.html') return '/login'
  if (file === 'monitoring.html') {
    const sourceRoute = { library: 'document-library', code: 'code-monitoring' }[url.searchParams.get('source')]
      || url.searchParams.get('source')
      || 'netdisk'
    return `/document-exposure/${sourceRoute}`
  }
  if (file === 'ransomware-detail.html') return `/ransomware/${encodeURIComponent(id)}`
  if (file === 'data-leak-detail.html') return `/data-leak/${encodeURIComponent(id)}`
  if (file === 'vulnerability-detail.html') return `/vulnerability-alerts/${encodeURIComponent(id)}`
  if (file === 'netdisk-detail.html') return `/document-exposure/detail/netdisk_aggregator/${encodeURIComponent(id)}`
  if (file === 'library-detail.html') return `/document-exposure/detail/document_library/${encodeURIComponent(id)}`
  if (file === 'code-detail.html') return `/document-exposure/code-monitoring/detail/${encodeURIComponent(id)}`
  if (file === 'event-detail.html') return `/event/${encodeURIComponent(id)}`
  if (file === 'collector-run-detail.html') {
    const params = new URLSearchParams(url.searchParams)
    params.delete('id')
    const query = params.toString()
    return `/collector-control/run/${encodeURIComponent(id || 'latest')}${query ? `?${query}` : ''}`
  }
  const routePath = screenRoutes[file]
  return routePath ? `${routePath}${url.search}` : rawHref
}

function handleNavigation(event) {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
  const link = event.target.closest('a[href]')
  if (!link || !screenRoot.value?.contains(link) || link.hasAttribute('download') || link.target === '_blank') return
  const href = link.getAttribute('href')
  if (!href || href.startsWith('#') || /^(mailto:|tel:|javascript:)/i.test(href)) return
  const url = new URL(href, window.location.href)
  if (url.origin !== window.location.origin) return
  event.preventDefault()
  router.push(`${url.pathname}${url.search}${url.hash}`)
}

async function renderScreen() {
  const version = ++renderVersion
  const file = route.meta.screen
  if (activeFile === 'intelligence.html' && file === activeFile && screenRoot.value) {
    await hydratePrototypeScreen({ root: screenRoot.value, route, file })
    return
  }
  disposePrototypeScreen(screenRoot.value)

  const source = screenSource(file)
  const parsed = new DOMParser().parseFromString(source, 'text/html')
  parsed.querySelectorAll('script').forEach((script) => script.remove())
  parsed.querySelectorAll('a[href]').forEach((link) => link.setAttribute('href', rewriteHref(link.getAttribute('href'))))
  parsed.querySelectorAll('[src]').forEach((node) => {
    const sourcePath = node.getAttribute('src')
    if (sourcePath?.startsWith('assets/')) node.setAttribute('src', `/${sourcePath}`)
  })
  parsed.querySelectorAll('image[href]').forEach((node) => {
    const sourcePath = node.getAttribute('href')
    if (sourcePath?.startsWith('assets/')) node.setAttribute('href', `/${sourcePath}`)
  })
  const monitoringTitle = {
    netdisk: '网盘监测 · 玄鉴',
    library: '文库监测 · 玄鉴',
    code: '代码监测 · 玄鉴'
  }[route.meta.source]
  document.title = monitoringTitle || parsed.title || '玄鉴威胁情报平台'
  document.body.className = parsed.body.className
  document.body.dataset.prototypePage = file
  document.body.dataset.prototypeSource = route.meta.source || ''
  document.body.dataset.prototypeRecordId = String(route.params.eventId || route.params.hitId || route.params.runId || '')
  await nextTick()
  if (version !== renderVersion || !screenRoot.value) return
  screenRoot.value.innerHTML = parsed.body.innerHTML
  activeFile = file
  initializePrototype()
  await hydratePrototypeScreen({ root: screenRoot.value, route, file })
}

watch(() => route.fullPath, renderScreen, { immediate: true })

onBeforeUnmount(() => {
  disposePrototypeScreen(screenRoot.value)
  delete document.body.dataset.prototypePage
  delete document.body.dataset.prototypeSource
  delete document.body.dataset.prototypeRecordId
})
</script>
