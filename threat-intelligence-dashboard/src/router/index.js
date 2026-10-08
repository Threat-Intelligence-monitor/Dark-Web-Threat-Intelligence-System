import { createRouter, createWebHistory } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  hasAuthSession,
  hasModuleAccess,
  isAuthSessionValidated,
  isCurrentUserAdmin,
  loadCurrentUser,
} from '@/composables/useAuth'
import { ASSIGNABLE_MODULE_KEYS, MODULE_KEYS } from '@/config/permissions'
import PrototypeScreen from '@/views/PrototypeScreen.vue'
import DataMigration from '@/views/DataMigration.vue'
import AccountManagement from '@/views/AccountManagement.vue'
import DocumentExposureScans from '@/views/DocumentExposureScans.vue'
import SocialMonitoring from '@/views/SocialMonitoring.vue'

const screen = (path, name, file, meta = {}) => ({
  path,
  name,
  component: PrototypeScreen,
  meta: { screen: file, ...meta },
})

const routes = [
  screen('/login', 'Login', 'index.html', { public: true }),
  screen('/', 'Dashboard', 'dashboard.html'),
  screen('/intelligence', 'IntelligenceSearch', 'intelligence.html'),
  screen('/ransomware', 'Ransomware', 'ransomware.html'),
  screen('/ransomware/:eventId', 'RansomwareDetail', 'ransomware-detail.html'),
  screen('/data-leak', 'DataLeak', 'data-leak.html'),
  screen('/data-leak/:eventId', 'DataLeakDetail', 'data-leak-detail.html'),
  screen('/vulnerability-alerts', 'VulnerabilityAlerts', 'vulnerabilities.html'),
  screen('/vulnerability-alerts/:eventId', 'VulnerabilityDetail', 'vulnerability-detail.html'),
  screen('/document-exposure/netdisk', 'DocumentExposureNetdisk', 'monitoring.html', { source: 'netdisk' }),
  screen('/document-exposure/document-library', 'DocumentExposureDocumentLibrary', 'monitoring.html', { source: 'library' }),
  screen('/document-exposure/code-monitoring', 'CodeMonitoringWorkbench', 'monitoring.html', { source: 'code' }),
  { path: '/social-monitoring', name: 'SocialMonitoring', component: SocialMonitoring, meta: { layout: 'prototype-vue' } },
  screen('/document-exposure/detail/netdisk_aggregator/:hitId', 'DocumentExposureNetdiskDetail', 'netdisk-detail.html', { source: 'netdisk' }),
  screen('/document-exposure/detail/document_library/:hitId', 'DocumentExposureLibraryDetail', 'library-detail.html', { source: 'library' }),
  screen('/document-exposure/code-monitoring/detail/:hitId', 'CodeMonitoringDetail', 'code-detail.html', { source: 'code' }),
  { path: '/document-exposure/scans', name: 'DocumentExposureScans', component: DocumentExposureScans, meta: { layout: 'prototype-vue' } },
  screen('/collector-control/sites', 'CollectorSites', 'collector-sites.html'),
  screen('/collector-control/sync', 'CollectorSync', 'collector-sync.html'),
  screen('/collector-control/runtime', 'CollectorRuntime', 'collector-runtime.html'),
  screen('/collector-control/failures', 'CollectorFailures', 'collector-failures.html'),
  screen('/collector-control/run/:runId', 'CollectorRunDetail', 'collector-run-detail.html'),
  screen('/settings', 'Settings', 'settings.html'),
  { path: '/settings/data-migration', name: 'DataMigration', component: DataMigration, meta: { adminOnly: true } },
  {
    path: '/account-management',
    name: 'AccountManagement',
    component: AccountManagement,
    meta: { adminOnly: true, layout: 'prototype-vue' },
  },
  screen('/event/:eventId', 'EventDetail', 'event-detail.html'),
  { path: '/threat-situation', redirect: '/' },
  { path: '/collector-control', redirect: '/collector-control/sites' },
  { path: '/document-exposure', redirect: '/document-exposure/netdisk' },
  { path: '/document-exposure/settings', redirect: '/settings?tab=objects&module=netdisk' },
  { path: '/document-exposure/netdisk/settings', redirect: '/settings?tab=objects&module=netdisk' },
  { path: '/document-exposure/document-library/settings', redirect: '/settings?tab=objects&module=library' },
  { path: '/document-exposure/code-monitoring/settings', redirect: '/settings?tab=objects&module=code' },
  { path: '/document-exposure/results', redirect: '/document-exposure/netdisk' },
  { path: '/document-exposure/code-monitoring/scans', redirect: '/collector-control/failures' },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

const PATH_MODULES = [
  ['/intelligence', MODULE_KEYS.INTELLIGENCE_SEARCH],
  ['/ransomware', MODULE_KEYS.RANSOMWARE],
  ['/data-leak', MODULE_KEYS.DATA_LEAK],
  ['/vulnerability-alerts', MODULE_KEYS.VULNERABILITY_ALERTS],
  ['/collector-control', MODULE_KEYS.COLLECTOR_CONTROL],
  ['/document-exposure', MODULE_KEYS.FILE_MONITORING],
  ['/social-monitoring', MODULE_KEYS.SOCIAL_MONITORING],
  ['/settings', MODULE_KEYS.FILE_MONITORING],
]

function eventDetailModule(to) {
  const rawModule = Array.isArray(to.query.module) ? to.query.module[0] : to.query.module
  const requestedModule = String(rawModule || '')
  if (ASSIGNABLE_MODULE_KEYS.includes(requestedModule)) return requestedModule

  const eventId = String(to.params.eventId || '')
  if (eventId.startsWith('vuln:')) return MODULE_KEYS.VULNERABILITY_ALERTS
  if (eventId.startsWith('document:')) return MODULE_KEYS.FILE_MONITORING
  return ''
}

function requiredModuleForRoute(to) {
  if (to.name === 'EventDetail') return eventDetailModule(to)
  const match = PATH_MODULES.find(([path]) => to.path === path || to.path.startsWith(`${path}/`))
  return match?.[1] || ''
}

function permissionDeniedRedirect(message) {
  ElMessage.warning(message)
  return { name: 'Dashboard' }
}

router.beforeEach(async (to) => {
  if (to.meta.public) {
    if (!hasAuthSession()) return true
    if (!isAuthSessionValidated() && !(await loadCurrentUser())) return true
    return '/'
  }

  if (!hasAuthSession()) return { path: '/login', query: { redirect: to.fullPath } }
  if (!isAuthSessionValidated() && !(await loadCurrentUser())) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }

  if (to.meta.adminOnly && !isCurrentUserAdmin()) {
    return permissionDeniedRedirect('仅管理员可以访问该功能')
  }

  const requiredModule = requiredModuleForRoute(to)
  if (to.name === 'EventDetail' && !requiredModule && !isCurrentUserAdmin()) {
    return permissionDeniedRedirect('无法确认事件所属模块，暂无权限查看详情')
  }
  if (requiredModule && !hasModuleAccess(requiredModule)) {
    return permissionDeniedRedirect('当前账号没有该模块的访问权限')
  }
  return true
})

export default router
