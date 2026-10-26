import { requestJson } from '@/composables/requestJson'

function buildQuery(params = {}) {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value == null || value === '') continue
    query.set(key, String(value))
  }
  const text = query.toString()
  return text ? `?${text}` : ''
}

export function useDocumentExposureApi() {
  return {
    loadSummary(params = {}) {
      return requestJson(`/api/document-exposures/summary${buildQuery({
        source_family: params.sourceFamily,
      })}`)
    },
    loadSessions(module = 'document_exposure') {
      return requestJson(`/api/platform-sessions${buildQuery({ module })}`)
    },
    loadPlatforms(module = 'document_exposure') {
      return requestJson(`/api/exposure-platforms${buildQuery({ module })}`)
    },
    launchLogin(platform) {
      return requestJson(`/api/platform-sessions/${encodeURIComponent(platform)}/launch-login`, {
        method: 'POST',
      })
    },
    saveSession(platform, accountLabel) {
      return requestJson(`/api/platform-sessions/${encodeURIComponent(platform)}/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ account_label: accountLabel || '' }),
      })
    },
    verifySession(platform) {
      return requestJson(`/api/platform-sessions/${encodeURIComponent(platform)}/verify`, {
        method: 'POST',
      })
    },
    deleteSession(platform) {
      return requestJson(`/api/platform-sessions/${encodeURIComponent(platform)}`, {
        method: 'DELETE',
      })
    },
    loadWatchlists() {
      return requestJson('/api/exposure-watchlists')
    },
    saveWatchlist(payload) {
      return requestJson('/api/exposure-watchlists', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
    },
    runScan(watchlistId, payload) {
      return requestJson(`/api/exposure-watchlists/${watchlistId}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
    },
    loadScans(params = {}) {
      return requestJson(`/api/exposure-scans${buildQuery({
        watchlist_id: params.watchlistId,
        limit: params.limit,
      })}`)
    },
    loadContinuousStatus(params = {}) {
      return requestJson(`/api/document-exposures/continuous-status${buildQuery({
        watchlist_id: params.watchlistId,
      })}`)
    },
    startContinuous(payload) {
      return requestJson('/api/document-exposures/continuous/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
    },
    stopContinuous(payload) {
      return requestJson('/api/document-exposures/continuous/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
    },
    loadNetdiskContinuousStatus(params = {}) {
      return requestJson(`/api/document-exposures/netdisk/continuous-status${buildQuery({
        watchlist_id: params.watchlistId,
      })}`)
    },
    loadNetdiskSourceStates(params = {}) {
      return requestJson(`/api/document-exposures/netdisk/source-states${buildQuery({
        watchlist_id: params.watchlistId,
      })}`)
    },
    loadNetdiskSourceHealth(params = {}) {
      return requestJson(`/api/document-exposures/netdisk/source-health${buildQuery({
        source_family: params.sourceFamily,
      })}`)
    },
    runNetdiskContinuousOnce() {
      return requestJson('/api/document-exposures/netdisk/continuous/run', {
        method: 'POST',
      })
    },
    startNetdiskContinuous(payload) {
      return requestJson('/api/document-exposures/netdisk/continuous/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
    },
    stopNetdiskContinuous(payload) {
      return requestJson('/api/document-exposures/netdisk/continuous/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
    },
    loadHits(params = {}) {
      return requestJson(`/api/document-exposures${buildQuery({
        watchlist_id: params.watchlistId,
        review_status: params.reviewStatus,
        platform: params.platform,
        access_state: params.accessState,
        source_family: params.sourceFamily,
        limit: params.limit,
      })}`)
    },
    loadHitsPage(params = {}) {
      return requestJson(`/api/document-exposures/page${buildQuery({
        watchlist_id: params.watchlistId,
        review_status: params.reviewStatus,
        platform: params.platform,
        access_state: params.accessState,
        source_family: params.sourceFamily,
        severity: params.severity,
        recent_hours: params.recentHours,
        query: params.query,
        offset: params.offset,
        limit: params.limit,
      })}`)
    },
    loadHitDetail(hitId) {
      return requestJson(`/api/document-exposures/${hitId}`)
    },
    reviewHit(hitId, payload) {
      return requestJson(`/api/document-exposures/${hitId}/review`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
    },
  }
}
