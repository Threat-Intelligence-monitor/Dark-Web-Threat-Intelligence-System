export function shouldRenderResourceAsImage(resource = {}) {
  const kind = String(resource.kind || '').toLowerCase()
  if (kind === 'source_image') return false
  return kind === 'image' || kind === 'screenshot' || /截图|image/i.test(String(resource.label || ''))
}

export function shouldRenderResourceAsHtml(resource = {}) {
  return String(resource.kind || '').toLowerCase() === 'html'
    || /\.html?(?:[?#]|$)/i.test(String(resource.url || ''))
    || /\bhtml?\b/i.test(String(resource.label || ''))
}
