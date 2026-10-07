const BASE = '/api'
const KEY_STORAGE = 'peinsight-api-key'

/**
 * 共享密钥。后端默认**不需要**鉴权，只有设置了 PEINSIGHT_API_KEY 时才校验。
 * 一旦后端开了鉴权，前端也必须带上同一个值，否则所有请求都会 401。
 * 存在 localStorage，只在浏览器本地，不会随构建产物分发出去。
 */
export function getApiKey() {
  try {
    return localStorage.getItem(KEY_STORAGE) || ''
  } catch {
    return '' // 隐私模式下 localStorage 可能不可用
  }
}

export function setApiKey(value) {
  try {
    if (value) localStorage.setItem(KEY_STORAGE, value)
    else localStorage.removeItem(KEY_STORAGE)
  } catch {
    /* 忽略：存不了就只在本次会话有效 */
  }
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  const key = getApiKey()
  if (key) headers['X-API-Key'] = key

  const res = await fetch(BASE + path, { ...options, headers })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail || detail
    } catch {
      /* 响应体不是 JSON，沿用 statusText */
    }
    throw new Error(detail)
  }
  return res.json()
}

export const listScans = () => request('/scans')

export const getScan = (id) => request(`/scans/${id}`)

export const getEngines = () => request('/engines')

export const getPrivacy = () => request('/privacy')

export const deleteScan = (id) => request(`/scans/${id}`, { method: 'DELETE' })

/** 扫描本机路径——单机桌面工具的主用法，样本不经过 HTTP。 */
export const scanLocalPath = (path, runDynamic) =>
  request('/scans/local', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, run_dynamic: runDynamic }),
  })

export const uploadAndScan = (file, runDynamic) => {
  const form = new FormData()
  form.append('file', file)
  return request(`/scans/upload?run_dynamic=${runDynamic}`, {
    method: 'POST',
    body: form,
  })
}
