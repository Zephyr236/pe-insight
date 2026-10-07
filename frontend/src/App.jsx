import { useCallback, useEffect, useState } from 'react'
import { listScans, getEngines, getPrivacy, getApiKey, setApiKey } from './api'
import ScanForm from './components/ScanForm'
import ScanList from './components/ScanList'
import ScanDetail from './components/ScanDetail'

export default function App() {
  const [scans, setScans] = useState([])
  const [engines, setEngines] = useState([])
  const [privacy, setPrivacy] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [error, setError] = useState(null)
  const [keySet, setKeySet] = useState(() => Boolean(getApiKey()))
  const [theme, setTheme] = useState(() => {
    // 有显式选择就用它；否则跟随系统偏好，避免按钮标签与实际渲染不一致
    const saved = document.documentElement.dataset.theme
    if (saved) return saved
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })

  const refresh = useCallback(async () => {
    try {
      setScans(await listScans())
    } catch (err) {
      setError(err.message)
    }
  }, [])

  useEffect(() => {
    refresh()
    getEngines().then(setEngines).catch(() => {})
    getPrivacy().then(setPrivacy).catch(() => {})
  }, [refresh])

  useEffect(() => {
    if (!error) return
    const timer = setTimeout(() => setError(null), 6000)
    return () => clearTimeout(timer)
  }, [error])

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    document.documentElement.dataset.theme = next
    try {
      localStorage.setItem('peinsight-theme', next)
    } catch {
      /* 隐私模式下 localStorage 可能不可用 */
    }
  }

  /**
   * 设置/清除共享密钥。
   *
   * 后端默认**不需要**鉴权——只有设置了 PEINSIGHT_API_KEY 才校验。
   * 所以本地单机用的时候这一步完全可以跳过；把服务挂到内网给别的机器用时
   * 才需要，而且前端必须和后端填同一个值，否则所有请求都会 401。
   */
  function configureKey() {
    const input = window.prompt(
      '设置 API Key\n\n' +
        '· 后端未设 PEINSIGHT_API_KEY 时，这里留空即可\n' +
        '· 后端设了的话，这里要填同一个值\n\n' +
        '当前：' + (getApiKey() ? '（已设置）' : '（未设置）'),
      getApiKey(),
    )
    if (input === null) return // 用户取消

    const value = input.trim()
    setApiKey(value)
    setKeySet(Boolean(value))
    // 立刻用新密钥重新拉一遍，让状态马上反映出来
    refresh()
    getEngines().then(setEngines).catch(() => {})
  }

  const available = engines.filter((e) => e.active).length
  const excluded = engines.filter((e) => e.available && !e.active)

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand__name">PE Insight</span>
          <span className="brand__tag">本地多引擎 PE 分析 · 样本不出本机</span>
        </div>

        <div className="engines-strip" title="引擎状态">
          {engines.map((e) => {
            // 四种状态：完全本地 / 仅元数据外传 / 被策略排除 / 不可用
            let state = 'off'
            if (e.available) {
              if (!e.active) state = 'warn'
              else if (e.network_level === 'metadata') state = 'meta'
              else state = 'on'
            }
            return (
              <span
                key={e.name}
                className={`chip chip--engine is-${state}`}
                title={`${e.network_level_text || ''}　${e.excluded_reason || e.reason || e.network_note || '可用'}`}
              >
                <span className="dot" aria-hidden="true" />
                {e.name}
                {e.active && e.network_level === 'metadata' && (
                  <span className="chip__badge">元数据</span>
                )}
              </span>
            )
          })}
          <span className="muted engines-strip__count">
            {available}/{engines.length} 已启用
          </span>
        </div>

        <button className="btn btn--ghost btn--sm" onClick={configureKey}>
          {keySet ? '🔑 已设密钥' : '🔑 密钥'}
        </button>

        <button className="btn btn--ghost btn--sm" onClick={toggleTheme}>
          {theme === 'dark' ? '☀ 浅色' : '☾ 深色'}
        </button>
      </header>

      {error && (
        <div className="toast" role="alert">
          {error}
        </div>
      )}

      {/* 外传通道必须显式暴露：这是本产品唯一无法自己兜住的隐私缺口 */}
      {excluded.length > 0 ? (
        <div className="banner banner--warn" role="status">
          <span className="banner__icon" aria-hidden="true">
            ⚠
          </span>
          <div>
            <strong>{excluded.map((e) => e.name).join('、')} 已安装但未启用</strong>
            <span>
              {excluded[0].excluded_reason}
              {'　可收紧该引擎的外传行为，或用 '}
              <code>PEINSIGHT_NETWORK_POLICY=any</code>
              {' 放宽策略。'}
            </span>
          </div>
        </div>
      ) : (
        privacy?.defender?.warning && (
          <div className="banner banner--warn" role="status">
            <span className="banner__icon" aria-hidden="true">
              ⚠
            </span>
            <div>
              <strong>Defender 存在元数据外传</strong>
              <span>{privacy.defender.warning}</span>
            </div>
          </div>
        )
      )}

      <div className="layout">
        <aside className="sidebar">
          <ScanForm
            onSubmitted={(id) => {
              setSelectedId(id)
              refresh()
            }}
            onError={setError}
          />
          <ScanList scans={scans} selectedId={selectedId} onSelect={setSelectedId} />
        </aside>

        <main className="main">
          {selectedId ? (
            <ScanDetail
              id={selectedId}
              onFinished={refresh}
              onDeleted={() => {
                setSelectedId(null)
                refresh()
              }}
              onError={setError}
            />
          ) : (
            <div className="detail detail--empty">
              <div>
                <h2 className="empty__title">选择或提交一个样本</h2>
                <p className="muted">
                  扫描在本机完成：多引擎签名查杀 + PE 结构分析 + Speakeasy 模拟执行。
                </p>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
