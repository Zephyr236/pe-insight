import { useEffect, useState } from 'react'
import { getScan, deleteScan } from '../api'
import { verdictOf } from '../verdict'
import { formatBytes, shortHash } from '../format'
import VerdictBadge from './VerdictBadge'
import StatTile from './StatTile'
import EngineTable from './EngineTable'
import StaticPanel from './StaticPanel'
import DynamicPanel from './DynamicPanel'

const TABS = [
  { key: 'engines', label: '引擎结果' },
  { key: 'static', label: '静态分析' },
  { key: 'dynamic', label: '动态分析' },
]

export default function ScanDetail({ id, onFinished, onDeleted, onError }) {
  const [scan, setScan] = useState(null)
  const [tab, setTab] = useState('engines')

  useEffect(() => {
    let cancelled = false
    let timer

    async function load() {
      try {
        const data = await getScan(id)
        if (cancelled) return
        setScan(data)
        if (data.status === 'pending' || data.status === 'running') {
          timer = setTimeout(load, 1500)
        } else {
          onFinished?.()
        }
      } catch (err) {
        if (!cancelled) onError?.(err.message)
      }
    }

    setScan(null)
    load()
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id])

  if (!scan) return <div className="detail detail--loading">加载中…</div>

  const inProgress = scan.status === 'pending' || scan.status === 'running'
  const v = verdictOf(scan.status === 'done' ? scan.verdict : scan.status)

  async function handleDelete() {
    if (!confirm(`删除扫描记录「${scan.filename}」？（样本文件保留在数据目录）`)) return
    try {
      await deleteScan(id)
      onDeleted?.()
    } catch (err) {
      onError?.(err.message)
    }
  }

  return (
    <div className="detail">
      <header className="detail__head">
        <div>
          <h2 className="detail__title">{scan.filename}</h2>
          <div className="detail__hashes mono">
            <span title="SHA256">{shortHash(scan.sha256)}</span>
          </div>
        </div>
        <button className="btn btn--ghost btn--sm" onClick={handleDelete}>
          删除记录
        </button>
      </header>

      {/* 唯一的英雄数字：整份报告的结论 */}
      <section className="hero" style={{ '--hero-color': `var(${v.cssVar})` }}>
        <div className="hero__figure">
          <span className="hero__icon" aria-hidden="true">
            {v.icon}
          </span>
          <span className="hero__label">{v.label}</span>
        </div>
        <div className="hero__sub">
          {inProgress
            ? '正在扫描，结果稍后自动刷新…'
            : scan.status === 'failed'
              ? scan.error || '扫描失败'
              : `检出 ${scan.detection_ratio} 个引擎`}
        </div>
      </section>

      {/* "样本未外传"的实证：扫描期间真的没有产生任何外部连接 */}
      {scan.network && (
        <div
          className={`netstrip ${
            !scan.network.enforced
              ? 'is-off'
              : scan.network.blocked_attempts?.length
                ? 'is-alert'
                : 'is-ok'
          }`}
        >
          <span className="netstrip__dot" aria-hidden="true" />
          {!scan.network.enforced
            ? '出网守卫未启用——本次扫描未强制隔离网络'
            : scan.network.blocked_attempts?.length
              ? `已拦截 ${scan.network.blocked_attempts.length} 次外网连接：${scan.network.blocked_attempts[0]}`
              : '扫描全程零外部网络连接（出网守卫已启用）'}
        </div>
      )}

      <section className="grid grid--stats">
        <StatTile label="检出率" value={scan.detection_ratio || '—'} />
        <StatTile label="引擎总数" value={scan.engine_total ?? '—'} />
        <StatTile label="文件大小" value={formatBytes(scan.size)} />
        <StatTile
          label="扫描状态"
          value={<VerdictBadge verdict={scan.status === 'done' ? scan.verdict : scan.status} size="sm" />}
        />
      </section>

      <nav className="tabs">
        {TABS.map((t) => (
          <button
            key={t.key}
            className={`tabs__btn ${tab === t.key ? 'is-active' : ''}`}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <section className="panel panel--body">
        {tab === 'engines' && <EngineTable results={scan.engines} />}
        {tab === 'static' && <StaticPanel data={scan.static} />}
        {tab === 'dynamic' && <DynamicPanel data={scan.dynamic} />}
      </section>
    </div>
  )
}
