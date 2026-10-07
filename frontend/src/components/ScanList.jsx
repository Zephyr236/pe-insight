import VerdictBadge from './VerdictBadge'
import { formatTime, formatBytes } from '../format'

export default function ScanList({ scans, selectedId, onSelect }) {
  if (!scans.length) {
    return <p className="empty">还没有扫描记录。</p>
  }

  return (
    <ul className="list">
      {scans.map((s) => (
        <li key={s.id}>
          <button
            className={`list__item ${s.id === selectedId ? 'is-active' : ''}`}
            onClick={() => onSelect(s.id)}
          >
            <div className="list__top">
              <span className="list__name" title={s.filename}>
                {s.filename || '未命名'}
              </span>
              <VerdictBadge verdict={s.status === 'done' ? s.verdict : s.status} size="sm" />
            </div>
            <div className="list__meta">
              <span className="mono">
                {s.status === 'done' ? s.detection_ratio : '—'}
              </span>
              <span>{formatBytes(s.size)}</span>
              <span>{formatTime(s.created_at)}</span>
            </div>
          </button>
        </li>
      ))}
    </ul>
  )
}
