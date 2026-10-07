import VerdictBadge from './VerdictBadge'
import { formatDuration } from '../format'

export default function EngineTable({ results }) {
  if (!results?.length) {
    return <p className="empty">没有引擎结果。</p>
  }

  return (
    <table className="table">
      <thead>
        <tr>
          <th>引擎</th>
          <th>结论</th>
          <th>检出名称</th>
          <th className="num">耗时</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r) => (
          <tr key={r.engine}>
            <td className="table__name">{r.engine}</td>
            <td>
              <VerdictBadge verdict={r.verdict} size="sm" />
              {r.error && <div className="table__note">{r.error}</div>}
            </td>
            <td className="mono">{r.signature || <span className="muted">—</span>}</td>
            <td className="num mono">{formatDuration(r.duration_ms)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
