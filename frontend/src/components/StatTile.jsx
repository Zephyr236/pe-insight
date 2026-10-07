/**
 * 统计块：label（句式大小写、无尾冒号）+ value。
 * 数值用比例数字而非等宽数字——大字号下等宽会让数字显得松散。
 */
export default function StatTile({ label, value, hint, tone }) {
  return (
    <div className="stat">
      <div className="stat__label">{label}</div>
      <div className="stat__value" style={tone ? { color: `var(${tone})` } : undefined}>
        {value}
      </div>
      {hint && <div className="stat__hint">{hint}</div>}
    </div>
  )
}
