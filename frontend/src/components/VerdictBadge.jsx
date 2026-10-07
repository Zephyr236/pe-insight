import { verdictOf } from '../verdict'

/**
 * 结论徽标。图标 + 文字 + 颜色三重编码——颜色从不单独表意，
 * 因此在色觉障碍或灰度打印下依然可读。
 */
export default function VerdictBadge({ verdict, size = 'md' }) {
  const v = verdictOf(verdict)
  return (
    <span
      className={`badge badge--${size}`}
      style={{ '--badge-color': `var(${v.cssVar})` }}
    >
      <span className="badge__icon" aria-hidden="true">
        {v.icon}
      </span>
      <span className="badge__label">{v.label}</span>
    </span>
  )
}
