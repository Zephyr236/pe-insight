/**
 * 结论 → 展示语义。
 *
 * 状态色板是固定的四个语义色（good / warning / serious / critical），
 * 且每个结论都必须同时带图标和文字——颜色永远不单独承载含义。
 * 色值取自设计规范的 status palette，两种主题下都不变。
 */
export const VERDICT = {
  malicious: { label: '恶意', icon: '⛔', cssVar: '--status-critical' },
  suspicious: { label: '可疑', icon: '⚠', cssVar: '--status-serious' },
  pup: { label: 'PUP', icon: '⚠', cssVar: '--status-warning' },
  clean: { label: '干净', icon: '✓', cssVar: '--status-good' },
  unknown: { label: '未知', icon: '?', cssVar: '--text-muted' },
  error: { label: '错误', icon: '!', cssVar: '--text-muted' },
  skipped: { label: '跳过', icon: '–', cssVar: '--text-muted' },
  running: { label: '扫描中', icon: '◌', cssVar: '--text-muted' },
  pending: { label: '排队中', icon: '◌', cssVar: '--text-muted' },
  failed: { label: '失败', icon: '!', cssVar: '--status-critical' },
}

export function verdictOf(key) {
  return VERDICT[key] || VERDICT.unknown
}
