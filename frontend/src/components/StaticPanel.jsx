import { formatBytes, formatTime } from '../format'

function Row({ label, children }) {
  return (
    <div className="kv">
      <div className="kv__k">{label}</div>
      <div className="kv__v">{children}</div>
    </div>
  )
}

export default function StaticPanel({ data }) {
  if (!data) return <p className="empty">无静态分析结果。</p>

  if (!data.is_pe) {
    return (
      <div className="notice notice--muted">
        <strong>非 PE 文件</strong>
        <p>{data.reason || '无法解析为 Windows PE 格式。'}</p>
      </div>
    )
  }

  return (
    <div className="stack">
      {data.indicators?.length > 0 && (
        <div className="notice notice--warn">
          <strong>可疑特征</strong>
          <ul>
            {data.indicators.map((flag) => (
              <li key={flag}>{flag}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid grid--kv">
        <Row label="架构">{data.machine}</Row>
        <Row label="子系统">{data.subsystem}</Row>
        <Row label="类型">
          {data.is_dll ? 'DLL' : 'EXE'}
          {data.is_driver ? ' · 驱动' : ''}
        </Row>
        <Row label="编译时间">{formatTime(data.compile_timestamp)}</Row>
        <Row label="入口点">
          <span className="mono">{data.entry_point}</span>
        </Row>
        <Row label="镜像基址">
          <span className="mono">{data.image_base}</span>
        </Row>
        <Row label="Imphash">
          <span className="mono">{data.imphash || '—'}</span>
        </Row>
        <Row label="数字签名">
          {data.signature?.present ? (
            <span>存在（{formatBytes(data.signature.size)}）</span>
          ) : (
            <span className="muted">无</span>
          )}
        </Row>
      </div>

      <h3 className="h3">节区</h3>
      <table className="table">
        <thead>
          <tr>
            <th>名称</th>
            <th className="num">虚拟大小</th>
            <th className="num">原始大小</th>
            <th className="num">熵</th>
            <th>权限</th>
          </tr>
        </thead>
        <tbody>
          {data.sections?.map((s) => (
            <tr key={s.name + s.virtual_address}>
              <td className="mono">{s.name}</td>
              <td className="num mono">{s.virtual_size?.toLocaleString()}</td>
              <td className="num mono">{s.raw_size?.toLocaleString()}</td>
              <td className="num mono">
                {s.entropy}
                {s.high_entropy && <span className="tag tag--warn">高</span>}
              </td>
              <td>
                {s.writable_and_executable ? (
                  <span className="tag tag--crit">W+X</span>
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {data.imports?.length > 0 && (
        <>
          <h3 className="h3">导入表（{data.imports.length} 个 DLL）</h3>
          <div className="imports">
            {data.imports.map((imp) => (
              <details key={imp.dll} className="imports__item">
                <summary>
                  <span className="mono">{imp.dll}</span>
                  <span className="muted"> · {imp.functions.length} 个函数</span>
                </summary>
                <div className="mono imports__funcs">{imp.functions.join(', ')}</div>
              </details>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
