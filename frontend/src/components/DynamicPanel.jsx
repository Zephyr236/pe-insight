function IocList({ title, values }) {
  if (!values?.length) return null
  return (
    <div className="ioc">
      <div className="ioc__title">
        {title} <span className="muted">({values.length})</span>
      </div>
      <ul className="ioc__list mono">
        {values.slice(0, 20).map((v) => (
          <li key={v}>{v}</li>
        ))}
      </ul>
    </div>
  )
}

export default function DynamicPanel({ data }) {
  if (!data) return <p className="empty">未启用动态分析。</p>

  if (!data.success) {
    return (
      <div className="notice notice--muted">
        <strong>模拟执行未产出结果</strong>
        <p>{data.error || '未知原因。'}</p>
        <p className="muted">
          模拟执行对加壳、反模拟、依赖外部 DLL 的样本经常失败——这不代表样本安全。
        </p>
      </div>
    )
  }

  const techniques = data.attack_techniques || []
  const iocs = data.iocs || {}
  const hasIocs = Object.values(iocs).some((v) => v?.length)
  const emu = data.emulation || {}

  return (
    <div className="stack">
      <div className="notice notice--info">
        样本在 Unicorn 模拟环境中执行，<strong>未作为真实进程运行</strong>。
      </div>

      {/* 模拟没跑到程序逻辑时必须显式告知，否则"无行为"会被误读成"安全" */}
      {emu.bootstrap_only ? (
        <div className="notice notice--warn">
          <strong>模拟未进入程序自身逻辑</strong>
          <p>
            只走完了 CRT 启动阶段（{data.total_api_calls} 次调用），
            <strong>没有观测到任何程序行为</strong>。常见原因是样本使用了
            自实现的字节码虚拟机或加壳保护——模拟器只能观测系统调用，
            而这类样本的工作全在它自己的解释器内部完成。
          </p>
          <p className="muted">
            这不代表样本安全，只代表本次模拟对它无效。
          </p>
        </div>
      ) : (
        emu.truncated && (
          <div className="notice notice--warn">
            <strong>模拟提前中止</strong>
            <p>
              原因：{emu.stop_reasons?.join('、') || '未知'}。样本是在第{' '}
              {data.total_api_calls} 次 API 调用处停下的，<strong>未覆盖完整逻辑</strong>——
              此处的"无恶意行为"不构成安全结论。
            </p>
          </div>
        )
      )}

      <div className="grid grid--stats">
        <div className="mini">
          <div className="mini__v">{data.total_api_calls?.toLocaleString()}</div>
          <div className="mini__l">API 调用次数</div>
        </div>
        <div className="mini">
          <div className="mini__v">{data.unique_apis?.toLocaleString()}</div>
          <div className="mini__l">不同 API 数</div>
        </div>
        <div className="mini">
          <div className="mini__v">{techniques.length}</div>
          <div className="mini__l">ATT&amp;CK 技术</div>
        </div>
      </div>

      {techniques.length > 0 && (
        <>
          <h3 className="h3">MITRE ATT&amp;CK 映射</h3>
          <table className="table">
            <thead>
              <tr>
                <th>技术编号</th>
                <th>技术名称</th>
                <th>相关 API</th>
                <th className="num">调用次数</th>
              </tr>
            </thead>
            <tbody>
              {techniques.map((t) => (
                <tr key={t.id}>
                  <td className="mono">{t.id}</td>
                  <td>{t.name}</td>
                  <td className="mono muted">{t.apis.slice(0, 3).join(', ')}</td>
                  <td className="num mono">{t.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {hasIocs && (
        <>
          <h3 className="h3">运行期提取的 IOC</h3>
          <div className="grid grid--iocs">
            <IocList title="URL" values={iocs.urls} />
            <IocList title="域名" values={iocs.domains} />
            <IocList title="IP" values={iocs.ips} />
            <IocList title="注册表" values={iocs.registry_keys} />
            <IocList title="文件路径" values={iocs.file_paths} />
          </div>
        </>
      )}

      {data.top_apis?.length > 0 && (
        <>
          <h3 className="h3">高频 API</h3>
          <div className="chips">
            {data.top_apis.slice(0, 24).map(([api, count]) => (
              <span className="chip mono" key={api}>
                {api}
                <span className="chip__n">{count}</span>
              </span>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
