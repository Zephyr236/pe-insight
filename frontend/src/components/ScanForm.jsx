import { useRef, useState } from 'react'
import { scanLocalPath, uploadAndScan } from '../api'

export default function ScanForm({ onSubmitted, onError }) {
  const [path, setPath] = useState('')
  const [runDynamic, setRunDynamic] = useState(true)
  const [busy, setBusy] = useState(false)
  const fileRef = useRef(null)

  async function submitPath(e) {
    e.preventDefault()
    if (!path.trim()) return
    setBusy(true)
    try {
      const res = await scanLocalPath(path.trim(), runDynamic)
      onSubmitted(res.id)
      setPath('')
    } catch (err) {
      onError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function submitFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    setBusy(true)
    try {
      const res = await uploadAndScan(file, runDynamic)
      onSubmitted(res.id)
    } catch (err) {
      onError(err.message)
    } finally {
      setBusy(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  return (
    <div className="panel">
      <form onSubmit={submitPath} className="form">
        <label className="form__label" htmlFor="path">
          本机文件路径
        </label>
        <div className="form__row">
          <input
            id="path"
            className="input mono"
            placeholder="C:\samples\suspicious.exe"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            spellCheck={false}
          />
          <button className="btn btn--primary" type="submit" disabled={busy || !path.trim()}>
            {busy ? '提交中…' : '扫描'}
          </button>
        </div>
      </form>

      <div className="form__row form__row--split">
        <button
          className="btn btn--ghost"
          type="button"
          onClick={() => fileRef.current?.click()}
          disabled={busy}
        >
          或选择文件…
        </button>
        <input ref={fileRef} type="file" hidden onChange={submitFile} />
      </div>

      <label className="checkbox">
        <input
          type="checkbox"
          checked={runDynamic}
          onChange={(e) => setRunDynamic(e.target.checked)}
        />
        <span>
          启用模拟执行
          <span className="muted"> — 样本不会真正运行，但耗时增加 1~2 分钟</span>
        </span>
      </label>

      <p className="hint">
        文件只写入本机数据目录，不会上传到任何服务器。
      </p>
    </div>
  )
}
