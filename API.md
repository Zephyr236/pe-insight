# PE Insight API

局域网内多引擎样本查杀服务的 HTTP 接口。

内网其他机器可以通过这套接口提交样本、拿回**每个引擎各自的查杀结果**，
样本全程只存在分析机上，不上传任何云端。

---

## 快速开始

### 在分析机上启动服务

```powershell
cd C:\Users\user\Desktop\pe-insight\backend

# 设置共享密钥（重要，见下方「安全」）
$env:PEINSIGHT_API_KEY = "换成你自己的随机密钥"

# 监听所有网卡，让内网其他机器能连
.\.venv\Scripts\python.exe -m app.cli serve --host 0.0.0.0 --port 8080
```

启动后会打印局域网访问地址，例如：

```
PE Insight 启动中 → http://0.0.0.0:8080
局域网访问地址： http://192.168.1.173:8080
鉴权：已启用（请求需带 X-API-Key 头）
```

### 放行防火墙

首次在局域网访问需要在分析机上放行端口（**管理员** PowerShell）：

```powershell
New-NetFirewallRule -DisplayName "PE Insight API" -Direction Inbound `
  -Protocol TCP -LocalPort 8080 -Action Allow -Profile Private
```

> 用 `-Profile Private` 而不是 `Any`：只在专用网络（家庭/办公内网）放行，
> 插到公共 Wi-Fi 时不会自动暴露。

### 从其他机器调用

```bash
curl -H "X-API-Key: 你的密钥" http://192.168.1.173:8080/api/health
```

---

## 鉴权：默认**关闭**

**开箱即用不需要任何密钥。** 本地单机、可信内网直接用就行，Web UI 也能正常
工作（它不带任何鉴权头，后端默认也不校验）。

只有把服务暴露到**不完全可信**的网段时才建议打开：

```powershell
$env:PEINSIGHT_API_KEY = "你的随机密钥"
```

打开后：

- 除 `/api/health` 外**所有** `/api/*` 接口都要求 `X-API-Key` 头
- **Web UI 也要同步设置**——顶栏点 `🔑 密钥`，填入同一个值即可（存在浏览器
  localStorage，只在本机生效）。没设的话界面会明确提示「缺少或错误的 X-API-Key」
- `/api/health` 始终免鉴权，方便探活

生成随机密钥：

```powershell
# PowerShell
-join ((48..57)+(65..90)+(97..122) | Get-Random -Count 40 | ForEach-Object {[char]$_})
```

```bash
# Linux / macOS
openssl rand -hex 24
```

### 为什么建议在开放网段时打开

这个接口接收**任意文件上传**，把文件送进 7 个引擎（含模拟执行），并把样本
**落盘保存**。在内网上不设防，等于给整个网段开了一个投毒入口——任何人都能
往里塞文件、占满 CPU、往磁盘写数据。

### 其他注意事项

| 风险 | 说明 |
|---|---|
| **样本落盘** | 上传的样本会存进分析机的 `data/samples/`。该目录已被加入 Defender 排除列表（不受实时防护保护）。定期用 `python -m app.cli purge-samples --yes` 清理 |
| **没有 TLS** | 明文 HTTP。内网可信网段可用；跨不可信网络请套反向代理（nginx/caddy）加 HTTPS |
| **无速率限制** | 没有内置限流。一次全引擎扫描在这台机器上要几十秒到几分钟，建议在调用侧排队，别并发灌 |
| **单一共享密钥** | 所有人共用一个 key，没有用户区分和审计。够用即可，需要更细粒度请接入反向代理的鉴权 |

---

## 鉴权

除健康检查外，所有请求都要带：

```
X-API-Key: <PEINSIGHT_API_KEY 的值>
```

缺失或错误返回：

```json
HTTP 401
{ "detail": "缺少或错误的 X-API-Key" }
```

`/api/health` 刻意免鉴权，方便探活：

```json
{
  "ok": true,
  "network_policy": "no-sample",
  "enforce_offline": true,
  "auth_required": true
}
```

---

## 扫描是异步的

一次全引擎扫描在这台机器上要 **几十秒到 4 分钟**（CAPA 和 Emsisoft 单次就要
20~110 秒）。所以接口设计成**提交 + 轮询**，而不是阻塞等待。

```
POST 提交 → 立即返回 {id, status:"pending"}
     ↓
GET /api/scans/{id} 轮询 → status 变 done 或 failed
     ↓
响应里带着每个引擎的结果
```

`status` 取值：`pending` → `running` → `done` / `failed`

---

## 接口一览

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/health` | 健康检查（免鉴权） |
| `GET` | `/api/engines` | 引擎清单及各自状态 |
| `GET` | `/api/privacy` | 外传通道审计 |
| `POST` | `/api/scans/upload` | **上传文件**并提交扫描 |
| `POST` | `/api/scans/local` | 提交**分析机本地路径**扫描 |
| `GET` | `/api/scans` | 扫描记录列表 |
| `GET` | `/api/scans/{id}` | 单次扫描的完整报告 |
| `DELETE` | `/api/scans/{id}` | 删除扫描记录 |

---

## `POST /api/scans/upload`

上传文件并提交扫描。**这是内网其他机器最常用的接口。**

**请求**（`multipart/form-data`）

| 参数 | 位置 | 类型 | 默认 | 说明 |
|---|---|---|---|---|
| `file` | form | file | 必填 | 要分析的样本 |
| `run_dynamic` | query | bool | `true` | 是否跑 Speakeasy 模拟执行 |

**响应** `200`

```json
{ "id": "c8fcdd26-5ad7-460e-be85-0ced5be1dd05", "status": "pending" }
```

**示例**

```bash
curl -H "X-API-Key: $KEY" \
     -F "file=@suspicious.exe" \
     "http://192.168.1.173:8080/api/scans/upload?run_dynamic=false"
```

```python
import requests, time

BASE = "http://192.168.1.173:8080"
HEAD = {"X-API-Key": "你的密钥"}

with open("suspicious.exe", "rb") as f:
    r = requests.post(f"{BASE}/api/scans/upload",
                      headers=HEAD,
                      files={"file": f},
                      params={"run_dynamic": "false"},
                      timeout=300)
scan_id = r.json()["id"]

# 轮询
while True:
    s = requests.get(f"{BASE}/api/scans/{scan_id}", headers=HEAD, timeout=60).json()
    if s["status"] in ("done", "failed"):
        break
    time.sleep(3)

print(s["verdict"], s["detection_ratio"])
for e in s["engines"]:
    print(f"  {e['engine']:<20} {e['verdict']:<12} {e['signature'] or ''}")
```

```powershell
$KEY = "你的密钥"
$r = Invoke-RestMethod -Uri "http://192.168.1.173:8080/api/scans/upload?run_dynamic=false" `
        -Method Post -Headers @{ "X-API-Key" = $KEY } -Form @{ file = Get-Item "C:\path\sample.exe" }
$r.id
```

---

## `GET /api/scans/{id}`

取回完整报告。轮询时反复调用这个接口直到 `status` 变成 `done`。

**响应**（节选）

```json
{
  "id": "c8fcdd26-...",
  "filename": "cmd.exe",
  "sha256": "8a6f...",
  "md5": "5f2b...",
  "size": 289792,
  "status": "done",
  "verdict": "suspicious",
  "detection_ratio": "2/7",
  "detections": 2,
  "engine_total": 7,

  "engines": [
    { "engine": "Windows Defender", "verdict": "clean",      "signature": null,              "duration_ms": 824,    "error": null },
    { "engine": "ClamAV",           "verdict": "clean",      "signature": null,              "duration_ms": 1283,   "error": null },
    { "engine": "Emsisoft",         "verdict": "clean",      "signature": null,              "duration_ms": 18996,  "error": null },
    { "engine": "YARA",             "verdict": "suspicious", "signature": "anti_analysis",   "duration_ms": 7,      "error": null },
    { "engine": "DIE",              "verdict": "clean",      "signature": "Linker: ...",     "duration_ms": 4651,   "error": null },
    { "engine": "Manalyze",         "verdict": "clean",      "signature": null,              "duration_ms": 996,    "error": null },
    { "engine": "CAPA",             "verdict": "suspicious", "signature": "create process...", "duration_ms": 110661, "error": null }
  ],

  "static":  { "is_pe": true, "machine": "IMAGE_FILE_MACHINE_AMD64", "sections": [ ... ], "imports": [ ... ] },
  "dynamic": { "success": true, "total_api_calls": 64, "attack_techniques": [ ... ], "iocs": { ... } },
  "network": { "enforced": true, "blocked_attempts": [] }
}
```

### `verdict` 取值

| 值 | 含义 |
|---|---|
| `malicious` | 至少一个引擎报恶意 |
| `suspicious` | 没有报恶意，但有引擎报可疑 |
| `clean` | 所有可用引擎都判干净 |
| `unknown` | 所有引擎都出错，没有有效结论 |

### 引擎 `verdict` 取值

| 值 | 含义 |
|---|---|
| `malicious` | 检出 |
| `suspicious` | 可疑（加壳、可疑能力、规则命中但未定性） |
| `pup` | 潜在不受欢迎程序 |
| `clean` | 未检出 |
| `unknown` | 无法判定 |
| `error` | 引擎执行出错（见 `error` 字段） |
| `skipped` | 引擎不可用或被安全策略排除（见 `error` 字段） |

> **注意 `skipped`**：Windows Defender 云保护开启时会被安全策略排除，
> 此时它出现在 `engines` 里但 `verdict` 是 `skipped`，且**不计入**
> `engine_total`。所以 `detection_ratio` 的分母可能小于引擎总数。

---

## `GET /api/engines`

引擎清单，用于确认分析机上哪些引擎真正生效。

```json
[
  {
    "name": "ClamAV",
    "kind": "signature",
    "network_level": "local",
    "network_level_text": "完全本地",
    "offline": true,
    "network_note": "",
    "available": true,
    "reason": null,
    "active": true,
    "excluded_reason": null
  }
]
```

| 字段 | 说明 |
|---|---|
| `available` | 分析机上装没装这个引擎 |
| `active` | **本次扫描会不会用它**。`false` 表示被网络策略排除 |
| `excluded_reason` | 被排除的具体原因 |
| `network_level` | `local` / `metadata` / `sample`，见下方 |

---

## `GET /api/privacy`

审计样本外传通道——回答「样本会不会被传出去」。

```json
{
  "defender": {
    "available": true,
    "maps_text": "高级（会提交可疑文件）",
    "submit_text": "从不发送（推荐用于离线分析）",
    "cloud_enabled": true,
    "sends_samples": false,
    "network_level": "metadata",
    "warning": "Defender 云保护已开启，但样本提交策略为「从不发送」。..."
  },
  "network_guard": { "enforced": true, "description": "扫描期间强制拦截一切外部网络连接" },
  "inbox_dir": "C:\\Users\\user\\Desktop\\pe-insight\\data\\inbox"
}
```

---

## `GET /api/scans`

记录列表，最新的在前。

```bash
curl -H "X-API-Key: $KEY" "http://192.168.1.173:8080/api/scans?limit=20"
```

返回摘要数组（不含各层详细报告），字段与详情接口的顶层一致。

---

## 错误码

| 状态码 | 含义 |
|---|---|
| `200` | 成功 |
| `401` | API Key 缺失或错误 |
| `404` | 扫描记录不存在，或 `/api/scans/local` 指定的文件不存在 |
| `413` | 文件超过 `PEINSIGHT_MAX_UPLOAD_MB`（默认 512 MB） |
| `422` | 请求参数格式错误 |

---

## 配置项

通过环境变量设置，重启服务生效。

| 变量 | 默认 | 说明 |
|---|---|---|
| `PEINSIGHT_API_KEY` | 空 | 共享密钥。**留空 = 不鉴权（默认）** |
| `PEINSIGHT_ALLOW_LAN_CORS` | `0` | 设为 `1` 时允许任意来源跨域（浏览器端从别的机器调用时需要） |
| `PEINSIGHT_NETWORK_POLICY` | `no-sample` | `local` / `no-sample` / `any`，见下 |
| `PEINSIGHT_DISABLED_ENGINES` | 空 | 逗号分隔的引擎名，如 `capa,emsisoft` |
| `PEINSIGHT_ENGINE_WORKERS` | `4` | 并发跑几个轻量引擎 |
| `PEINSIGHT_MAX_UPLOAD_MB` | `512` | 上传大小上限 |
| `PEINSIGHT_AUTO_UPDATE` | `1` | 服务启动后是否在后台更新签名库。设 `0` 关闭 |

### 网络策略

决定允许哪些外传等级的引擎参与扫描：

| 策略 | 允许的等级 | 说明 |
|---|---|---|
| `local` | 仅完全本地 | 最严，零外传 |
| **`no-sample`** | 本地 + 仅元数据 | **默认**。样本内容不外传 |
| `any` | 全部 | 允许会传样本的引擎 |

### 在弱机器上提速

这台分析机是 1 核。CAPA 单次要 110 秒、Emsisoft 19 秒，是全流程的主要耗时。
如果调用方只关心签名引擎的结论：

```powershell
$env:PEINSIGHT_DISABLED_ENGINES = "capa"    # 省掉最慢的那个
```

---

## 常见问题

**Q：从别的机器连不上？**

按顺序排查：

1. 分析机上 `netstat -ano | findstr :8080` 确认监听在 `0.0.0.0` 而不是 `127.0.0.1`
2. 防火墙有没有放行（见上面的 `New-NetFirewallRule`）
3. 两台机器在不在同一网段（`ping 192.168.1.173`）
4. 密钥对不对

**Q：为什么 `detection_ratio` 的分母小于引擎总数？**

`engine_total` 只统计**有效**引擎（排除 `skipped` 和 `error`）。Defender 因云保护
被策略排除时就不计入分母。看 `/api/engines` 的 `active` 字段知道哪些真正参与了。

**Q：扫描要多久？**

这台机器上：只跑签名引擎约 20 秒；CAPA 和 Emsisoft 都开的话约 2 分钟；
再加模拟执行约 4 分钟。调用侧记得给足超时。

**Q：样本会被传到云端吗？**

默认不会传样本内容。用 `GET /api/privacy` 可以直接查证。唯一的例外是
Windows Defender 的云保护会上传**元数据**（哈希等）——关掉它用
`Set-MpPreference -MAPSReporting Disabled`，或把 Defender 排在引擎之外。
