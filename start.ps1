# PE Insight 一键启动（需要管理员权限）
#
#   .\start.ps1                    启动（本机 + 内网），并打开浏览器
#   .\start.ps1 -Port 9000         指定端口
#   .\start.ps1 -LocalOnly         只监听本机，不对内网开放
#   .\start.ps1 -NoBrowser         不自动开浏览器
#   .\start.ps1 -SkipFirewall      不自动配置防火墙规则
#
# ⚠ 本文件必须保存为 **UTF-8 带 BOM**。
#   PowerShell 5.1 读取没有 BOM 的 .ps1 时会按系统 ANSI 代码页解析，
#   中文字符被拆成乱码字节，其中某些字节会被当成 { } 或引号，
#   导致报 "Missing closing '}'" 这种看起来毫无道理的解析错误。
#
# 为什么要管理员：
#   1. Emsisoft 的 a2cmd.exe 拒绝在非提升会话下扫描，会直接报"需要更高权限"
#   2. 对内网开放需要配置防火墙入站规则
#   3. Defender 的 MpCmdRun 在提升会话下行为更稳定

param(
    [int]$Port = 8080,
    [switch]$NoBrowser,
    [switch]$LocalOnly,
    [switch]$SkipFirewall,
    # 供内部提权重入时使用，不要手动传
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$backend = Join-Path $root 'backend'
$python = Join-Path $backend '.venv\Scripts\python.exe'

# ---------------------------------------------------------------- 提权
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host '需要管理员权限（Emsisoft 引擎要求），正在请求提权...' -ForegroundColor Yellow
    Write-Host '请在 UAC 弹窗中点"是"。' -ForegroundColor Yellow

    $argList = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-Port', "$Port", '-Elevated'
    )
    if ($NoBrowser) { $argList += '-NoBrowser' }
    if ($LocalOnly) { $argList += '-LocalOnly' }
    if ($SkipFirewall) { $argList += '-SkipFirewall' }

    try {
        Start-Process -FilePath 'powershell' -Verb RunAs -ArgumentList $argList | Out-Null
    } catch {
        Write-Host ''
        Write-Host '提权被拒绝或失败。请手动右键 PowerShell -> 以管理员身份运行，然后执行：' -ForegroundColor Red
        Write-Host "  cd `"$root`""
        Write-Host '  .\start.ps1'
        exit 1
    }
    # 提权后的实例会接管一切，本实例退出
    exit 0
}

# 让中文日志不乱码：Python 默认按系统代码页（中文 Windows 上是 GBK）写 stdout，
# 而控制台按 UTF-8 解，两边对不上就成了乱码。统一成 UTF-8。
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
try { $Host.UI.RawUI.WindowTitle = 'PE Insight 服务' } catch { }

if (-not (Test-Path $python)) {
    Write-Host '未找到虚拟环境。请先准备环境：' -ForegroundColor Yellow
    Write-Host '  cd backend'
    Write-Host '  uv venv --python 3.11 .venv'
    Write-Host '  uv pip install --python .venv\Scripts\python.exe -r requirements.txt'
    Write-Host '  uv pip install --python .venv\Scripts\python.exe flare-capa'
    exit 1
}

$host_ = if ($LocalOnly) { '127.0.0.1' } else { '0.0.0.0' }

# ------------------------------------------------- 防火墙（仅对内网开放时）
$lanIp = $null
if (-not $LocalOnly) {
    # 只认物理网卡：装了代理/VPN 的机器会有 TUN 虚拟网卡，
    # 拿那个地址报给用户的话别的机器根本连不上。
    try {
        $lanIp = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'Up' } |
            ForEach-Object {
                Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            } |
            Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
            Select-Object -First 1 -ExpandProperty IPAddress
    } catch { }

    if (-not $SkipFirewall) {
        $ruleName = "PE Insight API ($Port)"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            try {
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound `
                    -Protocol TCP -LocalPort $Port -Action Allow -Profile Private `
                    -Description 'PE Insight 多引擎样本分析 API（仅限专用网络）' | Out-Null
                Write-Host "已放行防火墙端口 $Port（仅专用网络）" -ForegroundColor Green
            } catch {
                Write-Host "防火墙规则创建失败：$($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "  内网可能连不上，可手动执行：" -ForegroundColor Yellow
                Write-Host "  New-NetFirewallRule -DisplayName `"$ruleName`" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Private"
            }
        } else {
            Write-Host "防火墙端口 $Port 已放行" -ForegroundColor DarkGray
        }
    }
}

$tip = if ($LocalOnly) { '本机' } else { '本机 + 内网' }
Write-Host "启动 PE Insight（$tip，端口 $Port）..." -ForegroundColor Cyan

# 清掉可能残留的旧实例，避免端口占用
Get-Process python -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "*pe-insight*" } |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 500

$proc = Start-Process -FilePath $python `
    -ArgumentList '-m', 'app.cli', 'serve', '--host', $host_, '--port', "$Port" `
    -WorkingDirectory $backend -PassThru -NoNewWindow

# 等真正就绪再开浏览器，否则用户看到的是"无法连接"
$ready = $false
foreach ($i in 1..60) {
    Start-Sleep -Milliseconds 500
    if ($proc.HasExited) { break }
    try {
        Invoke-RestMethod "http://127.0.0.1:$Port/api/health" -TimeoutSec 2 | Out-Null
        $ready = $true
        break
    } catch { }
}

if (-not $ready) {
    Write-Host '服务启动失败，请检查上面的输出。' -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host '已就绪' -ForegroundColor Green
Write-Host "  本机   http://127.0.0.1:$Port"
if (-not $LocalOnly -and $lanIp) {
    Write-Host "  内网   http://${lanIp}:$Port"
}
Write-Host ''
Write-Host '按 Ctrl+C 停止服务。'

if (-not $NoBrowser) {
    Start-Process "http://127.0.0.1:$Port"
}

Wait-Process -Id $proc.Id
