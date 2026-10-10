# PE Insight 一键安装
#
#   .\setup.ps1                  安装全部（含约 2.5 GB 的分析引擎）
#   .\setup.ps1 -SkipTools       只装代码依赖，不下载分析引擎
#   .\setup.ps1 -BuildFrontend   从源码重建前端（需要 Node.js，改前端时才用）
#   .\setup.ps1 -Force           重新执行所有步骤，不跳过已完成项
#   .\setup.ps1 -Yes             全程不提问，一律按"是"处理（无人值守安装用）
#
# 这个脚本会依次完成：
#   1. 检查 Windows 与 Python 版本
#   2. 准备 uv（没有就自动装）
#   3. 装 Python 3.11 + 虚拟环境 + Python 依赖
#   4. 准备前端（用仓库自带的构建产物，**不需要 Node.js**）
#   5. 下载分析引擎（ClamAV / Emsisoft / DIE / Manalyze / CAPA）
#
# 前端产物（frontend/dist/）是随仓库提交的，所以使用者不需要 Node.js 工具链。
# 只有改了 frontend/src/ 的贡献者才需要 -BuildFrontend。
#
# 不需要管理员权限。防火墙和 Defender 排除项在 start.ps1 里按需处理。
#
# ⚠ 本文件必须保存为 UTF-8 带 BOM，否则 PowerShell 5.1 解析中文会报
#   "Missing closing '}'"。原因见 start.ps1 顶部注释。

param(
    [switch]$SkipTools,
    [switch]$BuildFrontend,
    [switch]$Force,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$backend = Join-Path $root 'backend'
$frontend = Join-Path $root 'frontend'
$python = Join-Path $backend '.venv\Scripts\python.exe'

$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function Say($msg, $color = 'Gray') { Write-Host $msg -ForegroundColor $color }
function Step($n, $total, $msg) { Write-Host ''; Write-Host "[$n/$total] $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "  ⚠ $msg" -ForegroundColor Yellow }
function Die($msg) {
    Write-Host ''
    Write-Host "✗ $msg" -ForegroundColor Red
    exit 1
}

Say ''
Say '===============================================' White
Say '  PE Insight —— 本地多引擎 PE 分析平台' White
Say '  安装程序' White
Say '===============================================' White

# ---------------------------------------------------------------- 1. 环境
Step 1 5 '检查运行环境'

if ($env:OS -ne 'Windows_NT') {
    Die '本项目只支持 Windows。它依赖 Defender 的 MpCmdRun、Get-MpPreference 和 Windows 防火墙。'
}
Say '  ✓ Windows'

# 找 uv —— 它是唯一被要求的额外工具
$uv = $null
foreach ($cand in @(
    (Get-Command uv -ErrorAction SilentlyContinue).Source,
    (Join-Path $env:USERPROFILE '.local\bin\uv.exe'),
    (Join-Path $env:USERPROFILE '.cargo\bin\uv.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\uv\uv.exe')
)) {
    if ($cand -and (Test-Path $cand)) { $uv = $cand; break }
}

if (-not $uv) {
    Warn '未找到 uv（Python 包与解释器管理器）'
    Say '  安装它只需一条命令，会从 astral.sh 官方源下载：'
    Say '    irm https://astral.sh/uv/install.ps1 | iex'
    Say ''
    # -Yes：无人值守模式，不提问直接按默认继续
    $ans = if ($Yes) { 'y' } else { Read-Host '  现在自动安装 uv？(y/N)' }
    if ($ans -notmatch '^[yY]') {
        Die '已取消。装好 uv 后重新运行本脚本。'
    }
    Say '  正在安装 uv ...'
    try {
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
    } catch {
        Die "uv 安装失败：$($_.Exception.Message)`n  请手动安装后重试：https://docs.astral.sh/uv/"
    }
    $uv = Join-Path $env:USERPROFILE '.local\bin\uv.exe'
    if (-not (Test-Path $uv)) {
        Die "uv 安装后仍未找到。请重开一个终端再运行本脚本。"
    }
}
Say "  ✓ uv  $uv"

# ---------------------------------------------------------------- 2. Python
Step 2 5 '准备 Python 3.11 与依赖'

Say '  安装/确认 Python 3.11 ...'
& $uv python install 3.11
if ($LASTEXITCODE -ne 0) { Die 'Python 3.11 安装失败' }

if (-not (Test-Path $python) -or $Force) {
    Say '  创建虚拟环境 ...'
    Push-Location $backend
    try {
        & $uv venv --python 3.11 .venv
        if ($LASTEXITCODE -ne 0) { Die '虚拟环境创建失败' }
    } finally { Pop-Location }
} else {
    Say '  虚拟环境已存在，跳过'
}

# 必须是 setuptools<81：speakeasy 依赖的 distorm3 需要 distutils，
# 而 setuptools 81+ 把它移除了。
Say '  安装 setuptools<81（speakeasy 的硬性要求）...'
& $uv pip install --python $python 'setuptools<81' wheel --quiet
if ($LASTEXITCODE -ne 0) { Die 'setuptools 安装失败' }

Say '  安装 Python 依赖（首次约 100 MB）...'
& $uv pip install --python $python -r (Join-Path $backend 'requirements.txt') --quiet
if ($LASTEXITCODE -ne 0) { Die '依赖安装失败' }
Say '  ✓ Python 环境就绪'

# ---------------------------------------------------------------- 3. 前端
Step 3 5 '准备前端'

# 前端产物随仓库提交（frontend/dist/），使用者不需要 Node.js。
# 构建产物不入库是常见做法，但代价是每个使用者都得装一整条前端工具链——
# 对一个"clone 下来就能用"的桌面工具来说不划算。产物只有 176 KB。
$distIndex = Join-Path $frontend 'dist\index.html'

if ($BuildFrontend) {
    $npm = (Get-Command npm -ErrorAction SilentlyContinue).Source
    if (-not $npm) {
        Warn '未找到 Node.js / npm，无法从源码构建前端。'
        Say '  装好 Node.js (https://nodejs.org) 后重试。'
        if (-not (Test-Path $distIndex)) { Die '也没有可用的现成产物，前端无法就绪。' }
        Say '  仓库自带的前端产物仍可用，本次继续。'
    } else {
        Push-Location $frontend
        try {
            Say '  npm install ...'
            & npm install --no-audit --no-fund
            if ($LASTEXITCODE -ne 0) { Die 'npm install 失败' }
            Say '  npm run build ...'
            & npm run build
            if ($LASTEXITCODE -ne 0) { Die '前端构建失败' }
        } finally { Pop-Location }
        Say '  ✓ 前端已从源码重建'
    }
} elseif (Test-Path $distIndex) {
    Say '  使用仓库自带的构建产物，无需 Node.js'
} else {
    Warn '没有前端构建产物，Web UI 打不开（CLI 和 HTTP API 不受影响）。'
    Say '  装 Node.js 后加 -BuildFrontend 重建，或重新 clone 一份。'
}

# ---------------------------------------------------------------- 4. 引擎
Step 4 5 '下载分析引擎'

if ($SkipTools) {
    Warn '已跳过分析引擎下载（-SkipTools）。'
    Say '  之后可以随时补上：'
    Say '    cd backend'
    Say '    .\.venv\Scripts\python.exe -m app.cli setup-clamav'
    Say '    .\.venv\Scripts\python.exe -m app.cli setup-emsisoft'
    Say '    .\.venv\Scripts\python.exe -m app.cli setup-tools'
    Say '    .\.venv\Scripts\python.exe -m app.cli setup-yara'
} else {
    Say ''
    Say '  接下来会下载约 2.5 GB 的内容（全部来自各厂商官方源）：' White
    Say '    ClamAV 便携版 + 签名库     约 1.3 GB'
    Say '    Emsisoft Emergency Kit     约 0.7 GB'
    Say '    DIE / Manalyze / CAPA 规则 约 0.1 GB'
    Say '    YARA 规则集(signature-base) 约 9 MB'
    Say ''
    Say '  这一步最耗时（视网速 10~30 分钟），且**需要联网**。'
    Say '  下载的是各引擎本体和签名库，**不涉及任何样本上传**。'
    Say ''

    # -Yes：无人值守模式，不提问直接开始下载
    $ans = if ($Yes) { 'y' } else { Read-Host '  现在开始下载？(Y/n)' }
    if ($ans -match '^[nN]') {
        Warn '已跳过。之后按上面的命令可以随时补上。'
    } else {
        $steps = @(
            @{ name = 'ClamAV';    args = @('-m', 'app.cli', 'setup-clamav') },
            @{ name = 'Emsisoft';  args = @('-m', 'app.cli', 'setup-emsisoft') },
            @{ name = 'DIE/Manalyze/CAPA'; args = @('-m', 'app.cli', 'setup-tools') },
            @{ name = 'YARA 规则集'; args = @('-m', 'app.cli', 'setup-yara') }
        )
        foreach ($s in $steps) {
            Write-Host ''
            Write-Host "  ── 安装 $($s.name) ──" -ForegroundColor DarkCyan
            Push-Location $backend
            try {
                & $python @($s.args)
                if ($LASTEXITCODE -ne 0) {
                    Warn "$($s.name) 安装未完全成功，可稍后单独重试。"
                }
            } finally { Pop-Location }
        }
    }
}

# ---------------------------------------------------------------- 5. 收尾
Step 5 5 '完成'

Say ''
Say '  已安装的组件：' White
Push-Location $backend
try {
    # ⚠ 这里刻意**不用** `2>&1`。
    # PowerShell 5.1 会把原生命令 stderr 的每一行包成 NativeCommandError
    # 记录，而本脚本开头设了 $ErrorActionPreference = 'Stop'——那会让它直接
    # 升级为终止错误，把安装程序的最后一步炸掉。
    # （实测：unicorn 的一条 pkg_resources 弃用告警就足以触发。）
    # 那条告警已在 app/__init__.py 里滤掉，所以也不需要再过滤输出。
    # 保险起见仍然临时放宽 ErrorActionPreference，防止别的工具写 stderr。
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $python -m app.cli engines
    } finally { $ErrorActionPreference = $eap }
} finally { Pop-Location }

Say ''
Say '===============================================' Green
Say '  安装完成' Green
Say '===============================================' Green
Say ''
Say '  下一步：' White
Say '    双击 start.bat  或  在 PowerShell 里执行 .\start.ps1' White
Say ''
Say '  启动会请求管理员权限（Emsisoft 引擎要求），点"是"即可。' Gray
Say '  它会自动配置防火墙、拉起服务、打开浏览器。' Gray
Say ''
Say '  分析真实恶意样本前还需要一步（把样本目录排除出 Defender 实时防护），' Gray
Say '  见 README 的「分析真实样本：必须先做这一步」。' Gray
Say ''
