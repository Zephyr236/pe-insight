# 更新日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 修复：全新机器上安装程序全线失败

在一台干净的 Windows 上实测安装，发现两个必现问题：

- **所有下载报 `CERTIFICATE_VERIFY_FAILED`**。各 `setup_*` 模块直接调
  `urllib.request.urlopen()`，走 Python 默认 SSL 上下文，而 `uv` 装的
  Python 在该机器上拿不到可用的根证书链（实测默认上下文只有 23 个根证书，
  而 certifi 有 135 个）。同一个环境里 pip 是好的，因为 pip 自带 certifi。
  现在统一走 `app/download.py`：把 certifi 的根证书合并进默认上下文，
  并留出 `PEINSIGHT_CA_BUNDLE`（指定自有根证书）和
  `PEINSIGHT_INSECURE_DOWNLOAD=1`（跳过校验）两个逃生口给 TLS 拦截环境。
  证书错误现在会打印可操作的排查步骤，而不是一句 urlopen error。
- **`setup.ps1` 最后一步崩溃**。第 203 行对原生命令用了 `2>&1 | Where-Object`，
  而脚本开头设了 `$ErrorActionPreference = 'Stop'`——PowerShell 5.1 会把
  stderr 包成 `NativeCommandError` 并升级为终止错误，unicorn 的一条
  `pkg_resources` 弃用告警就足以触发。已去掉该管道并临时放宽
  ErrorActionPreference；那条告警本身在 `app/__init__.py` 里精确滤掉了。

`certifi` 因此成为显式依赖（此前只是传递依赖）。

### 变更：YARA 规则改为消费第三方规则集

不再自带手写规则，改用 [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
（5200+ 条）。原因：手写的"API 存在性"判据在系统文件上误报率过高——
19 条规则里有 8 条命中 124 个系统文件中的 8 个（6.5%），`aitstatic.exe`
和 `certutil.exe` 被判成勒索软件。换成 signature-base 后同一批文件
**误报 0**。

- 规则集下载到 `tools/yara-rules/`，`setup-yara` 安装、`update yara` 更新
- `rules/` 保留给使用者自己写的规则
- **逐文件下载而不是下 zip**：整包会被 Windows Defender 检出并锁死
  （`ThreatID 2147965225`，读取报 `OSError Errno 22`），单个 `.yar` 则不会
- YARA 引擎改为**容错加载**：747 个规则文件里有 13 个用到了本机 yara
  构建未编入的模块或需要外部变量，而 `yara.compile(filepaths=...)` 是
  原子的，一个坏文件会让整个规则库失效。现在退化为逐文件编译、剔除坏的、
  如实报告跳过了哪些
- 判定等级由规则名前缀 + `meta.score` 推导（signature-base 不带
  `meta.verdict`）。命中按严重度排序，`signature` 取最重的一条

### 移除：demo 功能

`demo` 命令、`app/demo.py`、以及依赖它的 `scripts/prep_doc_shots.py`
一并删除。合成样本的价值是"让检出链路肉眼可见"，但它的载荷必须绑定
具体规则，规则一换（手写 → signature-base）这批样本就整体失效——维护
成本大于收益。要看检出效果用 `selftest`（EICAR）或真实样本。

README 截图对应的合成样本说明已同步改写，截图文件本身保留。

### 测试

- 新增 `backend/tests/`：真阳性（用规则自身的字符串构造样本）、
  真阴性（180 个系统文件）、加载器容错、判定映射
- 真阳性这组不能省：没有它，"零误报"可以靠一条规则都不加载来满足
- 误报测试的取样口径与 `tools/diag_fp.py` 对齐（此前测试只取前 40 个，
  比诊断脚本窄，会漏报误报）

## [0.1.0] - 2026-10-07

首个可用版本。

### 三层检测

- **静态分析**：PE 结构解析、节区熵、导入表、加壳启发式、数字签名
- **多引擎签名查杀**：Windows Defender、ClamAV、Emsisoft、YARA
- **结构 / 能力分析**：DIE（加壳识别）、Manalyze（PE 结构）、CAPA（能力 + ATT&CK）
- **模拟执行**：Speakeasy，样本从不真正运行

### 隐私与隔离

- **出网守卫**（`netguard`）：扫描期间在 socket 层强制拦截一切外部连接，
  只放行回环地址。违规记录写进扫描报告，UI 上显示为"扫描全程零外部网络连接"
- **网络策略分级**：`local` / `no-sample` / `any` 三档，决定允许哪些外传等级的
  引擎参与扫描。默认 `no-sample`
- **隐私审计**（`privacy` 命令 + `/api/privacy`）：如实报告 Defender 云保护
  等本产品无法拦截的外传通道
- 各引擎的外传行为按实测声明，不做无法兑现的承诺

### 接口

- Web UI（React + Vite）
- HTTP API，可供内网其他机器调用，见 [API.md](API.md)
- 命令行：`scan` / `serve` / `engines` / `selftest` / `demo` / `privacy` /
  `verify-offline` / `update` / `setup-*` / `purge-samples` / `clamd`

### 资源调度

- 两档调度：轻量引擎并发、重量引擎串行，避免弱机器被内存压力拖垮
- 分级依据是实测内存占用而非耗时（见 `CONTRIBUTING.md`）
- ClamAV 的档位**动态判定**：有 `clamd` 常驻时是轻量（约 1.6 秒），
  没有时 `clamscan` 要加载 1.1 GB 签名库（约 26 秒），必须串行

### 签名库更新

- `update` 命令：手动更新签名库与规则集，支持 `--check` 只查看新鲜度
- 服务启动后 45 秒在后台自动更新，**只更新超过 24 小时的**（避免重启十次
  下载十次上百 MB）

### 安装

- `setup.ps1` / `setup.bat` 一键安装
- `start.ps1` / `start.bat` 一键启动，自动提权、自动配置防火墙

### 已知限制

- **仅支持 Windows**：依赖 Defender 的 `MpCmdRun`、`Get-MpPreference`
  和 Windows 防火墙
- **模拟执行的覆盖率有限**：加壳、反模拟样本经常跑几步就停；
  自实现虚拟机的样本完全无效
- **签名引擎对新型样本集体失明**：这是签名匹配的固有局限
- **聚合评分是保守规则**：任一引擎报毒即为恶意，未做误报率加权和
  引擎同源去重
- **Emsisoft 免费版限私人非商业使用**，商用需购买授权

### 开发过程中被实测推翻的假设

记录在这里，提醒后来者：**这个领域的直觉经常是错的，跑一遍再说。**

- 「单核机器上引擎应该串行跑」→ 实测并发 4 比串行快一倍（49.2s vs 23.1s）。
  这些工具比看起来更偏 I/O
- 「模拟执行跑完没行为 = 样本干净」→ 完全错。MinGW 编译的样本会在 CRT
  启动阶段就中止，需要 msvcrt 兼容补齐；自实现虚拟机的样本则完全无效
- 「YARA 反调试规则用 API 组合计数就行」→ 在 `notepad.exe` 上误报，
  因为正常程序普遍导入 `IsDebuggerPresent`、`OutputDebugString`
