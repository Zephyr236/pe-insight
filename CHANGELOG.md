# 更新日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

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
