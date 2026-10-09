"""命令行入口。

    python -m app.cli engines              查看引擎可用状态
    python -m app.cli scan <path>          扫描一个文件
    python -m app.cli serve                启动 Web 服务
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import orchestrator
from .config import settings
from .engines.registry import build_engines, describe_engines  # noqa: F401

_VERDICT_MARK = {
    "malicious": "!! 恶意",
    "suspicious": "?? 可疑",
    "clean": "OK 干净",
    "unknown": "-- 未知",
}


def cmd_engines(_args: argparse.Namespace) -> int:
    from .engines.base import POLICY_TEXT

    rows = describe_engines()
    policy = settings.network_policy
    print(f"网络策略：{POLICY_TEXT.get(policy, policy)}")
    print(f"          （PEINSIGHT_NETWORK_POLICY={policy}，可选 local / no-sample / any）\n")

    print(f"{'引擎':<20} {'已安装':<8} {'本次启用':<10} {'外传等级':<14} 说明")
    print("-" * 100)
    for row in rows:
        installed = "是" if row["available"] else "否"
        active = "是" if row["active"] else "否"
        note = (
            row["excluded_reason"]
            or row["reason"]
            or row.get("load_note")
            or row["network_note"]
            or ""
        )
        print(
            f"{row['name']:<20} {installed:<8} {active:<10} "
            f"{row['network_level_text']:<14} {note[:52]}"
        )

    excluded = [r for r in rows if not r["active"]]
    if excluded:
        print()
        print("[!] 有引擎因超出网络策略而未启用：")
        for row in excluded:
            print(f"    {row['name']}（{row['network_level_text']}）")
            print(f"      {row['excluded_reason']}")
        print()
        print("    可选处理方式：")
        print("      A. 收紧该引擎的外传行为，使它满足当前策略")
        print("         （Defender：Set-MpPreference -SubmitSamplesConsent NeverSend）")
        print("      B. 放宽策略，接受更高等级：")
        print("         $env:PEINSIGHT_NETWORK_POLICY = 'any'")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.is_file():
        print(f"文件不存在：{path}", file=sys.stderr)
        return 2

    print(f"扫描中：{path}")
    if args.dynamic:
        print("（含 Speakeasy 模拟执行，可能需要 1-2 分钟）")

    report = orchestrator.scan_file(
        path,
        run_dynamic=args.dynamic,
        dynamic_timeout_s=args.dynamic_timeout,
    )

    if args.json:
        print(orchestrator.dumps(report))
        return 0

    _print_report(report)
    return 0


def _print_report(report: dict) -> None:
    verdict = report["verdict"]
    print()
    print("=" * 72)
    print(f"  结论：{_VERDICT_MARK.get(verdict, verdict)}   "
          f"检出 {report['detection_ratio']}")
    print("=" * 72)
    print(f"  文件名   {report['filename']}")
    print(f"  大小     {report['size']:,} 字节")
    print(f"  SHA256   {report['sha256']}")
    print(f"  MD5      {report['md5']}")

    # 静态
    static = report.get("static") or {}
    print()
    print("-- 静态分析 " + "-" * 60)
    if static.get("is_pe"):
        print(f"  架构       {static.get('machine')}")
        print(f"  编译时间   {static.get('compile_timestamp')}")
        print(f"  Imphash    {static.get('imphash')}")
        print(f"  节区       {len(static.get('sections', []))} 个")
        for flag in static.get("indicators", []):
            print(f"  [!] {flag}")
    elif static.get("reason"):
        print(f"  {static['reason']}")
    if static.get("error"):
        print(f"  错误：{static['error']}")

    # 引擎
    print()
    print("-- 引擎结果 " + "-" * 60)
    for result in report.get("engines", []):
        mark = _VERDICT_MARK.get(result["verdict"], result["verdict"])
        sig = f"  [{result['signature']}]" if result.get("signature") else ""
        note = f"  ({result['error']})" if result.get("error") else ""
        print(f"  {result['engine']:<20} {mark:<10} {result['duration_ms']:>6}ms{sig}{note}")

    # 动态
    dynamic = report.get("dynamic")
    print()
    print("-- 动态分析（模拟执行） " + "-" * 48)
    if not dynamic:
        print("  未启用")
    elif not dynamic.get("success"):
        print(f"  {dynamic.get('error') or '模拟执行未产出结果'}")
    else:
        emu = dynamic.get("emulation") or {}
        # 模拟没跑到程序逻辑时必须显式告知——否则"没行为"会被误读成"安全"
        if emu.get("bootstrap_only"):
            print(
                f"  [!] 模拟只走完 CRT 启动（{dynamic['total_api_calls']} 次调用），"
                "未进入程序自身逻辑"
            )
            print("      常见原因：样本用了自实现的字节码虚拟机或加壳保护，")
            print("      模拟器观测不到它的系统交互。\"未观测到行为\"不等于样本安全。")
        elif emu.get("truncated"):
            reasons = "、".join(emu.get("stop_reasons") or ["未知"])
            print(f"  [!] 模拟在第 {dynamic['total_api_calls']} 次调用处中止（{reasons}）")
            print("      未覆盖样本完整逻辑，此处\"无行为\"不构成安全结论")

        runtime = emu.get("runtime_s")
        runtime_txt = f"（{runtime:.2f}s）" if isinstance(runtime, (int, float)) else ""
        print(f"  API 调用   {dynamic['total_api_calls']} 次 / {dynamic['unique_apis']} 个不同 API{runtime_txt}")

        techniques = dynamic.get("attack_techniques") or []
        if techniques:
            print("  ATT&CK 技术：")
            for tech in techniques[:10]:
                print(f"    {tech['id']:<12} {tech['name']}  ({tech['count']} 次)")

        iocs = dynamic.get("iocs") or {}
        for key, label in (("urls", "URL"), ("domains", "域名"), ("ips", "IP"), ("registry_keys", "注册表")):
            values = iocs.get(key) or []
            if values:
                print(f"  {label}：{', '.join(values[:5])}")

        decoded = dynamic.get("decoded_strings") or []
        if decoded:
            print(f"  运行期解密字符串 {len(decoded)} 条，例如：")
            for s in decoded[:5]:
                print(f"    {s[:88]}")

    print()


def _check_mark(check: dict) -> str:
    """把一个检查项渲染成短标记。"""
    if not check:
        return "—"
    state = check.get("state")
    if state == "locked":
        return "被锁定"
    if state == "skipped":
        return "跳过"
    if check.get("passed") is None:
        return "错误"
    # 干净载体上测的是链路健康度，不是检出
    if check.get("expect_detection") is False:
        return "正常" if check["passed"] else "错误"
    return "检出" if check["passed"] else "未检出"


def cmd_selftest(_args: argparse.Namespace) -> int:
    """用 EICAR 测试串验证每个引擎是否真的在查杀。

    只扫干净样本是看不出问题的——所有引擎都会说"干净"，
    包括那些压根没跑起来的。
    """
    from .engines.base import EngineKind
    from .selftest import FILE_LOCKED, run_selftest

    engines = build_engines()
    by_name = {e.name: e for e in engines}
    print("正在自检（生成 EICAR 测试文件，无害，用于验证引擎检出能力）…\n")

    report = run_selftest(engines)
    locked = report["eicar_state"] == FILE_LOCKED

    print(f"{'引擎':<20} {'EICAR 检出':<12} {'PE 链路':<10} 结论")
    print("-" * 78)

    failures: list[str] = []
    unverified: list[str] = []

    for entry in report["results"]:
        engine = by_name.get(entry["engine"])
        kind = engine.kind if engine else EngineKind.SIGNATURE

        if entry.get("skipped"):
            print(
                f"{entry['engine']:<20} {'—':<10} {'—':<10} "
                f"跳过：{entry['reason'][:30]}"
            )
            continue

        eicar = entry["checks"].get("eicar", {})
        pe = entry["checks"].get("pe_path", {})

        if kind is EngineKind.RULE:
            verdict = "正常（规则引擎，不针对 EICAR）"
        elif eicar.get("passed") is True:
            verdict = "正常"
        elif eicar.get("state") == "locked":
            # 文件被实时防护锁死：对 Defender 是检出证据，对其他引擎是无法验证
            if entry["engine"] == "Windows Defender":
                verdict = "正常（实时防护已拦截该文件＝检出）"
            else:
                verdict = "无法验证（文件被实时防护锁定）"
                unverified.append(entry["engine"])
        elif eicar.get("state") == "error":
            verdict = "异常！测试文件无法写入"
            failures.append(entry["engine"])
        else:
            verdict = "异常！引擎可能未真正工作"
            failures.append(entry["engine"])

        print(
            f"{entry['engine']:<20} {_check_mark(eicar):<10} "
            f"{_check_mark(pe):<10} {verdict}"
        )

    print()
    if locked:
        print(
            "注意：测试文件被 Windows Defender 实时防护锁定，文件仍在磁盘上但"
            "任何读取都被拒绝。这意味着**未排除的目录无法分析真实恶意样本**——"
            "样本一落盘就会被锁住，所有引擎都读不到。"
        )
        if unverified:
            print(f"受影响而无法验证的引擎：{'、'.join(unverified)}")
        print(
            "\n如需分析真实样本，请执行（需管理员权限）：\n"
            "  python -m app.cli setup-exclusions --yes"
        )
        print()

    if failures:
        print(f"有 {len(failures)} 个引擎未通过：{'、'.join(failures)}")
        print("请检查签名库是否已更新（ClamAV 需执行 freshclam）。")
        return 1

    if unverified:
        print("引擎本身未发现故障，但受实时防护干扰无法完整验证。")
        return 0

    print("全部可用引擎均通过自检。")
    return 0


def cmd_setup_exclusions(args: argparse.Namespace) -> int:
    """把分析目录加入 Defender 排除列表——分析真实样本的前提条件。"""
    from . import defender_exclusions as dx

    paths = [str(settings.data_dir)]
    paths.extend(args.path or [])

    print("即将把以下目录加入 Windows Defender 排除列表：\n")
    for path in paths:
        print(f"  {path}")

    print(
        "\n[!] 安全影响：被排除的目录不受实时防护保护。"
        "其中的恶意文件如果被误双击，会直接执行并感染本机。"
        "\n    仅在专用分析机，或你明确接受该风险时使用。\n"
    )

    if not args.yes:
        print("确认无误后加 --yes 执行。")
        return 1

    if not dx.is_admin():
        print("需要管理员权限。请以管理员身份打开 PowerShell 后重试。")
        return 1

    code = 0
    for path in paths:
        ok, msg = dx.add_exclusion(path)
        print(f"  {'OK  ' if ok else '失败'} {msg}")
        if not ok:
            code = 1

    if code == 0:
        print("\n完成。若要撤销，执行：")
        for path in paths:
            print(f"  Remove-MpPreference -ExclusionPath '{path}'")
    return code


def cmd_setup_clamav(args: argparse.Namespace) -> int:
    """下载并配置 ClamAV 便携版。"""
    from . import setup_clamav

    result = setup_clamav.install(
        force=args.force, skip_db=args.skip_db, progress=print
    )
    if result.get("error"):
        print(f"\n失败：{result['error']}")
        return 1

    print(f"\n安装目录：{result['dir']}")
    if result["database_ok"]:
        print("签名库已就绪。")
        print("\n提示：启动 clamd 可将单文件扫描从十余秒降到毫秒级：")
        print(f'  {result["dir"]}\\clamd.exe --config-file="{result["dir"]}\\clamd.conf"')
    else:
        print("签名库未就绪——没有签名库的 ClamAV 什么都查不出。")
        print("请重试，或手动执行：")
        print(f'  {result["dir"]}\\freshclam.exe --config-file="{result["dir"]}\\freshclam.conf"')
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    """更新签名库与规则集。"""
    from . import updater

    if args.check:
        print(f"{'组件':<18} {'状态':<12} 说明")
        print("-" * 72)
        for st in updater.status():
            print(f"{st.label:<18} {st.age_text:<12} {st.detail}")
        print("\n执行 `python -m app.cli update` 更新全部。")
        return 0

    names = [n.strip().lower() for n in args.only.split(",")] if args.only else None
    stale = args.if_stale_hours

    if names:
        unknown = [n for n in names if n not in updater.COMPONENTS]
        if unknown:
            print(f"未知组件：{'、'.join(unknown)}")
            print(f"可用：{'、'.join(updater.COMPONENTS)}")
            return 1

    print("检查各组件新鲜度…")
    for st in updater.status():
        if names and st.name not in names:
            continue
        print(f"  {st.label:<18} {st.age_text}")

    print()
    print("开始更新…")
    if stale:
        print(f"（只更新超过 {stale} 小时的，其余跳过）")
    print()

    results = updater.update(names=names, max_age_hours=stale, progress=print)

    print("\n=== 结果 ===")
    failed = 0
    for r in results:
        label = r.get("label", r["name"])
        if r.get("skipped"):
            mark = "跳过"
        elif r["updated"]:
            mark = "已更新"
        else:
            mark = "失败"
            failed += 1
        print(f"  {mark:<6} {label:<18} {r['message']}")

    if failed:
        print(f"\n有 {failed} 个组件更新失败，通常是网络问题，可稍后重试。")
        return 1
    print("\n完成。")
    return 0


def cmd_setup_tools(args: argparse.Namespace) -> int:
    """安装结构/能力分析工具（DIE / Manalyze / CAPA）。"""
    from . import setup_tools

    print("安装开源分析工具（全部免费、无试用期、完全本地）")
    results = setup_tools.install(force=args.force, progress=print)

    print("\n=== 安装结果 ===")
    for name, ok in results.items():
        print(f"  {'OK  ' if ok else '失败'} {name}")

    if not all(results.values()):
        print("\n有工具未装成功，可加 --force 重试。")
        return 1

    print("\n提示：Manalyze 的 VirusTotal 插件已被删除，不存在上传通道。")
    print("      CAPA 用 pip 版是为了绕开官方 PyInstaller 包的死锁问题。")
    return 0


def cmd_setup_yara(args: argparse.Namespace) -> int:
    """下载第三方 YARA 规则集（signature-base）。"""
    from . import setup_yara

    print("下载 signature-base 规则集（Florian Roth 维护，开源）")
    print("规则来自第三方，本项目不自带手写规则。\n")

    if not setup_yara.install(force=args.force, progress=print):
        print("\n下载失败。可稍后重试，或加 --force 重新拉取。")
        return 1

    count = setup_yara.installed_count()
    print(f"\n已就绪：{count} 个规则文件 → {setup_yara.rules_dir()}")
    print("重启服务后生效（规则在启动时一次性编译）。")
    return 0


def cmd_setup_emsisoft(args: argparse.Namespace) -> int:
    """下载并配置 Emsisoft Emergency Kit。"""
    from . import setup_emsisoft

    result = setup_emsisoft.install(
        force=args.force, skip_db=args.skip_db, progress=print
    )
    if result.get("error"):
        print(f"\n失败：{result['error']}")
        return 1

    print(f"\n安装目录：{result['dir']}")
    if result["database_ok"]:
        print("签名库已就绪。")
    else:
        print(f"签名库未就绪：{result.get('db_message')}")
        print("请重试，或手动执行：")
        print(f'  "{result["dir"]}\\bin64\\a2cmd.exe" /u')

    print("\n授权提示：EEK 免费版**仅限私人非商业用途**，无时间限制；")
    print("          商用需购买 EEK Pro 或 Emsisoft 商业授权。")
    print("          扫描时本产品固定传 /cloud=0，不会向云端提交任何数据。")
    return 0


def cmd_purge_samples(args: argparse.Namespace) -> int:
    """清空样本库。

    本工具默认把样本按 SHA256 存进 data/samples/，便于重复分析、比对与
    重跑。但真实恶意样本长期留在磁盘上是有风险的——尤其是 data 目录已被
    加入 Defender 排除列表，那里的文件不受实时防护保护。

    扫描报告留在数据库里不受影响，只是再也无法对同一份样本重新扫描。
    """
    from .config import settings

    samples_dir = settings.samples_dir
    files = [f for f in samples_dir.rglob("*") if f.is_file()]
    total = sum(f.stat().st_size for f in files)

    print(f"样本库：{samples_dir}")
    print(f"共 {len(files)} 个文件，{total / 1024 / 1024:.1f} MB\n")

    if not files:
        print("样本库为空。")
        return 0

    if not args.yes:
        print("这会永久删除全部已存样本（扫描报告不受影响）。")
        print("确认后加 --yes 执行。")
        return 1

    removed = 0
    for path in files:
        try:
            path.unlink()
            removed += 1
        except OSError as exc:
            print(f"  删除失败 {path.name}：{exc}")

    # 清掉空的分桶目录
    for path in sorted(samples_dir.rglob("*"), reverse=True):
        if path.is_dir() and not any(path.iterdir()):
            try:
                path.rmdir()
            except OSError:
                pass

    print(f"已删除 {removed} 个样本。")
    return 0


def cmd_clamd(args: argparse.Namespace) -> int:
    """管理 ClamAV 守护进程。"""
    from . import clamd_manager as cm

    if args.action == "status":
        st = cm.status()
        print(f"  已安装 : {st['installed']}")
        print(f"  运行中 : {st['running']}")
        print(f"  端口   : 127.0.0.1:{st['port']}")
        if st["installed"] and not st["running"]:
            print("\n  启动后可把单文件扫描从 ~3 秒降到毫秒级：")
            print("    python -m app.cli clamd start")
        return 0

    if args.action == "start":
        print("  正在启动 clamd（首次需加载签名库，可能要十几秒）…")
        ok, msg = cm.start()
    else:
        ok, msg = cm.stop()

    print(f"  {'OK  ' if ok else '失败'} {msg}")
    return 0 if ok else 1


def cmd_privacy(_args: argparse.Namespace) -> int:
    """审计是否存在把样本送出本机的通道。"""
    from . import privacy

    audit = privacy.audit_defender()
    print("=== 样本外传通道审计 ===\n")

    if not audit.get("available"):
        print(f"Windows Defender：无法审计（{audit.get('reason')}）")
    else:
        print("Windows Defender：")
        print(f"  云保护 (MAPS)      : {audit['maps_text']}")
        print(f"  样本提交策略       : {audit['submit_text']}")
        print(f"  存在外传通道       : {'是' if audit['sends_samples'] else '否'}")
        if audit.get("warning"):
            print(f"\n  [!] {audit['warning']}")
            print("\n  如需关闭（会削弱系统防护，请自行权衡）：")
            for cmd in privacy.harden_script():
                print(f"    {cmd}")
            print("  需以管理员身份运行 PowerShell。")

    print("\n本产品自身组件（不会外传）：")
    for name in ("ClamAV", "YARA", "Speakeasy 模拟执行", "静态分析"):
        print(f"  {name:<20} 完全本地")
    return 0


def cmd_verify_offline(args: argparse.Namespace) -> int:
    """实测断网可行性与"样本不外传"的强制效果。"""
    from . import netguard, privacy

    print("=== 1. 出网守卫实测 ===")
    ok, msg = netguard.selfcheck()
    print(f"  拦截外部连接 : {'通过' if ok else '失败'} — {msg}")
    ok2, msg2 = netguard.check_loopback_allowed()
    print(f"  放行回环连接 : {'通过' if ok2 else '失败'} — {msg2}")

    if not (ok and ok2):
        print("\n守卫未通过自检，不应信任其保护效果。")
        return 1

    print("\n=== 2. Defender 外传通道 ===")
    audit = privacy.audit_defender()
    if audit.get("available"):
        print(f"  云保护       : {audit['maps_text']}")
        print(f"  样本提交     : {audit['submit_text']}")
        if audit["sends_samples"]:
            print("  [!] Defender 可能把样本提交给微软——本产品无法拦截此通道")
    else:
        print(f"  无法审计：{audit.get('reason')}")

    print("\n=== 3. 实际扫描中的出网尝试 ===")
    target = Path(args.sample) if args.sample else _find_benign_sample()
    if not target:
        print("  未找到可用的测试样本，跳过")
        return 0

    print(f"  样本：{target}")
    report = orchestrator.scan_file(target, run_dynamic=args.dynamic)
    net = report.get("network") or {}
    blocked = net.get("blocked_attempts") or []

    print(f"  守卫已启用   : {net.get('enforced')}")
    print(f"  出网尝试次数 : {len(blocked)}")
    for item in blocked:
        print(f"    - {item}")

    if not blocked:
        print("\n扫描全程未产生任何外部网络连接。")
    return 0


def _find_benign_sample() -> Path | None:
    for candidate in (
        r"C:\Windows\System32\calc.exe",
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\attrib.exe",
    ):
        path = Path(candidate)
        if path.is_file():
            return path
    return None


#: 代理 / VPN 的虚拟网段。这些地址别的机器连不上，不能当"局域网地址"报出去。
_VIRTUAL_PREFIXES = ("172.17.", "172.18.", "172.19.", "10.0.2.", "172.16.")


def _primary_lan_ip() -> str | None:
    """找出真正能被同网段其他机器访问的本机 IP。

    这里有个坑：装了代理/VPN 的机器会有 TUN 虚拟网卡（实测这台是
    singbox_tun，172.18.0.1），而且**默认路由往往就指向它**。所以：

    - 不能用"第一个非回环地址"——会拿到 TUN
    - 也不能用 UDP connect 探源地址——代理接管流量后拿到的还是 TUN

    可靠的做法是只查**物理网卡**（Get-NetAdapter -Physical 会排除所有
    虚拟适配器），取它上面处于 Up 状态的 IPv4 地址。
    """
    import socket
    import subprocess

    # 首选：只枚举物理网卡
    script = (
        "Get-NetAdapter -Physical -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Status -eq 'Up' } | "
        "ForEach-Object { "
        "  Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 "
        "    -ErrorAction SilentlyContinue "
        "} | Select-Object -ExpandProperty IPAddress"
    )
    try:
        proc = subprocess.run(  # noqa: S603
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for line in (proc.stdout or "").splitlines():
            ip = line.strip()
            if ip and not ip.startswith(("127.", "169.254.")):
                return ip
    except (OSError, subprocess.TimeoutExpired):
        pass

    # 退路：枚举本机地址，排除回环、链路本地和已知的虚拟网段
    try:
        candidates = socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        return None

    for ip in candidates:
        if ip.startswith(("127.", "169.254.")):
            continue
        if ip.startswith(_VIRTUAL_PREFIXES):
            continue
        return ip
    return None


def _is_admin() -> bool:
    """当前进程是否以管理员运行。仅 Windows 有意义。"""
    import ctypes
    import sys

    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    lan = args.host not in ("127.0.0.1", "localhost")

    # Emsisoft 的 a2cmd 在非提升会话下会直接拒绝扫描（退出码 9「需要更高权限」）。
    # 启动脚本会自动提权，但有人可能直接跑这条命令，这里必须提醒。
    #
    # flush=True 不能省：stdout 重定向到文件/管道时是块缓冲的，而服务启动后
    # 会一直运行不退出，缓冲区永远不会自动落盘，用户就看不到这段警告。
    if not _is_admin():
        print()
        print("  [!] 当前不是管理员会话，Emsisoft 引擎会因权限不足而扫描失败。")
        print("      建议用项目根目录的 start.ps1 启动（它会自动请求提权），")
        print("      或手动以管理员身份运行 PowerShell 后重试。")
        print(flush=True)

    print(f"PE Insight 启动中 → http://{args.host}:{args.port}")
    print(f"数据目录：{settings.data_dir}")

    if lan:
        # 绑定到非回环地址意味着同一网段的任何机器都能访问
        local_ip = _primary_lan_ip()
        if local_ip:
            print(f"局域网访问地址：http://{local_ip}:{args.port}")
        else:
            print("局域网访问地址：本机 IP（探测失败，用 ipconfig 自行确认）")

        if settings.api_key:
            print("鉴权：已启用（请求需带 X-API-Key 头）")
        else:
            print()
            print("  [!] 警告：正在监听非回环地址，但没有设置 API Key。")
            print("      这个接口接收任意文件上传并送进杀毒引擎、把样本落盘。")
            print("      不设防等于给整个网段开了投毒入口。设置方法：")
            print()
            print('        $env:PEINSIGHT_API_KEY = "你的密钥"')
            print()

    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pe-insight", description="本地多引擎 PE 分析")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("engines", help="查看引擎可用状态").set_defaults(func=cmd_engines)

    sub.add_parser("selftest", help="验证引擎是否真的在查杀").set_defaults(
        func=cmd_selftest
    )

    sub.add_parser("privacy", help="审计样本外传通道").set_defaults(func=cmd_privacy)

    purge = sub.add_parser("purge-samples", help="清空已存样本（报告保留）")
    purge.add_argument("--yes", action="store_true", help="确认执行")
    purge.set_defaults(func=cmd_purge_samples)

    clamd = sub.add_parser("clamd", help="管理 ClamAV 守护进程（大幅提速）")
    clamd.add_argument("action", choices=["start", "stop", "status"])
    clamd.set_defaults(func=cmd_clamd)

    excl = sub.add_parser(
        "setup-exclusions", help="将分析目录加入 Defender 排除列表（分析真实样本的前提）"
    )
    excl.add_argument("--path", action="append", help="额外要排除的目录（可重复）")
    excl.add_argument("--yes", action="store_true", help="确认执行（会降低本机防护强度）")
    excl.set_defaults(func=cmd_setup_exclusions)

    verify = sub.add_parser("verify-offline", help="实测断网可行性与出网拦截")
    verify.add_argument("--sample", help="指定测试样本（默认取系统自带 PE）")
    verify.add_argument(
        "--dynamic", action="store_true", help="一并测试模拟执行（较慢）"
    )
    verify.set_defaults(func=cmd_verify_offline)

    setup = sub.add_parser("setup-clamav", help="下载并配置 ClamAV 便携版")
    setup.add_argument("--force", action="store_true", help="重新下载")
    setup.add_argument("--skip-db", action="store_true", help="跳过签名库更新")
    setup.set_defaults(func=cmd_setup_clamav)

    eek = sub.add_parser(
        "setup-emsisoft",
        help="下载并配置 Emsisoft Emergency Kit（免费、无时限、限私人非商业）",
    )
    eek.add_argument("--force", action="store_true", help="重新下载")
    eek.add_argument("--skip-db", action="store_true", help="跳过签名库更新")
    eek.set_defaults(func=cmd_setup_emsisoft)

    tools = sub.add_parser(
        "setup-tools", help="安装 DIE / Manalyze / CAPA（开源、本地、免费）"
    )
    tools.add_argument("--force", action="store_true", help="重新下载")
    tools.set_defaults(func=cmd_setup_tools)

    yara_rules = sub.add_parser(
        "setup-yara", help="下载 signature-base YARA 规则集（5000+ 条，开源）"
    )
    yara_rules.add_argument("--force", action="store_true", help="重新下载")
    yara_rules.set_defaults(func=cmd_setup_yara)

    upd = sub.add_parser("update", help="更新签名库与规则集")
    upd.add_argument("--check", action="store_true", help="只查看新鲜度，不下载")
    upd.add_argument("--only", help="只更新指定组件，逗号分隔（clamav,emsisoft,die,capa）")
    upd.add_argument(
        "--if-stale-hours",
        type=float,
        metavar="N",
        help="只更新超过 N 小时的组件",
    )
    upd.set_defaults(func=cmd_update)

    scan = sub.add_parser("scan", help="扫描一个文件")
    scan.add_argument("path", help="样本路径")
    scan.add_argument("--no-dynamic", dest="dynamic", action="store_false", help="跳过模拟执行")
    scan.add_argument("--dynamic-timeout", type=int, default=120, help="模拟执行超时秒数")
    scan.add_argument("--json", action="store_true", help="输出完整 JSON 报告")
    scan.set_defaults(func=cmd_scan)

    serve = sub.add_parser("serve", help="启动 Web 服务")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    settings.ensure_dirs()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
