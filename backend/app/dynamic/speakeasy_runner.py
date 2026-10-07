"""Speakeasy 模拟执行。

这是本产品动态分析的核心，也是"不执行样本"这一安全承诺的落点：
Speakeasy 用 Unicorn 引擎在用户态/内核态模拟 Windows API，样本的指令被
逐条解释执行，**从未作为真实进程运行过**，因此不受宿主机的网络隔离、
注册表保护、反虚拟机检测影响。

能从模拟执行里拿到的东西，恰恰是签名引擎看不见的：
- 完整 API 调用序列
- 运行期解密出来的字符串和 C2 地址
- 网络、注册表、文件、进程行为
- 可用于映射 MITRE ATT&CK 的技术点

报告结构（Speakeasy 1.5.x，`get_report()` 的返回）::

    {
      "arch": "x64", "os_run": "windows.6_1",
      "emulation_total_runtime": 0.298,
      "strings": {"static": {"ansi": [...], "unicode": [...]},
                  "in_memory": {"ansi": [...], "unicode": [...]}},
      "entry_points": [
        {"ep_type": "module_entry", "start_addr": "0x...",
         "apis": [{"pc": "0x...", "api_name": "KERNEL32.CreateFileW",
                   "args": ["0x1234"], "ret_val": "0x0"}],
         "error": {"type": "unsupported_api", ...}},   # 模拟中止原因
      ],
    }

   注意两个易错点：apis 直接挂在 entry_point 上（没有中间层），
   而 args 是字符串列表而不是对象列表。
"""

from __future__ import annotations

import multiprocessing
import re
from collections import Counter
from pathlib import Path
from queue import Empty

from ..config import settings

try:
    import speakeasy

    _SPEAKEASY_IMPORT_ERROR: str | None = None
except ImportError as exc:  # pragma: no cover - 取决于安装环境
    speakeasy = None  # type: ignore[assignment]
    _SPEAKEASY_IMPORT_ERROR = str(exc)


#: 归一化后的 API 名（小写）-> (ATT&CK 技术编号, 技术名称)
ATTACK_MAP: dict[str, tuple[str, str]] = {
    "createremotethread": ("T1055", "进程注入"),
    "virtualallocex": ("T1055", "进程注入"),
    "writeprocessmemory": ("T1055", "进程注入"),
    "ntmapviewofsection": ("T1055.002", "PE 注入"),
    "ntunmapviewofsection": ("T1055.002", "PE 注入"),
    "setthreadcontext": ("T1055.003", "线程执行劫持"),
    "queueuserapc": ("T1055.004", "APC 注入"),
    "setwindowshookexa": ("T1056.004", "API 挂钩"),
    "setwindowshookexw": ("T1056.004", "API 挂钩"),
    "getasynckeystate": ("T1056.001", "键盘记录"),
    "getkeystate": ("T1056.001", "键盘记录"),
    "getkeyboardstate": ("T1056.001", "键盘记录"),
    "createservicea": ("T1543.003", "创建 Windows 服务"),
    "createservicew": ("T1543.003", "创建 Windows 服务"),
    "openscmanagera": ("T1543.003", "创建 Windows 服务"),
    "openscmanagerw": ("T1543.003", "创建 Windows 服务"),
    "regsetvalueexa": ("T1547.001", "注册表自启动项"),
    "regsetvalueexw": ("T1547.001", "注册表自启动项"),
    "regcreatekeyexa": ("T1547.001", "注册表持久化"),
    "regcreatekeyexw": ("T1547.001", "注册表持久化"),
    "shellexecutea": ("T1106", "本地 API 调用"),
    "shellexecutew": ("T1106", "本地 API 调用"),
    "shellexecuteexw": ("T1106", "本地 API 调用"),
    "winexec": ("T1106", "本地 API 调用"),
    "createprocessa": ("T1106", "本地 API 调用"),
    "createprocessw": ("T1106", "本地 API 调用"),
    "createprocessinternalw": ("T1106", "本地 API 调用"),
    "urldownloadtofilea": ("T1105", "工具下载"),
    "urldownloadtofilew": ("T1105", "工具下载"),
    "internetopenurla": ("T1071.001", "Web 协议 C2"),
    "internetopenurlw": ("T1071.001", "Web 协议 C2"),
    "internetconnecta": ("T1071.001", "Web 协议 C2"),
    "internetconnectw": ("T1071.001", "Web 协议 C2"),
    "httpsendrequesta": ("T1071.001", "Web 协议 C2"),
    "httpsendrequestw": ("T1071.001", "Web 协议 C2"),
    "wsastartup": ("T1095", "非应用层协议"),
    "connect": ("T1095", "网络连接"),
    "socket": ("T1095", "网络套接字"),
    "gethostbyname": ("T1071.004", "DNS 解析"),
    "cryptencrypt": ("T1486", "数据加密（勒索）"),
    "cryptgenkey": ("T1486", "数据加密（勒索）"),
    "cryptacquirecontexta": ("T1486", "数据加密（勒索）"),
    "cryptacquirecontextw": ("T1486", "数据加密（勒索）"),
    "isdebuggerpresent": ("T1622", "反调试"),
    "checkremotedebuggerpresent": ("T1622", "反调试"),
    "ntqueryinformationprocess": ("T1622", "反调试"),
    "getsysteminfo": ("T1082", "系统信息探测"),
    "getcomputernamea": ("T1082", "系统信息探测"),
    "getcomputernamew": ("T1082", "系统信息探测"),
    "getusernamea": ("T1033", "用户发现"),
    "getusernamew": ("T1033", "用户发现"),
    "findfirstfilea": ("T1083", "文件发现"),
    "findfirstfilew": ("T1083", "文件发现"),
    "findfirstfileexw": ("T1083", "文件发现"),
    "getvolumeinformationa": ("T1083", "文件发现"),
    "getvolumeinformationw": ("T1083", "文件发现"),
    "createfilea": ("T1083", "文件访问"),
    "createfilew": ("T1083", "文件访问"),
    "copyfilea": ("T1074", "数据收集"),
    "copyfilew": ("T1074", "数据收集"),
    "deletefilea": ("T1485", "数据销毁"),
    "deletefilew": ("T1485", "数据销毁"),
    "virtualprotect": ("T1055", "内存权限修改"),
    "loadlibrarya": ("T1129", "动态加载库"),
    "loadlibraryw": ("T1129", "动态加载库"),
    "getprocaddress": ("T1129", "动态解析 API"),
}

#: 从字符串里提取 IOC
_RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,200}", re.IGNORECASE)
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|ru|cn|info|biz|top|xyz|io|me|cc|tk|pw|onion)\b",
    re.IGNORECASE,
)
_RE_REGISTRY = re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\"']{3,200}", re.IGNORECASE)
_RE_FILEPATH = re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|?*]{3,200}")

_NOISE_DOMAINS = {"example.com", "localhost", "schemas.microsoft.com", "w3.org"}
_NOISE_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}

#: CRT 启动例程调用的 API。它们与程序逻辑无关——如果模拟只走到这些，
#: 说明模拟刚过启动阶段就结束了，**没有观测到任何程序行为**。
#: 把这种情况和"真的跑了但没干坏事"区分开，是避免误读的关键。
_CRT_BOOTSTRAP_APIS = frozenset(
    {
        # msvcrt 启动例程
        "__p__iob", "setvbuf", "atexit", "_XcptFilter", "__set_app_type",
        "_set_app_type", "__p__fmode", "__p__commode", "__getmainargs",
        "__wgetmainargs", "_initterm", "_initterm_e", "__setusermatherr",
        "_amsg_exit", "_controlfp", "__p___initenv", "__p___argc",
        "__p___argv", "__p___wargv", "__p___mb_cur_max", "__lc_codepage",
        "__pxcptinfoptrs", "__fpecode", "_get_initial_narrow_environment",
        "_get_initial_wide_environment", "__acrt_iob_func", "_cexit",
        # MSVC CRT 启动
        "GetStartupInfoA", "GetStartupInfoW", "GetSystemTimeAsFileTime",
        "GetCurrentThreadId", "GetCurrentProcessId", "QueryPerformanceCounter",
        "GetModuleHandleA", "GetModuleHandleW", "GetCommandLineA",
        "GetCommandLineW", "GetProcessHeap", "HeapSetInformation",
        "SetUnhandledExceptionFilter", "IsProcessorFeaturePresent",
        "InitializeCriticalSection", "DeleteCriticalSection",
        "EncodePointer", "DecodePointer", "RtlUnwind",
    }
)


def _is_plausible_ip(ip: str) -> bool:
    """排除"版本号伪装成 IP"的假阳性。

    清单文件里的 version="5.1.0.0" 这类属性会被 IPv4 正则原样抓走。
    形如 x.y.0.0 的地址几乎不可能是真实的 C2，直接剔除。
    """
    if ip in _NOISE_IPS:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    if not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False
    # 后两段均为 0 → 判定为版本号而非地址
    return not (parts[2] == "0" and parts[3] == "0")


def is_available() -> tuple[bool, str]:
    if speakeasy is None:
        return False, f"未安装 speakeasy-emulator：{_SPEAKEASY_IMPORT_ERROR}"
    return True, ""


def _emulate_worker(path: str, queue: multiprocessing.Queue) -> None:
    """在子进程里执行模拟。

    必须是模块级函数——Windows 用 spawn 启动子进程，无法序列化闭包。
    """
    try:
        se = speakeasy.Speakeasy()

        # MinGW/GCC 编译的样本会调用 Speakeasy 没实现的 msvcrt 内部函数，
        # 导致模拟在入口点第一步就中止、一个 API 都记录不到。
        # 先补齐这几个启动例程用到的函数再跑。
        shims = 0
        if settings.msvcrt_shim:
            from .msvcrt_shim import register as register_shims

            shims = register_shims(se)

        module = se.load_module(path)
        se.run_module(module)

        report = _summarize(se.get_report())
        report["emulation"]["msvcrt_shims"] = shims
        queue.put(report)
    except Exception as exc:  # noqa: BLE001 - 模拟器对畸形样本很脆弱
        queue.put(
            {
                "available": True,
                "success": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        )


def emulate(path: Path, *, timeout_s: int = 120) -> dict:
    """在模拟环境中运行样本，带硬性超时。

    返回结构化行为报告。任何异常都被吞掉并转成 error 字段——模拟执行失败
    非常常见（不支持的指令、缺失的 DLL），不应该中断整轮扫描。

    超时必须靠独立进程实现：Speakeasy 的 run_module() 没有超时参数，
    而模拟执行遇到死循环或反模拟代码时会永久挂起。线程无法被强制终止，
    所以这里必须在自己的进程里跑，超时就杀掉。
    """
    ok, reason = is_available()
    if not ok:
        return {"available": False, "error": reason}

    ctx = multiprocessing.get_context("spawn")
    queue: multiprocessing.Queue = ctx.Queue()
    proc = ctx.Process(target=_emulate_worker, args=(str(path), queue), daemon=True)

    proc.start()
    proc.join(timeout_s)

    if proc.is_alive():
        proc.terminate()
        proc.join(5)
        if proc.is_alive():
            proc.kill()
            proc.join()
        return {
            "available": True,
            "success": False,
            "error": f"模拟执行超时（>{timeout_s}s），已强制中止",
        }

    # 进程已退出。spawn 模式下子进程的结果由独立线程送入管道，
    # join() 返回不代表数据一定已可见，所以带超时读取而不是查 empty()。
    proc.join()
    try:
        return queue.get(timeout=5)
    except Empty:
        return {
            "available": True,
            "success": False,
            "error": f"模拟进程异常退出（退出码 {proc.exitcode}），未返回结果",
        }


# --------------------------------------------------------------------------
# 报告解析
# --------------------------------------------------------------------------


def _normalize_api(raw_name: str | None) -> str:
    """把 "KERNEL32.CreateFileW" 归一化为 "CreateFileW"。

    Speakeasy 的 api_name 形如 "DLL.Function"，且 DLL 部分还可能是
    "api-ms-win-crt-string-l1-1-0" 这样的 API set 名。
    """
    if not raw_name:
        return ""
    return raw_name.rsplit(".", 1)[-1].strip()


def _collect_strings(raw: dict) -> dict[str, list[str]]:
    """按来源收集字符串。

    static   — 文件里静态可见的字符串
    in_memory — 运行期才出现的字符串，**解密/解包的直接证据**，价值最高
    """
    out = {"static": [], "in_memory": []}
    block = raw.get("strings") or {}
    for scope in ("static", "in_memory"):
        section = block.get(scope) or {}
        for encoding in ("ansi", "unicode"):
            for value in section.get(encoding) or []:
                if isinstance(value, str):
                    out[scope].append(value)
    return out


def _summarize(raw: dict) -> dict:
    api_counts: Counter[str] = Counter()
    stop_reasons: list[str] = []
    entry_points = raw.get("entry_points") or []

    for entry in entry_points:
        # apis 直接挂在 entry_point 上，没有中间层
        for call in entry.get("apis") or []:
            name = _normalize_api(call.get("api_name"))
            if name:
                api_counts[name] += 1

        error = entry.get("error")
        if isinstance(error, dict) and error.get("type"):
            stop_reasons.append(str(error["type"]))

    strings = _collect_strings(raw)
    # IOC 从两个来源合并提取；运行期字符串是加壳样本的主要线索来源
    all_strings = set(strings["static"]) | set(strings["in_memory"])
    truncated = bool(stop_reasons)

    # 只有 CRT 启动调用 = 模拟刚过启动就结束了，没看到程序逻辑。
    # 这与"跑完了但没干坏事"是两回事，必须区分开。
    beyond_bootstrap = set(api_counts) - _CRT_BOOTSTRAP_APIS
    bootstrap_only = bool(api_counts) and not beyond_bootstrap

    return {
        "available": True,
        "success": True,
        "entry_points": len(entry_points),
        "total_api_calls": sum(api_counts.values()),
        "unique_apis": len(api_counts),
        "top_apis": api_counts.most_common(40),
        "attack_techniques": _map_attack(api_counts),
        "iocs": _extract_iocs(all_strings),
        # 只在运行期出现的字符串——解密/解包行为的直接证据
        "decoded_strings": sorted(
            s for s in set(strings["in_memory"]) if _looks_interesting(s)
        )[:100],
        "emulation": {
            "runtime_s": raw.get("emulation_total_runtime"),
            "os": raw.get("os_run"),
            "arch": raw.get("arch"),
            "stop_reasons": stop_reasons,
            # 模拟在没有跑到样本主逻辑时就中止了，此时"没检出行为"不代表安全
            "truncated": truncated,
            # 只跑到 CRT 启动就结束了，整段程序逻辑都没执行到
            "bootstrap_only": bootstrap_only,
        },
    }


def _map_attack(api_counts: Counter[str]) -> list[dict]:
    hits: dict[str, dict] = {}
    for api, count in api_counts.items():
        technique = ATTACK_MAP.get(api.lower())
        if not technique:
            continue
        tid, name = technique
        entry = hits.setdefault(tid, {"id": tid, "name": name, "apis": [], "count": 0})
        if api not in entry["apis"]:
            entry["apis"].append(api)
        entry["count"] += count
    return sorted(hits.values(), key=lambda x: x["count"], reverse=True)


def _extract_iocs(strings: set[str]) -> dict:
    blob = "\n".join(strings)

    urls = {u.rstrip(".,;") for u in _RE_URL.findall(blob)}
    ips = {ip for ip in _RE_IPV4.findall(blob) if _is_plausible_ip(ip)}
    domains = {
        d.lower() for d in _RE_DOMAIN.findall(blob) if d.lower() not in _NOISE_DOMAINS
    }
    registry = set(_RE_REGISTRY.findall(blob))
    files = set(_RE_FILEPATH.findall(blob))

    return {
        "urls": sorted(urls)[:50],
        "ips": sorted(ips)[:50],
        "domains": sorted(domains)[:50],
        "registry_keys": sorted(registry)[:50],
        "file_paths": sorted(files)[:50],
    }


def _looks_interesting(value: str) -> bool:
    """过滤掉无意义的短字符串和纯数字噪音。"""
    if len(value) < 6:
        return False
    return any(c.isalpha() for c in value)
