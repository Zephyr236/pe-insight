"""MSVCRT 兼容补齐。

Speakeasy 面向 MSVC 编译的程序，但 MinGW/GCC 编译的样本会调用一批
它没实现的 msvcrt 内部函数。少了这些，模拟会在**入口点第一步**就中止，
一个 API 都记录不到——不是"没有行为"，而是"根本没跑起来"。

实测一个 MinGW 编译的样本，缺失的链条恰好是这四个：

    __p__iob → setvbuf → atexit → _XcptFilter

它们全是 CRT 启动例程用的，与程序本身的逻辑无关。补齐后模拟就能越过
启动阶段。注意：**这只是把门打开，不等于能看清屋里有什么**——如果样本
的逻辑跑在自实现的字节码虚拟机里，模拟器仍然观测不到任何系统交互。

用法：
    from .msvcrt_shim import register
    register(se)   # se 是已构造的 Speakeasy 实例
"""

from __future__ import annotations

#: 32 位 msvcrt 的 _iob 数组有 _NFILE 个 FILE 结构；每个 FILE 通常 32 字节，
#: 这里给足余量，避免程序索引到范围外
_IOB_ENTRIES = 20
_FILE_SIZE = 32


def _find_emu(args):
    """钩子可能以 (emu, argv, ctx) 或 (emu, ctx) 传入，取出带内存接口的那个。"""
    return next((a for a in args if hasattr(a, "mem_alloc")), None)


def _make_p_iob():
    def handler(*args, **kwargs):
        """FILE *__p__iob(void)

        返回标准流 FILE 数组的指针，CRT 用 _iob[0..2] 初始化
        stdin / stdout / stderr。
        """
        emu = _find_emu(args)
        if emu is None:
            return 0
        size = _IOB_ENTRIES * _FILE_SIZE
        try:
            addr = emu.mem_alloc(size=size, tag="shim._iob")
            emu.mem_write(addr, b"\x00" * size)
            return addr
        except Exception:  # noqa: BLE001 - 补齐失败不该让整轮模拟崩掉
            return 0

    return handler


def _const_zero(*args, **kwargs):
    """成功返回 0 的整型 API。"""
    return 0


def _xcpt_filter(*args, **kwargs):
    """int _XcptFilter(unsigned long code, EXCEPTION_POINTERS *ep)

    返回 EXCEPTION_EXECUTE_HANDLER 之外的默认处理：把异常码原样返回，
    表示"未处理，继续向上抛"。
    """
    for arg in args:
        if isinstance(arg, (list, tuple)) and arg:
            try:
                return int(arg[0])
            except (TypeError, ValueError):
                return 0
    return 0


#: 函数名 -> 钩子工厂。加新条目时先确认 Speakeasy 确实没实现它。
_SHIMS = {
    "__p__iob": _make_p_iob,
    "setvbuf": lambda: _const_zero,
    "atexit": lambda: _const_zero,
    "_XcptFilter": lambda: _xcpt_filter,
}


def missing_apis() -> tuple[str, ...]:
    return tuple(_SHIMS)


def register(se) -> int:
    """把补齐钩子注册到 Speakeasy 实例上，返回成功注册的数量。"""
    count = 0
    for name, factory in _SHIMS.items():
        try:
            se.add_api_hook(factory(), module="msvcrt", api_name=name, argc=0)
            count += 1
        except Exception:  # noqa: BLE001 - 不同 Speakeasy 版本接口可能不同
            continue
    return count
