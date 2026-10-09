# YARA 规则目录

这个目录放**你自己的** `.yar` / `.yara` 文件，重启服务后自动加载（按子目录递归扫描）。

## 规则来自哪里

本产品**不自带手写规则**。检测用的规则集是第三方维护的
[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
（Florian Roth 维护，5200+ 条），下载到 `tools/yara-rules/`，跟 `rules/`
一起被 YARA 引擎加载。

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.cli setup-yara     # 首次下载
.\.venv\Scripts\python.exe -m app.cli update yara    # 更新
```

### 为什么用第三方规则，而不是自己写

自己写规则这件事我们试过，结论是**不划算**：手写的判据很容易写成
"具备某种能力"（比如"导入了 3 个以上反调试 API"），而正常 Windows 程序
合法地使用反调试、加密、文件枚举 API。早期 19 条手写规则里，有 8 条在
124 个系统文件上误报（6.5%）——`aitstatic.exe` 被判成勒索软件，
`certutil.exe` 被判成勒索软件，`ActionLink.dll` 被判成持久化。

换成 signature-base 之后，同一批 124 个系统文件的误报是 **0**。原因是
第三方规则由专业分析师维护、绑定具体家族、每条都经过实战验证，而且
有版本更新——这些都不是"顺手写几条"能比的。

所以本项目的定位是**规则集的消费者和调度者**，不是规则作者。

### 加载是容错的

signature-base 有 747 个规则文件，其中十几个用到了本机 yara 构建没编进去
的模块（`magic` / `macho` / `cuckoo`），或者需要 `filepath` 之类的外部变量。
`yara.compile(filepaths=...)` 是原子的——一个文件编译不过，整个规则库就
全军覆没。所以引擎会退化成逐文件编译、剔除坏的、保留好的，并如实报告
跳过了哪些。用 `python -m app.cli engines` 能看到当前加载状态。

## meta 约定

第三方规则不带本项目的 meta，判定等级由引擎从规则名前缀和 `score` 推导：

| 判据 | 判定 |
|---|---|
| `meta.verdict`（自有规则的约定） | 直接采用 |
| 规则名以 `PUA_` / `PUP_` 开头 | `pup` |
| `meta.score >= 75` | `malicious` |
| 规则名以 `MAL_` / `APT_` / `RANSOM_` / `WEBSHELL_` / `HKTL_` / `EXPL_` / `IMPLANT_` / `RAT_` / `CRIME_` 开头 | `malicious` |
| 其余 | `suspicious` |

自己写规则时可以用 meta 显式声明，覆盖以上推导：

```yara
rule Example_Rule
{
    meta:
        verdict = "malicious"      # malicious | suspicious | pup
        family  = "Emotet"         # 显示在结果列的签名名
        description = "这条规则在查什么"
    strings:
        $a = "suspicious string" ascii
    condition:
        uint16(0) == 0x5A4D and $a   # 0x5A4D = "MZ"，确保是 PE
}
```

多文件之间用命名空间隔离，标识符冲突不会互相影响。

## 加规则前先跑误报测试

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests/test_yara_rules.py -q
```

`tests/test_yara_rules.py` 会拿 180 个系统文件跑一遍，**任何一条规则命中
干净的系统文件，测试就失败**。一条会在 notepad.exe 上误报的规则，比没有
这条规则更糟——它会让人不再看结果。

诊断脚本 `tools/diag_fp.py` 能列出"哪条规则命中了哪些文件"，用于定位。
