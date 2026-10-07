# YARA 规则目录

把 `.yar` / `.yara` 文件放这里，重启服务后自动加载（按子目录递归扫描）。

## meta 约定

```yara
rule Example_Rule
{
    meta:
        verdict = "malicious"      # malicious | suspicious | pup，默认 suspicious
        family  = "Emotet"         # 显示在结果列的签名名
        description = "这条规则在查什么"
    strings:
        $a = "suspicious string" ascii
    condition:
        uint16(0) == 0x5A4D and $a   # 0x5A4D = "MZ"，确保是 PE
}
```

`verdict = "malicious"` 的规则命中后，YARA 引擎会报恶意；否则报可疑。
多文件之间用命名空间隔离，标识符冲突不会互相影响。

## 规则来源建议

- [YARA-Rules/rules](https://github.com/Yara-Rules/rules) — 社区大集合
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) — Florian Roth 的规则集，质量很高
- [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) — Elastic 的检测规则（含大量 YARA）
- [Valhalla](https://valhalla.nextron-systems.com/) — 可按家族检索的高质量规则

> 拉取第三方规则集前先确认其许可证。`signature-base` 和 `YARA-Rules` 均为
> 开源，但部分商业规则集不允许再分发。
