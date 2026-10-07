/*
    通用启发式规则集 — 起步模板

    这些规则刻意写得宽泛，用来演示规则格式并覆盖几类最常见的恶意特征。
    生产环境请叠加真实情报规则（例如来自 YARA-Rules、Valhalla、Sigma 转换等）。

    meta 约定：
        verdict = "malicious" | "suspicious" | "pup"   默认 suspicious
        family  = 家族名（会显示在结果列）
*/

import "pe"
import "math"


rule Generic_HighEntropy_Packed_Sections
{
    meta:
        description = "存在高熵节区，疑似加壳或加密载荷"
        verdict = "suspicious"
        family = "packer"
        reference = "https://attack.mitre.org/techniques/T1027/002/"
    condition:
        pe.is_pe and
        pe.number_of_sections > 0 and
        // 熵由 math.entropy(offset, size) 计算——pe 模块本身不暴露节区熵字段
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 8192 and
            math.entropy(
                pe.sections[i].raw_data_offset,
                pe.sections[i].raw_data_size
            ) > 7.2
        )
}


rule Generic_Process_Injection_API_Set
{
    meta:
        description = "导入表中同时出现进程注入所需的核心 API"
        verdict = "malicious"
        family = "process_injection"
        reference = "https://attack.mitre.org/techniques/T1055/"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
        $d = "NtUnmapViewOfSection" ascii
        $e = "SetThreadContext" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($a, $b, $c, $d, $e)
}


rule Generic_Registry_Run_Persistence
{
    meta:
        description = "包含注册表自启动项路径"
        verdict = "suspicious"
        family = "persistence"
        reference = "https://attack.mitre.org/techniques/T1547/001/"
    strings:
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $run3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}


rule Generic_Anti_Debug_Techniques
{
    meta:
        description = "使用罕见的反调试技术组合，常见于加壳器和恶意样本"
        verdict = "suspicious"
        family = "anti_analysis"
        reference = "https://attack.mitre.org/techniques/T1622/"
    strings:
        // 这些才是"有意隐藏自己"的信号。IsDebuggerPresent / OutputDebugString /
        // QueryPerformanceCounter 在正常程序里极其常见，单独出现不构成线索——
        // 早期版本把它们计入阈值，结果在 notepad.exe 上就误报了。
        $qip = "NtQueryInformationProcess" ascii
        $sit = "NtSetInformationThread" ascii      // ThreadHideFromDebugger
        $obj = "NtQueryObject" ascii               // DebugObject 句柄探测
        $dip = "IsDebuggerPresent" ascii
        $cdp = "CheckRemoteDebuggerPresent" ascii
    condition:
        uint16(0) == 0x5A4D and (
            // 两种非常见技术的组合，或
            2 of ($qip, $sit, $obj) or
            // 常见 API 与非常见技术的搭配
            (($dip or $cdp) and ($qip or $sit))
        )
}


rule Generic_Download_And_Execute
{
    meta:
        description = "同时具备下载与执行能力的 API 组合"
        verdict = "malicious"
        family = "downloader"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $dl1 = "URLDownloadToFile" ascii
        $dl2 = "InternetOpenUrl" ascii
        $dl3 = "InternetReadFile" ascii
        $ex1 = "ShellExecute" ascii
        $ex2 = "WinExec" ascii
        $ex3 = "CreateProcess" ascii
    condition:
        uint16(0) == 0x5A4D and any of ($dl*) and any of ($ex*)
}


rule Generic_Crypto_Ransomware_API_Set
{
    meta:
        description = "导入表中出现加密 API 组合，疑似勒索行为"
        verdict = "suspicious"
        family = "ransomware"
        reference = "https://attack.mitre.org/techniques/T1486/"
    strings:
        $a = "CryptEncrypt" ascii
        $b = "CryptGenKey" ascii
        $c = "CryptAcquireContext" ascii
        $d = "CryptImportKey" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}


rule Generic_Known_Packer_Sections
{
    meta:
        description = "节区名匹配已知加壳器"
        verdict = "suspicious"
        family = "packer"
    strings:
        $upx = ".UPX0" ascii
        $aspack = ".aspack" ascii
        $themida = ".themida" ascii
        $vmp = ".vmp0" ascii
        $mpress = ".MPRESS1" ascii
        $petite = ".petite" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}


rule Generic_PowerShell_Encoded_Command
{
    meta:
        description = "包含 PowerShell 编码命令参数，常见于无文件攻击载荷"
        verdict = "suspicious"
        family = "powershell"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $byp = "-ExecutionPolicy Bypass" ascii wide nocase
        $hid = "-WindowStyle Hidden" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and $ps and 2 of ($enc1, $enc2, $byp, $hid)
}
