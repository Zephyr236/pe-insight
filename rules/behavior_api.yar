/*
    行为 API 组合规则

    设计原则（吃过亏）：**不要用"若干个常见 API 出现 N 次"当条件**。
    IsDebuggerPresent、OutputDebugString、QueryPerformanceCounter 这类
    API 在正常程序里到处都是，早期版本用阈值判定，结果在 notepad.exe 上
    就误报了。这里的每条规则都要求出现**罕见且有明确意图**的 API 或
    字符串组合。

    meta 约定：
        verdict = "malicious" | "suspicious" | "pup"   默认 suspicious
        family  = 家族/类别名（结果显示用）
*/

import "pe"


rule Behavior_Process_Injection_Core
{
    meta:
        description = "同时具备远程内存分配、写入与远程线程创建——进程注入的最小完整链条"
        verdict = "malicious"
        family = "process_injection"
        reference = "https://attack.mitre.org/techniques/T1055/"
    strings:
        $alloc = "VirtualAllocEx" ascii
        $write = "WriteProcessMemory" ascii
        $thread = "CreateRemoteThread" ascii
        $apc = "QueueUserAPC" ascii
        $ctx = "SetThreadContext" ascii
    condition:
        uint16(0) == 0x5A4D and
        // 必须凑齐"分配 + 写入 + 触发执行"三步，缺一不可
        $alloc and $write and ($thread or $apc or $ctx)
}


rule Behavior_Process_Hollowing
{
    meta:
        description = "进程镂空（Process Hollowing）的典型 API 组合"
        verdict = "malicious"
        family = "process_hollowing"
        reference = "https://attack.mitre.org/techniques/T1055/012/"
    strings:
        $a = "NtUnmapViewOfSection" ascii
        $b = "ZwUnmapViewOfSection" ascii
        $c = "CreateProcessInternalW" ascii
        $d = "SetThreadContext" ascii
        $e = "ResumeThread" ascii
        $f = "NtWriteVirtualMemory" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($a or $b) and ($c or $f) and ($d or $e)
}


rule Behavior_Keylogging_API_Set
{
    meta:
        description = "键盘状态轮询 + 钩子安装，疑似键盘记录"
        verdict = "suspicious"
        family = "keylogger"
        reference = "https://attack.mitre.org/techniques/T1056/001/"
    strings:
        $hook = "SetWindowsHookEx" ascii
        $state1 = "GetAsyncKeyState" ascii
        $state2 = "GetKeyboardState" ascii
        $state3 = "GetKeyNameText" ascii
        $map = "MapVirtualKey" ascii
    condition:
        uint16(0) == 0x5A4D and
        // 钩子 + 两种以上键盘读取，或三种键盘读取 API 同时出现
        ($hook and 1 of ($state1, $state2) and $map) or
        (2 of ($state1, $state2) and $map and $state3)
}


rule Behavior_Credential_Dumping_LSASS
{
    meta:
        description = "包含 LSASS 内存转储相关字符串，疑似凭据窃取"
        verdict = "malicious"
        family = "credential_access"
        reference = "https://attack.mitre.org/techniques/T1003/001/"
    strings:
        $lsass = "lsass.exe" ascii wide nocase
        $dump1 = "MiniDumpWriteDump" ascii
        $dump2 = "dbghelp" ascii wide nocase
        $dump3 = "MiniDumpWithFullMemory" ascii
        $procdump = "procdump" ascii wide nocase
        $sekurlsa = "sekurlsa" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        // lsass 目标 + 转储能力，或 procdump 式调用，或 mimikatz 风格模块名
        ($lsass and ($dump1 or $dump3)) or
        ($lsass and $procdump) or
        ($dump1 and $dump2 and $dump3) or
        $sekurlsa
}


rule Behavior_Download_And_Execute
{
    meta:
        description = "同时具备网络下载与本地执行能力"
        verdict = "malicious"
        family = "downloader"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $d1 = "URLDownloadToFile" ascii
        $d2 = "InternetReadFile" ascii
        $d3 = "WinHttpReadData" ascii
        $d4 = "InternetOpenUrl" ascii
        $e1 = "ShellExecute" ascii
        $e2 = "WinExec" ascii
        $e3 = "CreateProcess" ascii
    condition:
        uint16(0) == 0x5A4D and
        // 至少两个下载 API 才排除掉普通程序里偶尔出现的单个调用
        2 of ($d*) and 1 of ($e*)
}


rule Behavior_Service_Persistence
{
    meta:
        description = "通过 Windows 服务实现持久化"
        verdict = "suspicious"
        family = "persistence"
        reference = "https://attack.mitre.org/techniques/T1543/003/"
    strings:
        $scm = "OpenSCManager" ascii
        $svc1 = "CreateService" ascii
        $svc2 = "ChangeServiceConfig" ascii
        $desc = "ServiceDll" ascii wide
    condition:
        uint16(0) == 0x5A4D and $scm and ($svc1 or $svc2) and $desc
}


rule Behavior_Anti_VM_Detection
{
    meta:
        description = "探测虚拟机/沙箱环境，常见于规避自动化分析的样本"
        verdict = "suspicious"
        family = "anti_analysis"
        reference = "https://attack.mitre.org/techniques/T1497/001/"
    strings:
        $v1 = "VBoxService" ascii wide nocase
        $v2 = "VBoxTray" ascii wide nocase
        $v3 = "vmware" ascii wide nocase
        $v4 = "vmtoolsd" ascii wide nocase
        $v5 = "SbieDll" ascii wide nocase
        $v6 = "wine_get_unix_file_name" ascii
        $v7 = "sandboxie" ascii wide nocase
        $v8 = "cuckoo" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        // 命中两个以上不同厂商的虚拟机特征才算——出现单个可能是正常软件
        // 在做虚拟化兼容性检查
        2 of them
}


rule Behavior_Evasion_Disable_Security
{
    meta:
        description = "尝试关闭安全防护（Defender/防火墙/事件日志）"
        verdict = "malicious"
        family = "defense_evasion"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = "DisableRealtimeMonitoring" ascii wide
        $b = "Set-MpPreference" ascii wide nocase
        $c = "netsh advfirewall set" ascii wide nocase
        $d = "WinDefend" ascii wide
        $e = "vssadmin delete shadows" ascii wide nocase
        $f = "wbadmin delete catalog" ascii wide nocase
        $g = "bcdedit /set" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        // 两条以上独立的关闭防护动作，排除掉安全软件自身的管理接口
        2 of them
}


rule Behavior_Inject_Via_Section
{
    meta:
        description = "通过节区映射注入（比 CreateRemoteThread 更隐蔽）"
        verdict = "suspicious"
        family = "process_injection"
        reference = "https://attack.mitre.org/techniques/T1055/002/"
    strings:
        $a = "NtCreateSection" ascii
        $b = "NtMapViewOfSection" ascii
        $c = "ZwMapViewOfSection" ascii
        $d = "NtUnmapViewOfSection" ascii
        $e = "SEC_IMAGE" ascii wide
    condition:
        uint16(0) == 0x5A4D and $a and ($b or $c) and ($d or $e)
}
