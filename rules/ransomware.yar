/*
    勒索软件特征

    勒索样本的行为高度趋同，所以特征也相对可靠：
    加密 API 组合 + 影子副本删除 + 勒索信文案。

    注意"加密 API 组合"单独不足以定性——合法的加密软件（压缩、备份、
    密码管理器）也会用同一批 API。所以这里要求它和破坏性行为同时出现。
*/

import "pe"


rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "通过命令行删除卷影副本与备份——勒索软件的标准前置动作"
        verdict = "malicious"
        family = "ransomware"
        reference = "https://attack.mitre.org/techniques/T1490/"
    strings:
        $a = "vssadmin" ascii wide nocase
        $b = "delete shadows" ascii wide nocase
        $c = "wbadmin" ascii wide nocase
        $d = "delete catalog" ascii wide nocase
        $e = "WMI" ascii wide nocase
        $f = "Win32_ShadowCopy" ascii wide nocase
        $g = "bcdedit" ascii wide nocase
        $h = "recoveryenabled no" ascii wide nocase
        $i = "resize shadowstorage" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (
            ($a and $b) or
            ($c and $d) or
            ($e and $f) or
            ($g and $h) or
            ($a and $i)
        )
}


rule Ransomware_Note_Strings
{
    meta:
        description = "包含勒索信典型文案"
        verdict = "malicious"
        family = "ransomware"
    strings:
        $a1 = "your files have been encrypted" ascii wide nocase
        $a2 = "all your files are encrypted" ascii wide nocase
        $a3 = "your documents, photos, databases" ascii wide nocase
        $a4 = "to decrypt your files" ascii wide nocase
        $a5 = "send bitcoin" ascii wide nocase
        $a6 = "decryption key" ascii wide nocase
        $a7 = "do not rename encrypted files" ascii wide nocase
        $a8 = "you have 72 hours" ascii wide nocase
        $a9 = "tor browser" ascii wide nocase
        $b1 = "README_FOR_DECRYPT" ascii wide nocase
        $b2 = "HOW_TO_DECRYPT" ascii wide nocase
        $b3 = "RECOVER_YOUR_FILES" ascii wide nocase
        $b4 = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        // 勒索信文案的误报风险极低，两条即可判定
        2 of them
}


rule Ransomware_Crypto_Plus_Destruction
{
    meta:
        description = "加密 API 与文件枚举/销毁组合出现，疑似批量加密文件"
        verdict = "suspicious"
        family = "ransomware"
        reference = "https://attack.mitre.org/techniques/T1486/"
    strings:
        $c1 = "CryptEncrypt" ascii
        $c2 = "CryptGenKey" ascii
        $c3 = "CryptAcquireContext" ascii
        $c4 = "BCryptEncrypt" ascii
        $f1 = "FindFirstFile" ascii
        $f2 = "FindNextFile" ascii
        $f3 = "MoveFile" ascii
        $f4 = "DeleteFile" ascii
    condition:
        uint16(0) == 0x5A4D and
        // 必须同时具备"加密能力"和"批量文件遍历"两个要素
        2 of ($c*) and 2 of ($f*)
}


rule Ransomware_Extension_Targeting
{
    meta:
        description = "硬编码大量文档扩展名，典型的批量加密目标列表"
        verdict = "suspicious"
        family = "ransomware"
    strings:
        $e1 = ".doc" ascii wide
        $e2 = ".xls" ascii wide
        $e3 = ".pdf" ascii wide
        $e4 = ".jpg" ascii wide
        $e5 = ".zip" ascii wide
        $e6 = ".sql" ascii wide
        $e7 = ".mdb" ascii wide
        $e8 = ".ppt" ascii wide
        $e9 = ".dwg" ascii wide
        $e10 = ".psd" ascii wide
        $e11 = ".raw" ascii wide
        $e12 = ".vmdk" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        // 需要凑齐 8 种以上文档扩展名——正常程序不会硬编码这么长的清单
        8 of them
}
