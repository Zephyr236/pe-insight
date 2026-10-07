/*
    加壳器 / 保护器特征

    加壳本身不是恶意的——很多商业软件也加壳。所以这里全部标 suspicious，
    它的价值是**给分析员指路**：看到加壳就知道静态字符串和导入表不可信，
    应该重点看模拟执行的结果。
*/

import "pe"
import "math"


rule Packer_Known_Section_Names
{
    meta:
        description = "节区名匹配已知加壳器/保护器"
        verdict = "suspicious"
        family = "packer"
    strings:
        $upx0 = ".UPX0" ascii
        $upx1 = ".UPX1" ascii
        $aspack = ".aspack" ascii
        $adata = ".adata" ascii
        $themida = ".themida" ascii
        $vmp0 = ".vmp0" ascii
        $vmp1 = ".vmp1" ascii
        $mpress = ".MPRESS1" ascii
        $petite = ".petite" ascii
        $pec = "pec1" ascii
        $enigma = ".enigma1" ascii
        $nsp = ".nsp0" ascii
        $pklst = ".pklst" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}


rule Packer_Single_HighEntropy_Section
{
    meta:
        description = "单个高熵节区占据镜像主体，典型的壳结构"
        verdict = "suspicious"
        family = "packer"
    condition:
        pe.is_pe and
        pe.number_of_sections > 0 and
        pe.number_of_sections <= 5 and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 32768 and
            math.entropy(
                pe.sections[i].raw_data_offset,
                pe.sections[i].raw_data_size
            ) > 7.5
        )
}


rule Packer_Imports_Only_Loader
{
    meta:
        description = "导入表极小且集中在加载器 API，说明真实导入表被壳隐藏"
        verdict = "suspicious"
        family = "packer"
    strings:
        $l1 = "LoadLibraryA" ascii
        $l2 = "LoadLibraryW" ascii
        $l3 = "GetProcAddress" ascii
        $l4 = "VirtualAlloc" ascii
        $l5 = "VirtualProtect" ascii
    condition:
        pe.is_pe and
        // 导入函数很少，却具备完整的动态解析能力——真实导入表被壳藏起来了
        pe.number_of_imported_functions > 0 and
        pe.number_of_imported_functions <= 20 and
        (2 of ($l*) or ($l3 and $l4))
}


rule Packer_Tiny_Import_Table_Small_Binary
{
    meta:
        description = "体积极小却几乎没有导入表，疑似加壳的加载器/投放器"
        verdict = "suspicious"
        family = "dropper"
    condition:
        pe.is_pe and
        filesize < 65536 and
        pe.number_of_imported_functions <= 12 and
        pe.number_of_sections <= 4
}
