rule Malyx_EICAR_Test_File
{
    meta:
        author = "MalyxScanner"
        description = "EICAR standard antivirus test file"
        severity = "critical"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Malyx_Process_Injection_APIs
{
    meta:
        author = "MalyxScanner"
        description = "Executable referencing multiple process injection APIs"
        severity = "high"
    strings:
        $a1 = "WriteProcessMemory" ascii
        $a2 = "VirtualAllocEx" ascii
        $a3 = "CreateRemoteThread" ascii
        $a4 = "NtUnmapViewOfSection" ascii
        $a5 = "QueueUserAPC" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Malyx_Downloader_Behavior
{
    meta:
        author = "MalyxScanner"
        description = "Executable combining download and execution APIs"
        severity = "high"
    strings:
        $u1 = "URLDownloadToFileA" ascii
        $u2 = "URLDownloadToFileW" ascii
        $u3 = "InternetOpenUrlA" ascii
        $e1 = "WinExec" ascii
        $e2 = "ShellExecute" ascii
    condition:
        uint16(0) == 0x5A4D and any of ($u*) and any of ($e*)
}

rule Malyx_UPX_Packed
{
    meta:
        author = "MalyxScanner"
        description = "UPX packed executable"
        severity = "low"
    strings:
        $a = "UPX0" ascii
        $b = "UPX1" ascii
        $c = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Malyx_PowerShell_Encoded_Command
{
    meta:
        author = "MalyxScanner"
        description = "Encoded PowerShell command frequently used by droppers"
        severity = "medium"
    strings:
        $a = "-enc " nocase ascii wide
        $b = "-encodedcommand" nocase ascii wide
        $c = "frombase64string" nocase ascii wide
        $d = "-w hidden" nocase ascii wide
    condition:
        filesize < 20MB and 2 of them
}

rule Malyx_Macro_AutoOpen_Hooks
{
    meta:
        author = "MalyxScanner"
        description = "Office document containing macro auto-execution hooks"
        severity = "medium"
    strings:
        $a = "AutoOpen" nocase ascii wide
        $b = "Document_Open" nocase ascii wide
        $c = "Auto_Close" nocase ascii wide
        $d = "Workbook_Open" nocase ascii wide
    condition:
        filesize < 50MB and any of them
}
