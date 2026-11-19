rule Suspicious_PowerShell_Cradle
{
    meta:
        description = "PowerShell script that downloads and executes code"
        author = "ForenSight"
        attck = "T1059.001"
    strings:
        $d1 = "DownloadString" nocase
        $d2 = "DownloadFile" nocase
        $d3 = "Invoke-WebRequest" nocase
        $x1 = "IEX" nocase
        $x2 = "Invoke-Expression" nocase
        $x3 = "FromBase64String" nocase
    condition:
        filesize < 2MB and any of ($d*) and any of ($x*)
}

rule Reverse_Shell_Script
{
    meta:
        description = "Script containing a reverse-shell one-liner"
        author = "ForenSight"
        attck = "T1059"
    strings:
        $b1 = "/dev/tcp/" ascii
        $b2 = "bash -i" ascii
        $n1 = "nc -e" ascii
        $p1 = "Net.Sockets.TCPClient" ascii nocase
        $p2 = "GetStream()" ascii nocase
    condition:
        filesize < 2MB and (($b1 and $b2) or $n1 or ($p1 and $p2))
}
