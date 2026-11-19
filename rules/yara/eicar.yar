rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file (harmless stand-in for malware in the lab)"
        author = "ForenSight"
        attck = "T1105"
        severity = "High"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar at 0 or $eicar in (0..256)
}
