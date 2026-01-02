rule MALWARE_PowerOverwhelming_Embedded_DLL_Loader
{
    meta:
        description = "Detects embedded DLL reflection loader"

    strings:
        $res1 = ".rsrc"
        $res2 = "EmbedDLL.dll"
        $load = "Assembly.Load"

    condition:
        uint16(0) == 0x5A4D and
        all of ($res*) and
        $load
}
