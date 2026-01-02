rule MALWARE_PowerOverwhelming_C2_JSON_Memory
{
    meta:
        description = "Detects decrypted PowerOverwhelming C2 JSON in memory"
        scope = "memory"

    strings:
        $j1 = "\"EncryptedMessage\":\""
        $j2 = "\"IV\":\""
        $j3 = "\"HMAC\":\""
        $j4 = "\"Type\":"

    condition:
        all of them
}
