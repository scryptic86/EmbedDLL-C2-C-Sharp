rule MALWARE_PowerOverwhelming_AES_C2
{
    meta:
        author = "honeybucket"
        description = "Detects PowerOverwhelming malware AES-C2 implementation"
        confidence = "high"
        malware_family = "unknown .NET backdoor"
        last_updated = "2026-01-01"

    strings:
        /* Password (UTF-16LE) */
        $pwd = "p0w3r0verwh3lm1ng!" wide

        /* PBKDF2 salt */
        $salt = { 01 02 03 04 05 06 07 08 }

        /* .NET crypto */
        $rij = "RijndaelManaged"
        $pbkdf = "Rfc2898DeriveBytes"

        /* JSON C2 fields */
        $json1 = "\"EncryptedMessage\""
        $json2 = "\"IV\""
        $json3 = "\"HMAC\""
        $json4 = "\"GUID\""

        /* Reflection loading */
        $reflect = "System.Reflection"

    condition:
        uint16(0) == 0x5A4D and   // PE
        all of ($json*) and
        $salt and
        $pwd and
        2 of ($rij, $pbkdf, $reflect)
}
