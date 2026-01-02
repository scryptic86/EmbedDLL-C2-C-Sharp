rule MALWARE_PowerOverwhelming_Generic_AES
{
    meta:
        confidence = "medium"

    strings:
        $salt = { 01 02 03 04 05 06 07 08 }
        $pbkdf = "Rfc2898DeriveBytes"
        $json = "\"EncryptedMessage\""

    condition:
        $salt and
        $pbkdf and
        $json
}
