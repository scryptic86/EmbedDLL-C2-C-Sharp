rule MALWARE_PowerOverwhelming_Encrypted_Beacon
{
    meta:
        description = "Detects encrypted 64-byte beacon payloads"
        scope = "network"

    strings:
        /* base64-encoded IV length = 24 chars */
        $iv = /"IV":"[A-Za-z0-9+\/]{22}=="/

        /* Encrypted message usually > 400 bytes */
        $msg = /"EncryptedMessage":"[A-Za-z0-9+\/]{400,}=="/

    condition:
        $iv and $msg
}
