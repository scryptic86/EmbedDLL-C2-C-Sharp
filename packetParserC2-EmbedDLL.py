#!/usr/bin/env python3
"""
Full C2 Decryption + Parsing Script

Author: Malware Analysis Utility
Use: Decrypts and parses custom AES-encrypted C2 traffic from PCAP files

--------------------------------------------------------------------
USAGE:
    python c2_full_parser.py <pcap_file>

EXAMPLE:
    python c2_full_parser.py traffic.pcapng
--------------------------------------------------------------------
"""

import sys
import json
import struct
from base64 import b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from scapy.all import rdpcap, TCP, Raw


# =========================
# CONFIGURATION
# =========================

PASSWORD = "p0w3r0verwh3lm1ng!".encode("utf-16le")
SALT = bytes([1, 2, 3, 4, 5, 6, 7, 8])
PBKDF2_ITERATIONS = 1000
KEY_LEN = 32


# =========================
# CRYPTO
# =========================

def derive_key():
    """Derive AES key using PBKDF2"""
    key_iv = PBKDF2(
        PASSWORD,
        SALT,
        dkLen=48,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA1
    )
    return key_iv[:KEY_LEN]


def aes_decrypt(ciphertext, iv, key):
    """AES-CBC decrypt without padding removal"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


# =========================
# PCAP EXTRACTION
# =========================

def extract_c2_json_from_pcap(pcap_path):
    """
    Extract base64 JSON C2 blobs from HTTP/TCP payloads
    """
    packets = rdpcap(pcap_path)
    messages = []

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load

            # Look for base64 JSON blobs
            if b'eyJHVUlE' in payload:
                for part in payload.split():
                    try:
                        decoded = b64decode(part)
                        msg = json.loads(decoded)
                        if "EncryptedMessage" in msg:
                            messages.append(msg)
                    except Exception:
                        continue

    return messages


# =========================
# BINARY PARSING
# =========================

def parse_beacon_packet(data):
    """
    Parse initial beacon packet (64 bytes)
    """
    print("[*] Beacon Packet")

    fields = struct.unpack("<IIIIIIIIIIIIIIII", data[:64])

    names = [
        "Beacon ID",
        "Uptime Low",
        "Uptime High",
        "Flags",
        "OS Version",
        "PID",
        "PPID",
        "Architecture",
        "Privilege",
        "Net Status",
        "Unknown1",
        "Unknown2",
        "Checksum",
        "Reserved1",
        "Reserved2",
        "Reserved3"
    ]

    for name, val in zip(names, fields):
        print(f"  {name:15}: 0x{val:08x} ({val})")


def parse_tasking_packet(data):
    """
    Parse tasking / command packets
    """
    offset = 0
    while offset + 8 <= len(data):
        cmd_id, size = struct.unpack("<II", data[offset:offset+8])
        payload = data[offset+8:offset+8+size]

        print(f"[+] Task Command ID: 0x{cmd_id:08x}")
        print(f"    Payload Size : {size}")

        if payload.startswith(b"MZ"):
            extract_dll(payload)

        offset += 8 + size


def parse_response_packet(data):
    """
    Parse command response packets
    """
    cmd_id, status, size = struct.unpack("<III", data[:12])
    payload = data[12:12+size]

    print(f"[+] Response for Command 0x{cmd_id:08x}")
    print(f"    Status: {status}")
    print(f"    Data Length: {size}")

    if payload.startswith(b"MZ"):
        extract_dll(payload)


# =========================
# DLL EXTRACTION
# =========================

def extract_dll(blob):
    """
    Extract embedded DLL payload
    """
    name = f"extracted_{hash(blob) & 0xffffffff:x}.dll"
    with open(name, "wb") as f:
        f.write(blob)

    print(f"[!!!] DLL extracted: {name}")


# =========================
# MAIN PROCESSING
# =========================

def process_message(msg, index):
    print(f"\n========== MESSAGE {index} ==========")

    key = derive_key()
    iv = b64decode(msg["IV"])
    ciphertext = b64decode(msg["EncryptedMessage"])

    plaintext = aes_decrypt(ciphertext, iv, key)

    print(f"[*] Decrypted {len(plaintext)} bytes")

    # Heuristic routing
    if len(plaintext) == 64:
        parse_beacon_packet(plaintext)
    elif plaintext.startswith(b"MZ"):
        extract_dll(plaintext)
    elif plaintext[0:4] == b"\x01\x00\x00\x00":
        parse_tasking_packet(plaintext)
    else:
        parse_response_packet(plaintext)


# =========================
# ENTRY POINT
# =========================

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap file>")
        sys.exit(1)

    pcap_path = sys.argv[1]

    print("[*] Loading PCAP...")
    messages = extract_c2_json_from_pcap(pcap_path)

    print(f"[+] Found {len(messages)} C2 messages")

    for i, msg in enumerate(messages):
        process_message(msg, i)


if __name__ == "__main__":
    main()
