#!/usr/bin/env python3
"""
decrypt_laps.py - Decrypt Windows LAPS v2 (msLAPS-EncryptedPassword /
msLAPS-EncryptedPasswordHistory) blob(s).

Takes bloodyAD's `msldap laps` output - either the hex form of
msLAPS-EncryptedPassword, or the Python list-of-bytes repr of
msLAPS-EncryptedPasswordHistory (multiple previous rotations) - and decrypts
every blob found via MS-GKDI, using the dpapi-ng library to do the actual
RPC / crypto work. A single DC round-trip's worth of key material is reused
across all blobs when they share the same root key, so a whole history list
decrypts fast after the first blob.

msLAPS-EncryptedPassword layout (MS-ADA2 2.66):
    PasswordUpdateTimestamp : 8 bytes (dwHighDateTime, then dwLowDateTime; each 4-byte LE)
    EncryptedPasswordSize   : 4 bytes (little-endian uint32)
    Reserved                : 4 bytes
    EncryptedPassword       : variable (this is the actual DPAPI-NG / CMS blob)

The decrypted output is a JSON string: {"n": "...", "t": "...", "p": "..."}
  n = account name, t = timestamp (hex FILETIME), p = the plaintext password

Usage:
    python3 decrypt_laps.py <blob_or_line> [-s DC_HOST] [-u USER] [-p PASSWORD] [-k]
    python3 decrypt_laps.py -f bloodyad_output.txt [-s DC_HOST] -k

Examples:
    # Whole bloodyAD output file (current password + history list), Kerberos auth
    python3 decrypt_laps.py -f lapspasswords.txt -s dc01.trask.hsm -k

    # Single hex blob, explicit creds
    python3 decrypt_laps.py "SENTINEL-PROTO : 6caadc01...4a" \\
        -s dc01.trask.hsm -u e.parsons -p 'W3lcm2Tr4sk1988!'

    # Just validate/parse without contacting the DC
    python3 decrypt_laps.py -f lapspasswords.txt --no-decrypt
"""

import argparse
import ast
import json
import re
import struct
import sys

import dpapi_ng


def _extract_py_bytes_literals(raw: str):
    """Find every b'...'/b"..." Python bytes-literal substring in raw text
    (bloodyAD sometimes prints attribute values as a Python list-of-bytes
    repr, e.g. "[b'k\\xaa\\xdc...', b'...']") and safely eval each one."""
    literals = []
    i = 0
    n = len(raw)
    while i < n:
        if raw[i] == "b" and i + 1 < n and raw[i + 1] in ("'", '"'):
            quote = raw[i + 1]
            j = i + 2
            escaped = False
            while j < n:
                c = raw[j]
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == quote:
                    break
                j += 1
            if j < n:
                literal_src = raw[i : j + 1]
                try:
                    val = ast.literal_eval(literal_src)
                    if isinstance(val, bytes):
                        literals.append(val)
                except (ValueError, SyntaxError):
                    pass
                i = j + 1
                continue
        i += 1
    return literals


def _extract_hex_blobs(raw: str):
    """Find hex-string blobs, one per line, in the "NAME : <hex>" format
    (or a bare hex string on its own line). Only lines that are entirely
    hex after stripping a 'NAME :' prefix are treated as blobs, so this
    safely skips lines that contain Python list/bytes reprs instead."""
    blobs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        text = line
        if ":" in text:
            text = text.split(":", 1)[1].strip()
        text = re.sub(r"\s+", "", text)
        if text and re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) % 2 == 0:
            blobs.append(bytes.fromhex(text))
    return blobs


def parse_blobs(raw: str):
    """Pull every LAPS blob candidate out of raw input. Accepts, in any
    combination, possibly across multiple lines:
      - hex strings, optionally prefixed with 'NAME : '
      - Python bytes-literal(s) or a list-of-bytes-literals repr, as
        bloodyAD's msldap laps prints msLAPS-EncryptedPasswordHistory,
        e.g. "NAME : [b'k\\xaa\\xdc...', b'...']"
    Returns a list of raw blob bytes (16-byte header + CMS payload each),
    in the order found. Raises ValueError if nothing recognizable is found.
    """
    raw = raw.strip()
    blobs = []
    blobs.extend(_extract_py_bytes_literals(raw))
    blobs.extend(_extract_hex_blobs(raw))

    if not blobs:
        raise ValueError(
            "No hex string or Python bytes literal found in the input. "
            "Expected bloodyAD's 'msldap laps' output (hex or [b'...'] form)."
        )
    return blobs


def strip_header(blob: bytes):
    """Split off the 16-byte MS-ADA2 header, return (timestamp_int, encrypted_password_bytes).

    The 8-byte timestamp is stored as dwHighDateTime (4 bytes LE) followed by
    dwLowDateTime (4 bytes LE) - NOT as one flat little-endian uint64 - so the
    two 32-bit halves are read separately and reassembled.
    """
    if len(blob) <= 16:
        raise ValueError(f"Blob too short ({len(blob)} bytes) to contain the 16-byte header")

    ts_high = struct.unpack("<I", blob[0:4])[0]
    ts_low = struct.unpack("<I", blob[4:8])[0]
    timestamp = (ts_high << 32) | ts_low
    enc_size = struct.unpack("<I", blob[8:12])[0]
    # blob[12:16] is Reserved, ignored
    encrypted_password = blob[16:]

    if enc_size and enc_size != len(encrypted_password):
        # Not fatal - some tools / versions have been inconsistent here - just warn.
        print(
            f"    [!] Warning: header EncryptedPasswordSize={enc_size} but "
            f"remaining bytes={len(encrypted_password)}; continuing anyway",
            file=sys.stderr,
        )

    return timestamp, encrypted_password


def filetime_to_str(filetime: int) -> str:
    if not filetime:
        return "N/A"
    # FILETIME: 100-ns intervals since 1601-01-01
    from datetime import datetime, timedelta

    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, ValueError):
        return f"raw={filetime}"


def decrypt_one(index, total, raw_blob, args, cache):
    print(f"[{index}/{total}] " + "-" * 60)

    try:
        timestamp, enc_password = strip_header(raw_blob)
    except ValueError as e:
        print(f"    [-] {e}")
        return None

    print(f"    Blob size: {len(raw_blob)} bytes (header 16 + payload {len(enc_password)})")
    print(f"    PasswordUpdateTimestamp: {filetime_to_str(timestamp)}")
    cms_ok = enc_password[:1] == b"\x30"
    cms_note = "CMS SEQUENCE tag OK" if cms_ok else "WARNING: does not look like a CMS blob (should start with 0x30)"
    print(f"    Payload starts with: {enc_password[:8].hex()} ({cms_note})")

    if args.no_decrypt:
        return None

    auth_protocol = "kerberos" if args.kerberos else "negotiate"

    try:
        decrypted = dpapi_ng.ncrypt_unprotect_secret(
            enc_password,
            server=args.server,
            username=args.username,
            password=args.password,
            auth_protocol=auth_protocol,
            cache=cache,
        )
    except Exception as e:
        print(f"    [-] Decryption failed: {e}")
        print(
            "        Common causes: wrong/insufficient creds (need rights to read the "
            "LAPS-protected group key), wrong -s/DC, or clock skew (Kerberos)."
        )
        return None

    text = decrypted.decode("utf-16-le", errors="replace").rstrip("\x00")
    result = {"timestamp": filetime_to_str(timestamp), "raw_text": text}

    try:
        data = json.loads(text)
        result["account"] = data.get("n")
        result["password"] = data.get("p")
        print(f"    [+] Account : {data.get('n')}")
        print(f"    [+] Password: {data.get('p')}")
    except json.JSONDecodeError:
        print(f"    [+] Decrypted (raw, not JSON): {text}")

    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("blob", nargs="?", help="Hex LAPS blob, or the full 'NAME : hex' / 'NAME : [b\"...\"]' line from bloodyAD")
    ap.add_argument("-f", "--file", help="Read the blob(s) from a file instead of the command line "
                                          "(recommended - paste bloodyAD's raw output into a file first "
                                          "to avoid paste truncation). Can contain both the current "
                                          "hex password and a [b'...', ...] history list; every blob "
                                          "found is decrypted.")
    ap.add_argument("-s", "--server", help="DC hostname/IP to query for the MS-GKDI key (recommended - skips SRV lookup)")
    ap.add_argument("-u", "--username", help="Username for auth (e.g. user@domain.com or DOMAIN\\\\user)")
    ap.add_argument("-p", "--password", help="Password for auth")
    ap.add_argument("-k", "--kerberos", action="store_true",
                     help="Use existing Kerberos ticket (run kinit first) instead of -u/-p, like bloodyAD's -k")
    ap.add_argument("--no-decrypt", action="store_true",
                     help="Only parse/validate the blob(s) (show size, timestamp, CMS header) without contacting the DC")
    args = ap.parse_args()

    if args.kerberos and (args.username or args.password):
        ap.error("-k/--kerberos cannot be combined with -u/-p; kinit first and just pass -k")

    if bool(args.blob) == bool(args.file):
        ap.error("provide exactly one of: the blob as a positional argument, or -f/--file")

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            input_text = fh.read()
    else:
        input_text = args.blob

    try:
        raw_blobs = parse_blobs(input_text)
    except ValueError as e:
        print(f"[-] {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Found {len(raw_blobs)} blob(s) to process.")
    if not args.no_decrypt and not args.server:
        print("[!] No -s/--server given; will try SRV lookup for the DC (may fail in a lab without proper DNS)", file=sys.stderr)

    cache = dpapi_ng.KeyCache()
    results = []
    for idx, raw_blob in enumerate(raw_blobs, start=1):
        r = decrypt_one(idx, len(raw_blobs), raw_blob, args, cache)
        if r:
            results.append(r)

    if not args.no_decrypt:
        print("=" * 62)
        print(f"[+] Decrypted {len(results)}/{len(raw_blobs)} blob(s):")
        for r in results:
            print(f"    {r['timestamp']}  ->  {r.get('password', r['raw_text'])}")


if __name__ == "__main__":
    main()
