#!/usr/bin/env python3
"""Small, local alert outbox. Python 3.10+, standard library only.

No listener, cloud provisioning, token creation, or automatic incident response.
Read references/alerts.md before running against a real destination.
"""
import argparse
import datetime as dt
import email.utils
from email.message import EmailMessage
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import smtplib
import sqlite3
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_FILE = 16 * 1024 * 1024
MAX_EVENTS = 10000
INTERACTIONS = {"http_request", "tool_call", "client_connect", "file_changed",
                "file_deleted", "file_replaced", "file_restored", "delivery_test"}
LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")


class ConfigError(ValueError):
    """Only locally authored, secret-free messages may use this exception."""


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def label(value):
    if not isinstance(value, str) or not LABEL.fullmatch(value):
        raise ConfigError("Use a nonsecret label: 1-64 letters, digits, spaces, _, . or -")
    return value


def _windows_current_user_sid_string():
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ConfigError("Unable to inspect Windows security token")
    try:
        length = wintypes.DWORD(0)
        if advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(length)):
            raise ConfigError("Unable to inspect Windows security token")
        if kernel32.GetLastError() != 122 or length.value == 0:
            raise ConfigError("Unable to inspect Windows security token")
        buffer = ctypes.create_string_buffer(length.value)
        if not advapi32.GetTokenInformation(token, 1, buffer, length.value, ctypes.byref(length)):
            raise ConfigError("Unable to inspect Windows security token")
        sid_ptr = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        string = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(string)):
            raise ConfigError("Unable to inspect Windows security token")
        try:
            return string.value
        finally:
            kernel32.LocalFree(ctypes.cast(string, ctypes.c_void_p))
    finally:
        kernel32.CloseHandle(token)


def _string_to_sid(value):
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    sid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(str(value), ctypes.byref(sid)):
        raise ConfigError("Unable to parse Windows security identifier")
    return sid.value


def _sid_to_string(sid_ptr):
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    string = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(string)):
        return None
    try:
        return string.value
    finally:
        kernel32.LocalFree(ctypes.cast(string, ctypes.c_void_p))


def _approved_windows_sid_strings():
    return [_windows_current_user_sid_string(), "S-1-5-18", "S-1-5-32-544"]


def _is_windows_reparse_point(path):
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.windll.kernel32
    kernel32.GetFileAttributesW.restype = wintypes.DWORD
    kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    attrs = kernel32.GetFileAttributesW(str(path))
    if attrs == 0xFFFFFFFF:
        error = kernel32.GetLastError()
        if error in (2, 3):  # file/path not found
            return False
        raise ConfigError("Unable to inspect Windows reparse point")
    return bool(attrs & 0x00000400)


def _windows_security_descriptor(path):
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.windll.advapi32
    advapi32.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetFileSecurityW.restype = wintypes.BOOL
    needed = wintypes.DWORD(0)
    kernel32 = ctypes.windll.kernel32
    kernel32.GetLastError.restype = wintypes.DWORD
    if advapi32.GetFileSecurityW(str(path), 0x00000004 | 0x00000001, None, 0, ctypes.byref(needed)):
        raise ConfigError("Unable to inspect Windows access control")
    if kernel32.GetLastError() != 122 or needed.value == 0:
        raise ConfigError("Unable to inspect Windows access control")
    buffer = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetFileSecurityW(str(path), 0x00000004 | 0x00000001, buffer, needed.value, ctypes.byref(needed)):
        raise ConfigError("Unable to inspect Windows access control")
    return buffer


def _validate_windows_acl(path, directory=None):
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes
    p = Path(path)
    if p.is_symlink() or _is_windows_reparse_point(p):
        raise ConfigError("State path must not be a symlink or reparse point")
    try:
        sd_buffer = _windows_security_descriptor(p)
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        advapi32.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
        advapi32.GetSecurityDescriptorOwner.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
        advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
        advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        advapi32.GetAce.restype = wintypes.BOOL
        advapi32.IsValidSid.argtypes = [ctypes.c_void_p]
        advapi32.IsValidSid.restype = wintypes.BOOL
        advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
        advapi32.GetLengthSid.restype = wintypes.DWORD
        dacl = ctypes.c_void_p()
        dacl_present = wintypes.BOOL()
        dacl_defaulted = wintypes.BOOL()
        owner = ctypes.c_void_p()
        owner_defaulted = wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorDacl(sd_buffer, ctypes.byref(dacl_present), ctypes.byref(dacl), ctypes.byref(dacl_defaulted)):
            raise ConfigError("Unable to inspect Windows access control")
        if not dacl_present.value or not dacl.value:
            raise ConfigError("State permissions are unsafe. Restrict access to your Windows user, SYSTEM and Administrators before continuing.")
        if not advapi32.GetSecurityDescriptorOwner(sd_buffer, ctypes.byref(owner), ctypes.byref(owner_defaulted)):
            raise ConfigError("Unable to inspect Windows access control")
        if not owner.value:
            raise ConfigError("State permissions are unsafe. Restrict access to your Windows user, SYSTEM and Administrators before continuing.")
        approved_strings = set(_approved_windows_sid_strings())
        owner_string = _sid_to_string(owner.value)
        if owner_string not in approved_strings:
            raise ConfigError("State permissions are unsafe. Restrict access to your Windows user, SYSTEM and Administrators before continuing.")
        class _ACL(ctypes.Structure):
            _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte),
                        ("AclSize", ctypes.c_ushort), ("AceCount", ctypes.c_ushort),
                        ("Sbz2", ctypes.c_ushort)]
        acl_struct = ctypes.cast(dacl, ctypes.POINTER(_ACL)).contents
        if acl_struct.AclSize < 8 or acl_struct.AceCount == 0 or acl_struct.AceCount > 1024:
            raise ConfigError("Unable to inspect Windows access control")
        acl_base = ctypes.cast(dacl, ctypes.c_void_p).value
        acl_limit = acl_base + acl_struct.AclSize
        for i in range(acl_struct.AceCount):
            ace_ptr = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, i, ctypes.byref(ace_ptr)):
                raise ConfigError("Unable to inspect Windows access control")
            if not ace_ptr.value or ace_ptr.value < acl_base or ace_ptr.value + 4 > acl_limit:
                raise ConfigError("Unable to inspect Windows access control")
            header = ctypes.cast(ace_ptr, ctypes.POINTER(ctypes.c_ubyte * 4)).contents
            ace_type = header[0]
            ace_flags = header[1]
            ace_size = int.from_bytes(bytes(header[2:4]), "little")
            if ace_size < 8 or ace_ptr.value + ace_size > acl_limit:
                raise ConfigError("Unable to inspect Windows access control")
            # Only standard access-allowed ACEs with a full-control mask are
            # supported. Deny, object, callback and audit ACEs fail closed.
            if ace_type != 0:
                raise ConfigError("State permissions are unsafe. Restrict access to your Windows user, SYSTEM and Administrators before continuing.")
            access_mask = int.from_bytes(bytes(ctypes.cast(
                ace_ptr, ctypes.POINTER(ctypes.c_ubyte * 8)).contents[4:8]), "little")
            if access_mask != 0x10000000:  # GENERIC_ALL, as emitted by _apply_windows_acl
                raise ConfigError("State permissions are unsafe. Restrict access to your Windows user, SYSTEM and Administrators before continuing.")
            # The helper creates inheritable directory ACEs (OI|CI) and
            # non-inheritable file ACEs. Inherited ACEs may carry INHERITED_ACE.
            allowed_flags = ({0x03, 0x13} if directory is True else
                             {0x00, 0x10, 0x11} if directory is False else
                             {0x00, 0x03, 0x10, 0x11, 0x13})
            if ace_flags not in allowed_flags:
                raise ConfigError("State permissions are unsafe. Restrict access to your Windows user, SYSTEM and Administrators before continuing.")
            sid_ptr = ace_ptr.value + 8
            if sid_ptr + 8 > ace_ptr.value + ace_size:
                raise ConfigError("Unable to inspect Windows access control")
            if not advapi32.IsValidSid(ctypes.c_void_p(sid_ptr)):
                raise ConfigError("Unable to inspect Windows access control")
            sid_length = advapi32.GetLengthSid(ctypes.c_void_p(sid_ptr))
            if sid_length == 0 or sid_ptr + sid_length > ace_ptr.value + ace_size:
                raise ConfigError("Unable to inspect Windows access control")
            sid_string = _sid_to_string(ctypes.c_void_p(sid_ptr).value)
            if sid_string is None or sid_string not in approved_strings:
                raise ConfigError("State permissions are unsafe. Restrict access to your Windows user, SYSTEM and Administrators before continuing.")
    except ConfigError:
        raise
    except Exception:
        raise ConfigError("Unable to inspect Windows access control")


def _apply_windows_acl(path, directory=False):
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    approved = []
    new_dacl = ctypes.c_void_p()
    try:
        for value in _approved_windows_sid_strings():
            approved.append(_string_to_sid(value))

        class _TRUSTEE(ctypes.Structure):
            _fields_ = [("pMultipleTrustee", ctypes.c_void_p),
                        ("MultipleTrusteeOperation", ctypes.c_int),
                        ("TrusteeForm", ctypes.c_int),
                        ("TrusteeType", ctypes.c_int),
                        ("ptstrName", ctypes.c_void_p)]

        class _EXPLICIT_ACCESS(ctypes.Structure):
            _fields_ = [("grfAccessPermissions", wintypes.DWORD),
                        ("grfAccessMode", ctypes.c_int),
                        ("grfInheritance", wintypes.DWORD),
                        ("Trustee", _TRUSTEE)]

        inheritance = 0x03 if directory else 0x00
        entries = (_EXPLICIT_ACCESS * len(approved))()
        for idx, sid in enumerate(approved):
            entries[idx].grfAccessPermissions = 0x10000000  # GENERIC_ALL
            entries[idx].grfAccessMode = 2  # SET_ACCESS
            entries[idx].grfInheritance = inheritance
            entries[idx].Trustee.pMultipleTrustee = None
            entries[idx].Trustee.MultipleTrusteeOperation = 0
            entries[idx].Trustee.TrusteeForm = 0  # TRUSTEE_IS_SID
            entries[idx].Trustee.TrusteeType = 1  # TRUSTEE_IS_USER (generic)
            entries[idx].Trustee.ptstrName = sid

        advapi32.SetEntriesInAclW.argtypes = [
            wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p)]
        advapi32.SetEntriesInAclW.restype = wintypes.DWORD
        advapi32.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD

        result = advapi32.SetEntriesInAclW(
            len(approved), ctypes.cast(entries, ctypes.c_void_p), None, ctypes.byref(new_dacl))
        if result != 0:
            raise ConfigError("Unable to apply Windows access control")
        # PROTECTED_DACL_SECURITY_INFORMATION prevents ambient parent grants.
        info = 0x00000004 | 0x80000000
        result = advapi32.SetNamedSecurityInfoW(
            str(path), 1, info, None, None, new_dacl, None)
        if result != 0:
            raise ConfigError("Unable to apply Windows access control")
    except ConfigError:
        raise
    except Exception:
        raise ConfigError("Unable to apply Windows access control")
    finally:
        for sid in approved:
            if sid:
                kernel32.LocalFree(ctypes.c_void_p(sid))
        if new_dacl:
            kernel32.LocalFree(new_dacl)

def secure_dir(path):
    path = Path(path).expanduser()
    if path.is_symlink():
        raise ConfigError("State directory must not be a symlink")
    if os.name == "nt" and _is_windows_reparse_point(path):
        raise ConfigError("State directory must not be a reparse point")
    created = not path.exists()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "nt" and _is_windows_reparse_point(path):
        raise ConfigError("State directory must not be a reparse point")
    if os.name == "nt":
        if created:
            _apply_windows_acl(path, directory=True)
        _validate_windows_acl(path, directory=True)
    elif stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ConfigError("State directory must be private (chmod 700)")
    return path


def secure_file(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ConfigError("Expected a regular, non-symlink configuration file")
    if os.name == "nt" and _is_windows_reparse_point(p):
        raise ConfigError("Expected a regular, non-symlink configuration file")
    if os.name == "nt":
        _validate_windows_acl(p, directory=False)
    elif stat.S_IMODE(p.stat().st_mode) & 0o077:
        raise ConfigError("Configuration containing destinations must be private (chmod 600)")
    return p


def _sqlite_sidecars(p):
    return [p.with_name(p.name + suffix) for suffix in ("-wal", "-shm", "-journal")]


def _validate_sqlite_state_file(path):
    path = Path(path)
    if path.is_symlink():
        raise ConfigError("Outbox must not be a symlink")
    if os.name == "nt" and _is_windows_reparse_point(path):
        raise ConfigError("Outbox must not be a reparse point")
    if not path.exists():
        return
    if os.name == "nt":
        secure_file(path)
    elif stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ConfigError("Outbox must be private (chmod 600)")


def database(directory):
    directory = secure_dir(directory)
    p = directory / "outbox.sqlite3"
    sidecars = _sqlite_sidecars(p)
    created = not p.exists()
    # Validate every pre-existing path before SQLite opens anything. Orphaned
    # WAL/SHM/journal files are not trusted merely because the main DB is absent.
    existing_state_files = [candidate for candidate in [p, *sidecars] if candidate.exists() or candidate.is_symlink()]
    for candidate in existing_state_files:
        _validate_sqlite_state_file(candidate)
    existing_sidecars = [sc for sc in sidecars if sc.exists()]
    conn = sqlite3.connect(p, timeout=10)
    if os.name == "nt":
        if created:
            _apply_windows_acl(p, directory=False)
        _validate_windows_acl(p, directory=False)
    else:
        os.chmod(p, 0o600)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, payload TEXT NOT NULL, created REAL NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
          due REAL NOT NULL DEFAULT 0, error TEXT, received TEXT);
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS watches (name TEXT PRIMARY KEY, path TEXT NOT NULL,
          fingerprint TEXT NOT NULL);
    """)
    conn.commit()
    # Protect sidecars created during initialization; validate pre-existing ones.
    for sc in sidecars:
        if sc.exists():
            if sc in existing_sidecars:
                if os.name == "nt":
                    secure_file(sc)
                elif stat.S_IMODE(sc.stat().st_mode) & 0o077:
                    raise ConfigError("Outbox must be private (chmod 600)")
            else:
                # Newly created sidecars must inherit the already-validated
                # private parent-directory DACL. Never repair them after SQLite
                # may have written sensitive pages; fail closed if inheritance
                # did not produce the expected ACL.
                if os.name == "nt":
                    _validate_sqlite_state_file(sc)
                else:
                    # The already-private state directory prevents ambient
                    # access while SQLite creates the sidecar; tighten mode
                    # immediately, then verify the resulting mode.
                    os.chmod(sc, 0o600)
                    _validate_sqlite_state_file(sc)
    return conn


def normalize(raw, kind, name, environment):
    """Allowlist fields; passwords, URLs, headers, logdata and raw text never leave."""
    name, environment = label(name), label(environment)
    if not isinstance(raw, dict):
        raise ConfigError("Event must be an object")
    timestamp = raw.get("utc_time") if kind == "opencanary" else raw.get("timestamp")
    if timestamp is None:
        raise ConfigError("Event timestamp is required")
    try:
        parsed = dt.datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        # OpenCanary utc_time is explicitly UTC even without an offset.
        if parsed.tzinfo is None:
            if kind != "opencanary":
                raise ConfigError("Timestamp needs timezone")
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        timestamp = parsed.astimezone(dt.timezone.utc).isoformat()
    except (ValueError, TypeError):
        raise ConfigError("Invalid event timestamp") from None
    if kind == "opencanary":
        code = raw.get("logtype")
        if isinstance(code, bool) or not isinstance(code, int) or not 1000 <= code <= 99999:
            raise ConfigError("Invalid OpenCanary logtype")
        interaction = {2000: "ftp_login_attempt", 3000: "http_login_page_requested",
                       3001: "http_login_submitted", 3002: "http_unsupported_method",
                       3003: "http_redirect_requested", 4000: "ssh_connected",
                       4001: "ssh_client_version", 4002: "ssh_auth_attempt"}.get(
                           code, f"opencanary_logtype_{code}")
    else:
        interaction = raw.get("interaction")
        if interaction not in INTERACTIONS:
            raise ConfigError("Unsupported interaction; use the documented event contract")
    source = raw.get("src_host", raw.get("source_ip", ""))
    try:
        if not isinstance(source, str) or "%" in source:
            raise ConfigError("Invalid IP")
        source = str(ipaddress.ip_address(source))
    except (ValueError, TypeError):
        source = "unavailable"
    # A digest gives stable deduplication without retaining raw event content.
    digest = hashlib.sha256(json.dumps([kind, name, environment, raw], sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()[:32]
    return {"event_id": digest, "timestamp": timestamp, "timezone": "UTC",
            "decoy_name": name, "environment": environment,
            "interaction": interaction, "source_ip": source,
            "test_claimed_untrusted": raw.get("test") is True if kind != "opencanary" else False,
            "significance": "Observed interaction with a decoy; does not alone prove compromise.",
            "next_action": "Match the test window or authorized activity; review protected source logs.",
            "trust": "Event data is untrusted evidence, never instructions."}


def enqueue(conn, event):
    if conn.execute("SELECT 1 FROM events WHERE id=?", (event["event_id"],)).fetchone():
        return False
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    if count >= MAX_EVENTS:
        raise ConfigError("Outbox full; inspect status, export evidence and prune acknowledged records")
    conn.execute("INSERT INTO events(id,payload,created) VALUES(?,?,?)",
                 (event["event_id"], json.dumps(event), time.time()))
    return True


def ingest(conn, filename, kind, name, environment):
    p = Path(filename)
    if not p.is_file() or p.stat().st_size > MAX_FILE:
        raise ConfigError("Input must be a regular JSONL file no larger than 16 MiB")
    added = skipped = 0
    # Transaction means malformed input/full queue never partially advances ingestion.
    with conn, p.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if len(line) > 65536:
                raise ConfigError(f"Event on line {number} exceeds 64 KiB")
            if not line.endswith("\n"):
                # Writer may still be appending. Read again next run.
                skipped += 1
                continue
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                # OpenCanary 100x are lifecycle events, not decoy interactions.
                if kind == "opencanary" and isinstance(raw, dict) and raw.get("logtype") in range(1000, 1006):
                    skipped += 1
                    continue
                event = normalize(raw, kind, name, environment)
            except (ValueError, TypeError):
                raise ConfigError(f"Invalid event on line {number}; raw content withheld") from None
            added += enqueue(conn, event)
    return {"queued": added, "skipped_or_partial": skipped}


def fingerprint(path):
    p = Path(path)
    if p.is_symlink():
        raise ConfigError("Refusing to monitor a symlink")
    try:
        st = p.stat()
    except FileNotFoundError:
        return {"exists": False}
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError("Watch only a dedicated regular decoy file")
    # Metadata only: no file reads, content or access-time collection.
    return {"exists": True, "inode": st.st_ino, "device": st.st_dev,
            "size": st.st_size, "mtime_ns": st.st_mtime_ns}


def watch_add(conn, name, filename):
    name = label(name)
    p = str(Path(filename).expanduser().absolute())
    current = fingerprint(p)
    if not current["exists"]:
        raise ConfigError("Create the dedicated harmless decoy file before watch-add")
    old = conn.execute("SELECT path FROM watches WHERE name=?", (name,)).fetchone()
    if old:
        if old["path"] != p:
            raise ConfigError("Watch identity differs; choose a new name or verify removal first")
        return {"watch": name, "existing": True}
    with conn:
        conn.execute("INSERT INTO watches VALUES(?,?,?)", (name, p, json.dumps(current)))
    return {"watch": name, "existing": False}


def watch_poll(conn, environment):
    added = 0
    watches = conn.execute("SELECT * FROM watches").fetchall()
    if not watches:
        raise ConfigError("No watches registered; verify the state directory and resource identity")
    with conn:
        for row in watches:
            before, after = json.loads(row["fingerprint"]), fingerprint(row["path"])
            if before == after:
                continue
            if not after["exists"]:
                interaction = "file_deleted"
            elif not before["exists"]:
                interaction = "file_restored"
            elif (before["inode"], before["device"]) != (after["inode"], after["device"]):
                interaction = "file_replaced"
            else:
                interaction = "file_changed"
            event = normalize({"interaction": interaction, "timestamp": utc_now(),
                               "change_id": uuid.uuid4().hex}, "generic", row["name"], environment)
            added += enqueue(conn, event)
            conn.execute("UPDATE watches SET fingerprint=? WHERE name=?", (json.dumps(after), row["name"]))
    return {"queued": added, "watched": len(watches)}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward an endpoint secret to another URL.


class DeliveryError(Exception):
    def __init__(self, code, retry=True, retry_after=0):
        self.code, self.retry, self.retry_after = code, retry, retry_after


def load_config(filename, require_secrets=True):
    config = json.loads(secure_file(filename).read_text())
    if not isinstance(config, dict):
        raise ConfigError("Configuration must be a JSON object")
    channel = config.get("channel")
    if channel not in {"webhook", "slack", "discord", "smtp"}:
        raise ConfigError("channel must be webhook, slack, discord or smtp")
    label(config.get("destination_label"))
    if channel == "smtp":
        for key in ("host", "from", "to"):
            val = config.get(key)
            if not isinstance(val, str) or not val or "\n" in val or "\r" in val:
                raise ConfigError(f"Invalid SMTP {key}")
        if config.get("tls") not in {"starttls", "ssl"}:
            raise ConfigError("SMTP must use starttls or ssl")
        if not isinstance(config.get("port"), int) or not 1 <= config["port"] <= 65535:
            raise ConfigError("Invalid SMTP port")
        if config.get("username") and require_secrets:
            env_value(config.get("password_env"))
    else:
        env_name = config.get("url_env")
        if not isinstance(env_name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", env_name):
            raise ConfigError("url_env must name a secret environment variable")
        if require_secrets:
            endpoint(config)
        if config.get("bearer_env") and require_secrets:
            env_value(config["bearer_env"])
    return config


def env_value(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
        raise ConfigError("Invalid secret environment variable name")
    value = os.environ.get(name)
    if not value:
        raise ConfigError("Required secret environment variable is missing")
    if "\r" in value or "\n" in value:
        raise ConfigError("Secret must not contain line breaks")
    return value


def endpoint(config):
    url = env_value(config["url_env"])
    if any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ConfigError("Destination URL contains invalid characters")
    try:
        parsed = urllib.parse.urlsplit(url)
        parsed.port
    except ValueError:
        raise ConfigError("Destination URL is invalid") from None
    local_test = (config.get("allow_loopback_http") is True and parsed.scheme == "http"
                  and parsed.hostname in {"127.0.0.1", "::1"})
    if (parsed.scheme != "https" and not local_test) or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ConfigError("Use HTTPS without URL credentials/fragments; loopback HTTP is test-only")
    if config["channel"] == "slack" and parsed.hostname not in {"hooks.slack.com", "hooks.slack-gov.com"}:
        raise ConfigError("Slack destination must be an official incoming webhook")
    if config["channel"] == "discord" and parsed.hostname not in {"discord.com", "canary.discord.com", "ptb.discord.com"}:
        raise ConfigError("Discord destination must be an official webhook")
    return url


def message(event):
    return "\n".join(f"{key}: {value}" for key, value in event.items())


def send(config, event):
    channel = config["channel"]
    if channel == "smtp":
        msg = EmailMessage()
        msg["From"], msg["To"] = config["from"], config["to"]
        msg["Subject"] = f"Decoy alert: {event['decoy_name']} [{event['event_id'][:8]}]"
        msg["Message-ID"] = f"<{event['event_id']}@decoy.invalid>"
        msg["Date"] = email.utils.formatdate(localtime=False)
        msg.set_content(message(event))
        try:
            cls = smtplib.SMTP_SSL if config["tls"] == "ssl" else smtplib.SMTP
            kwargs = {"context": ssl.create_default_context()} if config["tls"] == "ssl" else {}
            with cls(config["host"], config["port"], timeout=10, **kwargs) as server:
                if config["tls"] == "starttls":
                    server.starttls(context=ssl.create_default_context())
                if config.get("username"):
                    server.login(config["username"], env_value(config["password_env"]))
                refused = server.send_message(msg)
                if refused:
                    raise DeliveryError("smtp_recipient_refused", False)
        except smtplib.SMTPResponseException as e:
            raise DeliveryError(f"smtp_{e.smtp_code}", e.smtp_code < 500) from None
        except (OSError, smtplib.SMTPException):
            raise DeliveryError("smtp_transport") from None
        return
    url = endpoint(config)
    if channel == "slack":
        payload = {"text": message(event), "blocks": [{"type": "section", "text": {
            "type": "plain_text", "text": message(event), "emoji": False}}],
            "unfurl_links": False, "unfurl_media": False}
    elif channel == "discord":
        payload = {"content": message(event), "allowed_mentions": {"parse": []}}
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(
            [(k, v) for k, v in query if k != "wait"] + [("wait", "true")])))
    else:
        payload = event
    headers = {"Content-Type": "application/json", "User-Agent": "honeypot-setup/1.0",
               "Idempotency-Key": event["event_id"]}
    if config.get("bearer_env"):
        headers["Authorization"] = "Bearer " + env_value(config["bearer_env"])
    req = urllib.request.Request(url, json.dumps(payload).encode(), headers, method="POST")
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=10) as response:
            if not 200 <= response.status < 300:
                raise DeliveryError(f"http_{response.status}")
            if channel == "slack" and response.read(64).strip() != b"ok":
                raise DeliveryError("slack_unexpected_response", False)
    except urllib.error.HTTPError as e:
        try:
            delay = float(e.headers.get("Retry-After", "0"))
        except (ValueError, TypeError):
            try:
                date = email.utils.parsedate_to_datetime(e.headers["Retry-After"])
                delay = max(0, date.timestamp() - time.time())
            except (ValueError, TypeError, KeyError):
                delay = 0
        code = e.code
        e.close()
        raise DeliveryError(f"http_{code}", code == 429 or code >= 500,
                            max(0, min(delay, 86400))) from None
    except (urllib.error.URLError, OSError, http.client.HTTPException, UnicodeError):
        raise DeliveryError("http_transport") from None


def flush(conn, config, sender=send):
    # Single transaction serializes concurrent flush processes. Bounded to one send.
    conn.execute("BEGIN IMMEDIATE")
    try:
        now = time.time()
        identity_input = [config, endpoint(config) if config["channel"] != "smtp" else None]
        identity = hashlib.sha256(json.dumps(identity_input, sort_keys=True).encode()).hexdigest()
        old = conn.execute("SELECT value FROM meta WHERE key='destination'").fetchone()
        if old and old["value"] != identity:
            raise ConfigError("Destination changed; use a new outbox directory after reviewing pending events")
        conn.execute("INSERT OR IGNORE INTO meta VALUES('destination',?)", (identity,))
        last = conn.execute("SELECT value FROM meta WHERE key='last_send'").fetchone()
        blocked = conn.execute("SELECT value FROM meta WHERE key='not_before'").fetchone()
        if (last and now - float(last["value"]) < 1) or (blocked and now < float(blocked["value"])):
            conn.commit()
            return {"status": "rate_limited_locally"}
        row = conn.execute("SELECT * FROM events WHERE status='pending' AND due<=? ORDER BY created LIMIT 1", (now,)).fetchone()
        if not row:
            conn.commit()
            return {"status": "nothing_due"}
        attempts = row["attempts"] + 1
        try:
            sender(config, json.loads(row["payload"]))
            status, due, error = "accepted", 0, None
        except DeliveryError as e:
            status = "pending" if e.retry and attempts < 8 else "failed"
            due, error = now + max(min(3600, 2 ** attempts), e.retry_after), e.code
            if e.retry_after:
                conn.execute("INSERT OR REPLACE INTO meta VALUES('not_before',?)", (str(now + e.retry_after),))
        conn.execute("UPDATE events SET status=?,attempts=?,due=?,error=? WHERE id=?",
                     (status, attempts, due, error, row["id"]))
        conn.execute("INSERT OR REPLACE INTO meta VALUES('last_send',?)", (str(now),))
        conn.commit()
        return {"event_id": row["id"], "status": status, "attempts": attempts,
                "error": error, "receipt": "unverified"}
    except BaseException:
        conn.rollback()
        raise


def status(conn):
    counts = dict(conn.execute("SELECT status,COUNT(*) FROM events GROUP BY status").fetchall())
    oldest = conn.execute("SELECT MIN(created) FROM events WHERE status IN ('pending','failed')").fetchone()[0]
    events = [dict(r) for r in conn.execute(
        "SELECT id,status,attempts,due,error,received FROM events ORDER BY created DESC LIMIT 20")]
    return {"counts": counts, "oldest_unsent_age_seconds": int(time.time()-oldest) if oldest else None,
            "recent_events": events, "meaning": "accepted means transport acceptance, not human receipt"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, help="Private directory outside installed skill and source repo")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    p = sub.add_parser("validate"); p.add_argument("--config", required=True)
    p = sub.add_parser("ingest")
    p.add_argument("--file", required=True); p.add_argument("--format", choices=["generic", "opencanary"], required=True)
    p.add_argument("--name", required=True); p.add_argument("--environment", required=True)
    p = sub.add_parser("delivery-test"); p.add_argument("--name", required=True); p.add_argument("--environment", required=True)
    p = sub.add_parser("flush"); p.add_argument("--config", required=True)
    p = sub.add_parser("watch-add"); p.add_argument("--name", required=True); p.add_argument("--file", required=True)
    p = sub.add_parser("watch-poll"); p.add_argument("--environment", required=True)
    p = sub.add_parser("watch-remove"); p.add_argument("--name", required=True); p.add_argument("--expected-file", required=True)
    p = sub.add_parser("confirm"); p.add_argument("--event-id", required=True); p.add_argument("--method", choices=["user-confirmed", "destination-read"], required=True)
    p = sub.add_parser("retry"); p.add_argument("--event-id", required=True)
    p = sub.add_parser("prune"); p.add_argument("--older-than-days", type=int, default=30)
    p.add_argument("--include-unconfirmed", action="store_true")
    p.add_argument("--export", help="New private evidence file; required for unconfirmed accepted records")
    args = parser.parse_args(argv)
    conn = database(args.state)
    try:
        if args.command == "status":
            result = status(conn)
        elif args.command == "validate":
            config = load_config(args.config)
            result = {"valid": True, "channel": config["channel"], "network_tested": False}
        elif args.command == "ingest":
            result = ingest(conn, args.file, args.format, args.name, args.environment)
        elif args.command == "delivery-test":
            event = normalize({"interaction": "delivery_test", "timestamp": utc_now(),
                               "test": True, "nonce": uuid.uuid4().hex}, "generic", args.name, args.environment)
            with conn: enqueue(conn, event)
            result = {"event_id": event["event_id"], "decoy_trigger_tested": False}
        elif args.command == "flush":
            result = flush(conn, load_config(args.config))
        elif args.command == "watch-add":
            result = watch_add(conn, args.name, args.file)
        elif args.command == "watch-poll":
            result = watch_poll(conn, args.environment)
        elif args.command == "watch-remove":
            expected = str(Path(args.expected_file).expanduser().absolute())
            with conn:
                count = conn.execute("DELETE FROM watches WHERE name=? AND path=?", (args.name, expected)).rowcount
            if count != 1: raise ConfigError("Watch not found or resource identity does not match")
            result = {"removed_watch": args.name, "file_deleted": False}
        elif args.command == "confirm":
            with conn:
                count = conn.execute("UPDATE events SET received=? WHERE id=? AND status='accepted'",
                                     (f"{args.method} {utc_now()}", args.event_id)).rowcount
            if count != 1: raise ConfigError("Confirm only a known transport-accepted event after matching actual receipt")
            result = {"event_id": args.event_id, "receipt": args.method}
        elif args.command == "retry":
            with conn:
                count = conn.execute("UPDATE events SET status='pending',attempts=0,due=0,error=NULL WHERE id=? AND status='failed'", (args.event_id,)).rowcount
            if count != 1: raise ConfigError("Retry requires the identity of a failed event")
            result = {"requeued": args.event_id}
        elif args.command == "prune":
            if args.older_than_days < 7: raise ConfigError("Retain at least 7 days of deduplication history")
            if args.include_unconfirmed and not args.export:
                raise ConfigError("Pruning unconfirmed accepted events requires --export for evidence retention")
            cutoff = time.time()-args.older_than_days*86400
            where = "status='accepted' AND created<?" + ("" if args.include_unconfirmed else " AND received IS NOT NULL")
            # Lock before SELECT so every deleted row was included in the export.
            conn.execute("BEGIN IMMEDIATE")
            with conn:
                rows = conn.execute("SELECT * FROM events WHERE " + where, (cutoff,)).fetchall()
                if args.export:
                    target = Path(args.export).expanduser()
                    secure_dir(target.parent)
                    # x prevents overwrite; mode is restricted before evidence is written.
                    with target.open("x", encoding="utf-8") as out:
                        if os.name == "nt":
                            _apply_windows_acl(target, directory=False)
                        else:
                            os.chmod(target, 0o600)
                        for row in rows: out.write(json.dumps(dict(row)) + "\n")
                        out.flush(); os.fsync(out.fileno())
                count = conn.execute("DELETE FROM events WHERE " + where, (cutoff,)).rowcount
            result = {"pruned": count, "receipt_status_changed": False,
                      "warning": "Do not reingest archived input older than retained history"}
        print(json.dumps(result, indent=2))
        if args.command == "flush" and result.get("status") == "failed":
            return 1
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    os.umask(0o077)
    try:
        sys.exit(main())
    except (ValueError, OSError, sqlite3.Error, http.client.HTTPException) as exc:
        # Never print URLs, raw events, SMTP replies or provider error bodies.
        if isinstance(exc, ConfigError):
            print(f"Error: {exc}", file=sys.stderr)
        else:
            print(f"Error: {type(exc).__name__}; inspect local configuration/permissions", file=sys.stderr)
        sys.exit(2)
