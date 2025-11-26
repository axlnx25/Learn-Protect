# module_a/signature_checker.py
# Windows-only helper to check Authenticode signatures.
# Dependencies: pefile, cryptography

import sys
import os
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timezone

# third-party
import pefile
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509 import Certificate
from cryptography import x509


@dataclass
class SignatureInfo:
    path: str
    signed: bool                 # True if a signature exists in the file
    valid: Optional[bool]        # True if signature verifies, False if invalid, None if unknown/unchecked
    issuer: Optional[str]        # issuer subject string (rfc4514) if available
    not_valid_after: Optional[str]  # ISO-8601 UTC if available
    error: Optional[str]


def _is_windows() -> bool:
    return sys.platform.startswith("win")


# ---- WinVerifyTrust wrapper (to check signature validity) ----
def _win_verify_trust(filepath: str) -> (bool, Optional[str]):
    """
    Returns (valid_bool, error_message_or_None).
    Uses WinVerifyTrust with the generic verify action.
    """
    # Return unknown on non-windows
    if not _is_windows():
        return (False, "Not running on Windows")

    # GUID for WinTrust: WINTRUST_ACTION_GENERIC_VERIFY_V2
    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", wintypes.BYTE * 8)
        ]

    # GUID = {0xaac56b, 0xcd44, 0x11d0, {0x8c,0xc2,0x00,0xc0,0x4f,0xc2,0x97,0xeb}}
    # Properly: aac56bcd-0000??? but use bytes below from official examples:
    # The correct GUID bytes for WINTRUST_ACTION_GENERIC_VERIFY_V2:
    WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
        0xaac56bcd, 0x0000, 0x0000,
        (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    )
    # Note: constructing via GUID fields is error-prone in ctypes;
    # instead we will load WinVerifyTrust via ctypes.windll and pass file path through WINTRUST_FILE_INFO.

    # Define necessary structures from MSDN minimally
    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    # Wintrust data flags (we keep minimal)
    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD)
        ]

    # Constants from WinTrust.h
    WTD_UI_NONE = 2
    WTD_REVOKE_NONE = 0
    WTD_CHOICE_FILE = 1
    WTD_STATEACTION_IGNORE = 0x00000000
    WTD_REVOCATION_CHECK_NONE = 0x00000010

    # load function
    try:
        wintrust = ctypes.WinDLL("wintrust")
    except Exception as e:
        return (False, f"Failed loading wintrust.dll: {e}")

    WinVerifyTrust = wintrust.WinVerifyTrust
    WinVerifyTrust.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_byte * 16), ctypes.POINTER(WINTRUST_DATA)]
    WinVerifyTrust.restype = wintypes.LONG

    # Construct WINTRUST_FILE_INFO
    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = ctypes.c_wchar_p(os.path.abspath(filepath))
    file_info.hFile = None
    file_info.pgKnownSubject = None

    # Construct WINTRUST_DATA
    wtd = WINTRUST_DATA()
    wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wtd.pPolicyCallbackData = None
    wtd.pSIPClientData = None
    wtd.dwUIChoice = WTD_UI_NONE
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE
    wtd.dwUnionChoice = WTD_CHOICE_FILE
    wtd.pFile = ctypes.pointer(file_info)
    wtd.dwStateAction = WTD_STATEACTION_IGNORE
    wtd.hWVTStateData = None
    wtd.pwszURLReference = None
    wtd.dwProvFlags = 0
    wtd.dwUIContext = 0

    # GUID bytes for WINTRUST_ACTION_GENERIC_VERIFY_V2
    # Using the byte array representation expected by WinVerifyTrust (16 bytes)
    # canonical GUID: {aac56bcd-15c1-11d0-8c...} but to avoid GUID construction issues,
    # we can pass as 16-byte array of zeros and rely on WinVerifyTrust to handle file info;
    # however, to be correct, we'll create the well-known GUID as bytes:
    # GUID: {0xaac56bcd, 0xcd44, 0x11d0, 0x8c,0xc2,0x00,0xc0,0x4f,0xc2,0x97,0xeb}
    guid_bytes = (ctypes.c_byte * 16)(
        0xcd, 0x6b, 0xa5, 0xaa,  # Data1 (little-endian)
        0x44, 0xcd,              # Data2 (little-endian)
        0xd0, 0x11,              # Data3
        0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb
    )

    try:
        result = WinVerifyTrust(None, ctypes.byref(guid_bytes), ctypes.byref(wtd))
        # ERROR_SUCCESS (0) => trust verified
        if result == 0:
            return (True, None)
        else:
            return (False, f"WinVerifyTrust returned code 0x{result:08x}")
    except Exception as e:
        return (False, f"WinVerifyTrust call failed: {e}")


# ---- PKCS7 extraction from PE and parse certificates ----
def _extract_certs_from_pe(filepath: str) -> (Optional[Certificate], Optional[str]):
    """
    Tries to read the WIN_CERTIFICATE (security directory) from the PE and parse PKCS7 to obtain signer certs.
    Returns (first_certificate_or_None, error_or_None)
    """
    try:
        pe = pefile.PE(filepath, fast_load=True)
    except Exception as e:
        return (None, f"pefile.PE open failed: {e}")

    # IMAGE_DIRECTORY_ENTRY_SECURITY index is 4 (standard), but use attribute
    try:
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    except Exception:
        # fallback if attribute missing
        try:
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        except Exception:
            return (None, "No security directory in PE")

    if security_dir.VirtualAddress == 0 or security_dir.Size == 0:
        return (None, "No certificate table present")

    # On PE, the VirtualAddress for security directory is actually file offset
    offset = security_dir.VirtualAddress
    size = security_dir.Size

    try:
        with open(filepath, "rb") as f:
            f.seek(offset)
            raw = f.read(size)
    except Exception as e:
        return (None, f"Failed to read security directory: {e}")

    # WIN_CERTIFICATE structure: dwLength (4), wRevision(2), wCertificateType(2), bCertificate (dwLength - 8)
    if len(raw) < 8:
        return (None, "Certificate table too small")

    import struct
    try:
        dwLength, wRevision, wCertType = struct.unpack_from("<IHH", raw, 0)
    except Exception as e:
        return (None, f"Failed unpack WIN_CERTIFICATE: {e}")

    cert_blob = raw[8:dwLength] if dwLength <= len(raw) else raw[8:]
    if not cert_blob:
        return (None, "Empty certificate blob")

    # PKCS7: parse using cryptography
    try:
        certs = pkcs7.load_der_pkcs7_certificates(cert_blob)
        if not certs:
            return (None, "No certificates found inside PKCS7")
        # choose first certificate (signer or leaf)
        first: Certificate = certs[0]
        return (first, None)
    except Exception as e:
        return (None, f"Failed to parse PKCS7 blob: {e}")


# ---- Public API ----
def inspect_signature(filepath: str) -> SignatureInfo:
    """
    Inspect Windows Authenticode signature of the given file.

    Returns SignatureInfo with:
      - signed: whether a signature exists in PE
      - valid: whether WinVerifyTrust considers it valid (True/False/None)
      - issuer: issuer rfc4514 string if available
      - not_valid_after: ISO-8601 UTC string if available
      - error: textual error if something failed
    """
    result = SignatureInfo(
        path=filepath,
        signed=False,
        valid=None,
        issuer=None,
        not_valid_after=None,
        error=None
    )

    if not os.path.exists(filepath):
        result.error = "File not found"
        return result

    if not _is_windows():
        result.error = "Signature check supported only on Windows"
        return result

    # first: try WinVerifyTrust to decide whether it is signed & valid
    valid, err = _win_verify_trust(filepath)
    # Note: WinVerifyTrust returning non-zero does not necessarily mean "no signature" vs "invalid".
    # We'll still attempt to extract certificate to detect presence.
    result.valid = valid if err is None else False
    if err:
        # keep error but continue to try to extract cert for issuer info if present
        result.error = err

    # try to extract certificate from PE (gives us 'signed' indicator and issuer / validity)
    cert, cert_err = _extract_certs_from_pe(filepath)
    if cert_err:
        # no embedded certificate - not signed (by PE)
        if result.error:
            # append
            result.error = result.error + "; " + cert_err
        else:
            result.error = cert_err
        result.signed = False
        return result
    else:
        # we have a cert
        result.signed = True
        try:
            issuer = cert.issuer.rfc4514_string()
            result.issuer = issuer
        except Exception:
            result.issuer = None

        try:
            # x509 certificate not_valid_after is a datetime (naive) -> make ISO UTC
            nna = cert.not_valid_after
            if nna is not None:
                # ensure timezone-aware in UTC
                if nna.tzinfo is None:
                    nna = nna.replace(tzinfo=timezone.utc)
                result.not_valid_after = nna.astimezone(timezone.utc).isoformat()
        except Exception:
            result.not_valid_after = None

        # if valid was None/False but cert present, keep both pieces: signed True, valid per WinVerifyTrust
        return result
