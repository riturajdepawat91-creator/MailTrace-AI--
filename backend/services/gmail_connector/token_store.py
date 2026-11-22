"""Current-user Windows DPAPI token storage. No plaintext fallback is allowed."""

from __future__ import annotations

import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path
from typing import Any, Protocol


class TokenStoreError(RuntimeError):
    """Raised when secure token storage is unavailable or invalid."""


class Protector(Protocol):
    def protect(self, plaintext: bytes) -> bytes: ...

    def unprotect(self, ciphertext: bytes) -> bytes: ...


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


class WindowsDpapi:
    """Thin wrapper over CryptProtectData/CryptUnprotectData (CurrentUser scope)."""

    @staticmethod
    def _transform(data: bytes, *, decrypt: bool) -> bytes:
        if os.name != "nt":
            raise TokenStoreError("Secure Gmail token storage is available only on Windows.")
        if not data:
            raise TokenStoreError("Refusing to protect or restore an empty token payload.")

        source_buffer = ctypes.create_string_buffer(data)
        source = _DataBlob(len(data), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_byte)))
        output = _DataBlob()
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if decrypt:
            ok = crypt32.CryptUnprotectData(
                ctypes.byref(source), None, None, None, None, 0, ctypes.byref(output)
            )
        else:
            ok = crypt32.CryptProtectData(
                ctypes.byref(source), "MailTrace Gmail OAuth", None, None, None, 0,
                ctypes.byref(output),
            )
        if not ok:
            raise TokenStoreError("Windows could not access the protected Gmail token store.")
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            kernel32.LocalFree(output.pbData)

    def protect(self, plaintext: bytes) -> bytes:
        return self._transform(plaintext, decrypt=False)

    def unprotect(self, ciphertext: bytes) -> bytes:
        return self._transform(ciphertext, decrypt=True)


class DpapiTokenStore:
    """DPAPI-protected JSON file under the signed-in user's local app data."""

    def __init__(self, path: Path | None = None, protector: Protector | None = None):
        if path is None:
            local_app_data = os.environ.get("LOCALAPPDATA")
            if not local_app_data:
                raise TokenStoreError("The signed-in Windows user's local profile is unavailable.")
            path = Path(local_app_data) / "MailTrace" / "gmail" / "oauth.dpapi"
        self.path = Path(path)
        self._protector = protector or WindowsDpapi()

    def save(self, token_data: dict[str, Any]) -> None:
        try:
            serialized = json.dumps(token_data, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            protected = self._protector.protect(serialized)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(self.path.suffix + ".new")
            with temporary.open("wb") as handle:
                handle.write(protected)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except TokenStoreError:
            raise
        except OSError as exc:
            raise TokenStoreError("Could not persist the protected Gmail token cache.") from exc
        except (TypeError, ValueError) as exc:
            raise TokenStoreError("The Gmail token response was not valid for secure storage.") from exc

    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        try:
            cleartext = self._protector.unprotect(self.path.read_bytes())
            value = json.loads(cleartext.decode("utf-8"))
        except TokenStoreError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TokenStoreError("The protected Gmail token cache could not be read.") from exc
        if not isinstance(value, dict):
            raise TokenStoreError("The protected Gmail token cache has an invalid format.")
        return value

    def delete(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError as exc:
            raise TokenStoreError("Could not remove the protected Gmail token cache.") from exc
