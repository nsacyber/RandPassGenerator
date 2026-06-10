"""AES Key Wrap (RFC 3394) and PBKDF2 key derivation.

References:
    KeyWrapper.java, KeyUnwrapper.java
    NIST SP800-38F, NIST SP800-132, RFC 3394
"""

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap, InvalidUnwrap
from cryptography.hazmat.backends import default_backend

# Fixed salt from KeyWrapper.java (matches Java implementation)
_SALT = bytes.fromhex("762043c38a8e1ad1c8502ec6e53d8c503fe9b28bf73f583e4fadd5888737a5ae")
_ITERATIONS = 100_000
_KEY_LENGTH = 32  # 256-bit KEK


class KeyWrapError(RuntimeError):
    """Raised when AES Key Unwrap fails (wrong passphrase or corrupted data)."""


def derive_kek(passphrase: str) -> bytes:
    """Derive a 256-bit Key Encryption Key via PBKDF2-HMAC-SHA512.

    Passphrase must be at least 16 characters (matches Java minimum check).
    """
    if len(passphrase) < 16:
        raise ValueError(f"Passphrase must be at least 16 characters (got {len(passphrase)})")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=_KEY_LENGTH,
        salt=_SALT,
        iterations=_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def wrap_key(key_hex: str, passphrase: str) -> bytes:
    """Wrap the UTF-8 bytes of key_hex using AES Key Wrap (RFC 3394).

    Note: wraps the hex string as UTF-8 bytes, matching Java's KeyWrapper behavior.
    """
    kek = derive_kek(passphrase)
    key_material = key_hex.encode("utf-8")  # matches Java: new String(inputKey).getBytes()
    return aes_key_wrap(kek, key_material, default_backend())


def unwrap_key(wrapped: bytes, passphrase: str) -> bytes:
    """Unwrap AES-wrapped key bytes. Returns the original UTF-8 key bytes.

    Raises KeyWrapError if the passphrase is wrong or data is corrupted.
    """
    kek = derive_kek(passphrase)
    try:
        return aes_key_unwrap(kek, wrapped, default_backend())
    except InvalidUnwrap as e:
        raise KeyWrapError("Key unwrap failed — wrong passphrase or corrupted file") from e
