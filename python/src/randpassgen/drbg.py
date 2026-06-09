"""NIST SP800-90A Hash DRBG (Hash-based Deterministic Random Bit Generator).

Reference: NIST SP800-90A Rev 1, Section 10.1 (Hash_DRBG).
Java reference: gov.nsa.ia.drbg.HashDRBG
"""

import hashlib
import math
from typing import Optional

# ---------------------------------------------------------------------------
# NIST SP800-90A Table 2 — strength → (seedlen_bits, hash_algorithm)
# ---------------------------------------------------------------------------
_STRENGTH_TO_SEEDLEN: dict[int, int] = {80: 440, 128: 440, 192: 888, 256: 888}
_STRENGTH_TO_HASHBITS: dict[int, int] = {80: 160, 128: 256, 192: 384, 256: 512}
_HASHBITS_TO_ALG: dict[int, str] = {160: "sha1", 256: "sha256", 384: "sha384", 512: "sha512"}

_KAT_PASSED: Optional[bool] = None  # module-level KAT result cache


def _sha(data: bytes, hashbits: int) -> bytes:
    return hashlib.new(_HASHBITS_TO_ALG[hashbits], data).digest()


def _pbi2ba(n: int) -> bytes:
    """Minimal big-endian byte representation of a non-negative int.

    Equivalent to Java's AbstractDRBG.pbi2ba(BigInteger): strips the extra
    sign byte that Java prepends when the most-significant bit is set.
    """
    if n == 0:
        return b'\x00'
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def _hash_df(input_string: bytes, no_of_bits_to_return: int, hashbits: int) -> bytes:
    """NIST SP800-90A Hash Derivation Function (Section 10.4.1).

    Inputs:
        input_string: bytes to hash
        no_of_bits_to_return: desired output length in bits (must be multiple of 8)
        hashbits: hash output size in bits (256, 384, or 512)
    """
    len_ = math.ceil(no_of_bits_to_return / hashbits)
    bits_be = no_of_bits_to_return.to_bytes(4, 'big')
    temp = b""
    for counter in range(1, len_ + 1):
        temp += _sha(bytes([counter]) + bits_be + input_string, hashbits)
    return temp[:(no_of_bits_to_return + 7) // 8]
