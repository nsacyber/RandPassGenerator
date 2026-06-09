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


class HashDRBG:
    """NIST SP800-90A Hash DRBG.

    Usage:
        drbg = HashDRBG(strength=192)
        drbg.instantiate(entropy_bytes, nonce_bytes)
        random_bytes = drbg.generate(32)

    The first instantiation triggers NIST known-answer tests (once per process).
    RuntimeError is raised if they fail.
    """

    _MAX_RESEED_COUNT = 1 << 48  # SP800-90A section 10.1 limit

    def __init__(self, strength: int = 192, _skip_kat: bool = False) -> None:
        if strength not in _STRENGTH_TO_SEEDLEN:
            raise ValueError(f"Unsupported DRBG strength {strength}. Use 80, 128, 192, or 256.")
        if not _skip_kat:
            _run_known_answer_tests()

        seedlen_bits = _STRENGTH_TO_SEEDLEN[strength]
        self._seedlen = seedlen_bits // 8          # bytes
        self._hashbits = _STRENGTH_TO_HASHBITS[strength]
        self._modulus = 1 << seedlen_bits           # 2^seedlen
        self._V: int = 0
        self._C: int = 0
        self._reseed_counter: int = 0
        self._instantiated: bool = False

    # ------------------------------------------------------------------
    # SP800-90A Section 10.1.1.2: Instantiate
    # ------------------------------------------------------------------
    def instantiate(
        self,
        entropy: bytes,
        nonce: bytes,
        personalization: bytes = b"",
    ) -> None:
        """Instantiate the DRBG with entropy, nonce, and optional personalization."""
        seed_material = entropy + nonce + personalization
        seedlen_bits = self._seedlen * 8

        V_bytes = _hash_df(seed_material, seedlen_bits, self._hashbits)
        self._V = int.from_bytes(V_bytes, 'big')

        C_bytes = _hash_df(b'\x00' + V_bytes, seedlen_bits, self._hashbits)
        self._C = int.from_bytes(C_bytes, 'big')

        self._reseed_counter = 1  # matches Java's resetReseedCounter() → 1
        self._instantiated = True

    # ------------------------------------------------------------------
    # SP800-90A Section 10.1.1.3: Reseed
    # ------------------------------------------------------------------
    def reseed(self, entropy: bytes, additional_input: bytes = b"") -> None:
        """Reseed the DRBG with fresh entropy."""
        seed_material = b'\x01' + _pbi2ba(self._V) + entropy + additional_input
        seedlen_bits = self._seedlen * 8

        V_bytes = _hash_df(seed_material, seedlen_bits, self._hashbits)
        self._V = int.from_bytes(V_bytes, 'big')

        C_bytes = _hash_df(b'\x00' + V_bytes, seedlen_bits, self._hashbits)
        self._C = int.from_bytes(C_bytes, 'big')

        self._reseed_counter = 1

    # ------------------------------------------------------------------
    # SP800-90A Section 10.1.1.4: Hashgen
    # ------------------------------------------------------------------
    def _hashgen(self, num_bytes: int) -> bytes:
        outlen = self._hashbits // 8
        m = math.ceil(num_bytes / outlen)
        data = self._V
        W = b""
        for _ in range(m):
            W += _sha(_pbi2ba(data), self._hashbits)
            data = (data + 1) % self._modulus
        return W[:num_bytes]

    # ------------------------------------------------------------------
    # SP800-90A Section 10.1.1.5: Generate
    # ------------------------------------------------------------------
    def generate(self, num_bytes: int, additional_input: bytes = b"") -> bytes:
        """Generate num_bytes of random output."""
        if not self._instantiated:
            raise RuntimeError("HashDRBG not instantiated")
        if self._reseed_counter > self._MAX_RESEED_COUNT:
            raise RuntimeError("Reseed required (reseed counter exceeded)")

        if additional_input:
            w = int.from_bytes(
                _sha(b'\x02' + _pbi2ba(self._V) + additional_input, self._hashbits),
                'big',
            )
            self._V = (self._V + w) % self._modulus

        output = self._hashgen(num_bytes)

        H = int.from_bytes(_sha(b'\x03' + _pbi2ba(self._V), self._hashbits), 'big')
        self._V = (self._V + H + self._C + self._reseed_counter) % self._modulus
        self._reseed_counter += 1

        return output

    def generate_bytes(self, num_bytes: int) -> bytes:
        """Convenience alias for generate()."""
        return self.generate(num_bytes)

    def is_instantiated(self) -> bool:
        return self._instantiated

    def uninstantiate(self) -> None:
        self._V = 0
        self._C = 0
        self._reseed_counter = 0
        self._instantiated = False


def _run_known_answer_tests() -> None:
    """Run NIST KATs once per process. Raises RuntimeError on failure."""
    global _KAT_PASSED
    if _KAT_PASSED is True:
        return
    if _KAT_PASSED is False:
        raise RuntimeError("NIST Hash DRBG known-answer tests previously FAILED")
    # First call — run the tests
    passed = _perform_kat()
    _KAT_PASSED = passed
    if not passed:
        raise RuntimeError(
            "NIST Hash DRBG known-answer tests FAILED — "
            "this build cannot be trusted to generate cryptographic material"
        )


def _perform_kat() -> bool:
    """Placeholder — replaced in Task 5."""
    return True
