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
    """Run the two NIST KAT vectors from HashDRBG.java initializeTests()."""
    try:
        _kat1()
        _kat2()
        return True
    except AssertionError:
        return False


def _kat1() -> None:
    """KAT-1: strength=128, SHA-256, seedlen=440 bits."""
    drbg = HashDRBG(strength=128, _skip_kat=True)
    drbg.instantiate(
        bytes.fromhex("63363377e41e86468deb0ab4a8ed683f6a134e47e014c700454e81e95358a569"),
        bytes.fromhex("808aa38f2a72a62359915a9f8a04ca68"),
    )
    assert drbg._V == int("32ab605ddc8d5651093b8a59bd9d3adea1249e21a69e2e4a3967515fa03ad41ccf5b126eb9f3b268080c952df88241fe4cc27bbcbbbed5", 16)
    assert drbg._C == int("8ea2691d1915ebb4975593ca3fbad0ba137026d901a95950a207c41dc7773e15c1e85f4a5f91002866830bebe5c4ee1785b839323fbb44", 16)

    drbg.reseed(bytes.fromhex("e62b8a8ee8f141b6980566e3bfe3c04903dad4ac2cdf9f2280010a6739bc83d3"))
    assert drbg._V == int("59177d93843f0550f33933a51eb488168699ab9c85651536a61f7ec71e8b274a151f17e56becaf531dcfc955f2f1adb6536d51b256d53c", 16)

    drbg.generate(128)  # discard generate-1 output (1024 bits = 128 bytes)
    output = drbg.generate(128)
    expected = bytes.fromhex(
        "04eec63bb231df2c630a1afbe724949d005a587851e1aa795e477347c8b056621"
        "c18bddcdd8d99fc5fc2b92053d8cfacfb0bb8831205fad1ddd6c071318a6018f0"
        "3b73f5ede4d4d071f9de03fd7aea105d9299b8af99aa075bdb4db9aa28c18d174"
        "b56ee2a014d098896ff2282c955a81969e069fa8ce007a180183a07dfae17"
    )
    assert output == expected


def _kat2() -> None:
    """KAT-2: strength=192, SHA-384, seedlen=888 bits."""
    drbg = HashDRBG(strength=192, _skip_kat=True)
    drbg.instantiate(
        bytes.fromhex("2d3e072e78b3d5af2d60424b37a1ca56b24ad1b1fb27a9c327db0651cb75341c"),
        bytes.fromhex("147d214920513cd539ce383f810d9551"),
    )
    assert drbg._V == int("bd9fe59036c728dbe30392569dedd9cca0cfaf9e7be20745e28e3a86615149caf4d970062c59b8f0ae7235f5d52762820ce6443cd313289d1c84e1b0e12ee992435008dc32904ea28fad4abfa00ff54adfb7186cb4d335b54ceff76b1992ae1ee3997054e76f88108783744324df96", 16)

    drbg.reseed(bytes.fromhex("7597a56fdbaa0cb66cef235ccb6bbb423ef2a2f19e5a65a7b86dd11d0cee6cd4"))
    assert drbg._V == int("fbcb667f386b611aadf6d76999427af0adeabae5b4b2898bf37a57554f6dbf0758b2095f4b4f06415c8a06f27773cf0f7e48b8c41eb5d7d4d48f628067c773f7ae0b9e24adaf4999b4330d73b0c9340f51b6e9e6f2e3f3d43fb8f4421349bc4e05c4e09202124b76c83b3ecf821f30", 16)

    drbg.generate(192)  # discard generate-1 output (1536 bits = 192 bytes)
    output = drbg.generate(192)
    expected = bytes.fromhex(
        "5d3d1c5ea9e8c219d43511288fc65dbc1a2f6284c59b26d4375f156b75d383d01"
        "ac6773cad41bf5b6d9fc41416933c0459f9b6d481412e38e9dde34cec3529a313"
        "d2e7815bc5c29a550dfd6be3365d0f8fbbe3a33bc07b6b96351834462a2e624d4"
        "ffa0bd1bf9adda378f4ddb6d4f6a99f7e3fa2556e52006b40fe9caa30ff4cbed3"
        "e574e2b3752680ce7117ab880dd3890be9c19f6442b0e2e04684e05f4fffd90f9"
        "7112f0766a589ed82c07af7cba239c36a3d2bf52a25df2c84678556cedf"
    )
    assert output == expected
