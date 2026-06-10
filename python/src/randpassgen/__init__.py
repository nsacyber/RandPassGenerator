"""randpassgen — cryptographically strong password, passphrase, and key generator.

Public API:
    generate_password(strength=160, charset=None)  -> str
    generate_passphrase(strength=160, max_word_len=8) -> str
    generate_key(strength=160) -> str

Each call instantiates a fresh NIST SP800-90A Hash DRBG seeded from os.urandom.
The first call triggers NIST known-answer tests; RuntimeError is raised if they fail.
"""

import os

from randpassgen.drbg import HashDRBG
from randpassgen.entropy import collect_entropy, ENTROPY_GATE_BITS
from randpassgen.generators import CharacterSet, WordSet, HexKeyGen

__all__ = ["generate_password", "generate_passphrase", "generate_key"]


def _fresh_drbg(strength: int = 192) -> HashDRBG:
    entropy = collect_entropy(ENTROPY_GATE_BITS)
    nonce = os.urandom(16)
    drbg = HashDRBG(strength=strength)
    drbg.instantiate(entropy, nonce)
    return drbg


def generate_password(strength: int = 160, charset: str | None = None) -> str:
    """Generate a single password meeting the requested bit strength.

    Args:
        strength: Bit strength (default 160).
        charset: Optional custom character set string. Defaults to the
                 64-character unambiguous set (no 0/O or 1/l confusion).

    Returns:
        A random password string.
    """
    cs = CharacterSet(charset) if charset else CharacterSet()
    drbg = _fresh_drbg()
    return cs.get_random_string_by_entropy(strength, drbg)


def generate_passphrase(strength: int = 160, max_word_len: int = 8) -> str:
    """Generate a single space-joined passphrase meeting the requested bit strength.

    Args:
        strength: Bit strength (default 160).
        max_word_len: Maximum length of each word (default 8).

    Returns:
        A passphrase of space-separated words.
    """
    ws = WordSet(max_word_len=max_word_len)
    drbg = _fresh_drbg()
    return " ".join(ws.get_random_words(strength, drbg))


def generate_key(strength: int = 160) -> str:
    """Generate a single hex-encoded cryptographic key of the requested bit strength.

    Args:
        strength: Bit strength (default 160).

    Returns:
        Lowercase hex string of length ceil(strength/8)*2.
    """
    drbg = _fresh_drbg()
    return HexKeyGen.generate_key(strength, drbg)
