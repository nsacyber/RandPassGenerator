"""Password, passphrase, and hex-key generators.

References:
    CharacterSet.java, WordSet.java, HexKeyGen.java
"""

import math
from importlib.resources import files
from typing import Optional

from randpassgen.drbg import HashDRBG

# 64 unambiguous characters (no 0/O or 1/l), exactly 6 bits/char.
# Source: CharacterSet.java DEFAULT_USABLE
DEFAULT_USABLE = "ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789.+:%#$"

_BUFSIZE = 24  # short buffer size (Java: BUFFER_FILL_SIZE = 24)
_RLIM_MAX = 0x7FFF  # Short.MAX_VALUE in Java


class CharacterSet:
    """Builds a de-duplicated character list and draws uniform random characters from it."""

    def __init__(self, chars: str = DEFAULT_USABLE) -> None:
        self._charset: list[str] = []
        self._buf: Optional[list[int]] = None
        self._buf_idx: int = 0
        if chars:
            self._add_unique(chars)

    def add_set(self, chars: str) -> int:
        """Add characters to the set (duplicates ignored). Returns new size."""
        self._add_unique(chars)
        self._buf = None  # reset buffer on charset change (matches Java)
        return self.size()

    def _add_unique(self, chars: str) -> None:
        for c in chars:
            if not (c.isspace() or c == '\x00' or ord(c) < 32):
                if c not in self._charset:
                    self._charset.append(c)

    def size(self) -> int:
        return len(self._charset)

    def bits_per_item(self) -> float:
        return math.log2(self.size())

    def _fill_buf(self, drbg: HashDRBG) -> None:
        raw = drbg.generate_bytes(_BUFSIZE * 2)
        self._buf = [(raw[i * 2] << 8 | raw[i * 2 + 1]) & 0x7FFF for i in range(_BUFSIZE)]
        self._buf_idx = 0

    def _next_uniform_short(self, max_val: int, drbg: HashDRBG) -> int:
        """Uniform int in [0, max_val) via rejection sampling (Java nextUniformShort)."""
        rlim = (_RLIM_MAX // max_val) * max_val
        while True:
            if self._buf is None or self._buf_idx >= len(self._buf):
                self._fill_buf(drbg)
            sval = self._buf[self._buf_idx]
            self._buf_idx += 1
            if sval < rlim:
                return sval % max_val

    def get_random_string(self, length: int, drbg: HashDRBG) -> str:
        """Return a random string of the given length drawn uniformly from this set."""
        if length <= 0:
            raise ValueError(f"length must be positive, got {length}")
        return "".join(self._charset[self._next_uniform_short(self.size(), drbg)] for _ in range(length))

    def get_random_string_by_entropy(self, strength_bits: int, drbg: HashDRBG) -> str:
        """Return a string long enough to achieve the requested bit strength."""
        length = math.ceil(strength_bits / self.bits_per_item())
        return self.get_random_string(length, drbg)
