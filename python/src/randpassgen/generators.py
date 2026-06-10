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


class WordSet:
    """Loads a wordlist and draws uniform random words from it.

    Reference: WordSet.java
    """

    MIN_WORD_LEN = 3
    MAX_WORD_LEN = 8

    def __init__(
        self,
        min_word_len: int = MIN_WORD_LEN,
        max_word_len: int = MAX_WORD_LEN,
        wordlist_path: Optional[str] = None,
    ) -> None:
        self._min = min_word_len
        self._max = max_word_len
        self._buf: Optional[list[int]] = None
        self._buf_idx: int = 0

        if wordlist_path:
            with open(wordlist_path, encoding="utf-8") as f:
                lines = f.readlines()
        else:
            data = files("randpassgen.data").joinpath("wordlist.txt").read_text(encoding="utf-8")
            lines = data.splitlines()

        seen: set[str] = set()
        self._words: list[str] = []
        for line in lines:
            word = line.strip().lower()
            if min_word_len <= len(word) <= max_word_len and word not in seen:
                seen.add(word)
                self._words.append(word)

    def size(self) -> int:
        return len(self._words)

    def contains(self, word: str) -> bool:
        return word.lower() in set(self._words)

    def bits_per_word(self) -> float:
        return math.log2(self.size())

    def _fill_buf(self, drbg: HashDRBG) -> None:
        raw = drbg.generate_bytes(_BUFSIZE * 2)
        self._buf = [(raw[i * 2] << 8 | raw[i * 2 + 1]) & 0x7FFF for i in range(_BUFSIZE)]
        self._buf_idx = 0

    def _next_uniform_index(self, drbg: HashDRBG) -> int:
        """Rejection-sample a uniform index into the word list."""
        max_val = self.size()
        # For large word lists, use 32-bit values (combining two 16-bit values)
        if max_val > _RLIM_MAX:
            max_32bit = 0x7FFFFFFF
            rlim = (max_32bit // max_val) * max_val
            while True:
                if self._buf is None or self._buf_idx + 1 >= len(self._buf):
                    self._fill_buf(drbg)
                # Combine two 16-bit values into a 32-bit value
                sval = (self._buf[self._buf_idx] << 16 | self._buf[self._buf_idx + 1]) & 0x7FFFFFFF
                self._buf_idx += 2
                if sval < rlim:
                    return sval % max_val
        else:
            rlim = (_RLIM_MAX // max_val) * max_val
            while True:
                if self._buf is None or self._buf_idx >= len(self._buf):
                    self._fill_buf(drbg)
                sval = self._buf[self._buf_idx]
                self._buf_idx += 1
                if sval < rlim:
                    return sval % max_val

    @staticmethod
    def random_upcase(word: str, rcc: int, drbg: HashDRBG) -> str:
        """Randomly capitalise the first rcc letters of a word at 50% per letter."""
        if rcc <= 0:
            return word
        result = list(word)
        for i in range(min(rcc, len(word))):
            if ord(drbg.generate_bytes(1)) >= 128:  # 50% chance via single byte
                result[i] = result[i].upper()
        return "".join(result)

    def get_random_words(
        self, strength_bits: int, drbg: HashDRBG, rcc: int = 0
    ) -> list[str]:
        """Return a list of random words meeting the requested bit strength."""
        count = math.ceil(strength_bits / self.bits_per_word())
        words = [self._words[self._next_uniform_index(drbg)] for _ in range(count)]
        if rcc > 0:
            words = [self.random_upcase(w, rcc, drbg) for w in words]
        return words


class HexKeyGen:
    """Generates a cryptographic hex key of the requested bit strength."""

    @staticmethod
    def generate_key(strength_bits: int, drbg: HashDRBG) -> str:
        """Return a hex-encoded key of strength_bits length."""
        num_bytes = (strength_bits + 7) // 8
        return drbg.generate_bytes(num_bytes).hex()
