import math
import pytest
from randpassgen.drbg import HashDRBG
from randpassgen.generators import CharacterSet, WordSet, HexKeyGen


def _make_drbg() -> HashDRBG:
    drbg = HashDRBG(strength=192, _skip_kat=True)
    drbg.instantiate(b'\xaa' * 111, b'\xbb' * 16)
    return drbg


class TestCharacterSet:
    def test_default_usable_size(self):
        cs = CharacterSet()
        assert cs.size() == 64

    def test_bits_per_item_default(self):
        cs = CharacterSet()
        assert abs(cs.bits_per_item() - 6.0) < 1e-9

    def test_deduplication(self):
        cs = CharacterSet("aaabbbccc")
        assert cs.size() == 3

    def test_whitespace_stripped(self):
        cs = CharacterSet("abc def")
        assert cs.size() == 6  # space is stripped

    def test_get_random_string_length(self):
        cs = CharacterSet()
        drbg = _make_drbg()
        pw = cs.get_random_string(20, drbg)
        assert len(pw) == 20

    def test_get_random_string_chars_in_set(self):
        cs = CharacterSet("abc")
        drbg = _make_drbg()
        pw = cs.get_random_string(100, drbg)
        assert all(c in "abc" for c in pw)

    def test_get_random_string_by_entropy_160bits(self):
        cs = CharacterSet()  # DEFAULT_USABLE, 6 bits/char
        drbg = _make_drbg()
        pw = cs.get_random_string_by_entropy(160, drbg)
        # ceil(160/6) = 27 chars
        assert len(pw) == 27

    def test_get_random_string_by_entropy_256bits(self):
        cs = CharacterSet()
        drbg = _make_drbg()
        pw = cs.get_random_string_by_entropy(256, drbg)
        # ceil(256/6) = 43 chars
        assert len(pw) == 43

    def test_custom_charset_from_string(self):
        cs = CharacterSet("XYZ0123456789")
        assert cs.size() == 13

    def test_add_set(self):
        cs = CharacterSet("abc")
        cs.add_set("def")
        assert cs.size() == 6


class TestWordSet:
    def _ws(self, max_len: int = 8) -> WordSet:
        return WordSet(max_word_len=max_len)

    def test_loads_bundled_wordlist(self):
        ws = self._ws()
        assert ws.size() > 10000  # bundled list has 117,435 words

    def test_min_word_length_filter(self):
        ws = WordSet(min_word_len=5, max_word_len=8)
        ws_full = WordSet(min_word_len=3, max_word_len=8)
        assert ws.size() < ws_full.size()

    def test_get_random_words_count(self):
        ws = self._ws()
        drbg = _make_drbg()
        words = ws.get_random_words(160, drbg)
        # Each word ~16 bits entropy for ~117k-word list → ceil(160/16) = 10 words
        assert len(words) >= 8  # at least 8 words for 160-bit strength

    def test_get_random_words_all_in_wordlist(self):
        ws = self._ws()
        drbg = _make_drbg()
        for _ in range(5):
            words = ws.get_random_words(128, drbg)
            for word in words:
                assert ws.contains(word.lower()), f"Word {word!r} not in wordlist"

    def test_random_upcase_first_n(self):
        ws = self._ws()
        drbg = _make_drbg()
        words = ws.get_random_words(128, drbg, rcc=3)
        assert len(words) >= 1


class TestHexKeyGen:
    def test_key_length_160_bits(self):
        drbg = _make_drbg()
        key = HexKeyGen.generate_key(160, drbg)
        assert len(key) == 40  # 160 bits = 20 bytes = 40 hex chars

    def test_key_length_256_bits(self):
        drbg = _make_drbg()
        key = HexKeyGen.generate_key(256, drbg)
        assert len(key) == 64

    def test_key_is_valid_hex(self):
        drbg = _make_drbg()
        key = HexKeyGen.generate_key(160, drbg)
        bytes.fromhex(key)  # raises ValueError if not valid hex

    def test_two_keys_differ(self):
        drbg = _make_drbg()
        k1 = HexKeyGen.generate_key(160, drbg)
        k2 = HexKeyGen.generate_key(160, drbg)
        assert k1 != k2
