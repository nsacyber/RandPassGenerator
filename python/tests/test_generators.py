import math
import pytest
from randpassgen.drbg import HashDRBG
from randpassgen.generators import CharacterSet


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
