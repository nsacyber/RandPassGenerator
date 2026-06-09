import hashlib
import pytest
from randpassgen.drbg import _pbi2ba, _hash_df


class TestPbi2ba:
    def test_zero(self):
        assert _pbi2ba(0) == b'\x00'

    def test_single_byte_low(self):
        assert _pbi2ba(0x01) == b'\x01'

    def test_single_byte_high(self):
        # 0xFF has bit 7 set; pbi2ba returns [0xFF] (1 byte), not [0x00, 0xFF]
        assert _pbi2ba(0xFF) == b'\xff'

    def test_two_bytes(self):
        assert _pbi2ba(0x0100) == b'\x01\x00'

    def test_leading_zero_stripped(self):
        # 0x80 = 128: minimal representation is [0x80] (1 byte)
        assert _pbi2ba(0x80) == b'\x80'

    def test_seedlen_sized_value(self):
        # 111-byte value (888 bits): should return exactly 111 bytes
        n = (1 << 887)  # first 888-bit number
        result = _pbi2ba(n)
        assert len(result) == 111
        assert result[0] == 0x80


class TestHashDf:
    def test_hash_df_sha256_output_length(self):
        """hash_df with SHA-256 and 440-bit request produces 55 bytes."""
        result = _hash_df(b"test", 440, 256)
        assert len(result) == 55

    def test_hash_df_sha384_output_length(self):
        """hash_df with SHA-384 and 888-bit request produces 111 bytes."""
        result = _hash_df(b"test", 888, 384)
        assert len(result) == 111

    def test_hash_df_deterministic(self):
        r1 = _hash_df(b"same input", 256, 256)
        r2 = _hash_df(b"same input", 256, 256)
        assert r1 == r2

    def test_hash_df_different_inputs_differ(self):
        r1 = _hash_df(b"input A", 256, 256)
        r2 = _hash_df(b"input B", 256, 256)
        assert r1 != r2
