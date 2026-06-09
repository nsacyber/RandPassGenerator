import hashlib
import pytest
from randpassgen.drbg import _pbi2ba, _hash_df, HashDRBG
from randpassgen.entropy import collect_entropy, ENTROPY_GATE_BITS


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


class TestHashDRBGBasic:
    def _make_drbg(self, strength: int = 192) -> HashDRBG:
        drbg = HashDRBG(strength=strength, _skip_kat=True)
        entropy = b'\x00' * (ENTROPY_GATE_BITS // 8)
        nonce = b'\x00' * 16
        drbg.instantiate(entropy, nonce)
        return drbg

    def test_not_instantiated_raises(self):
        drbg = HashDRBG(strength=192, _skip_kat=True)
        with pytest.raises(RuntimeError, match="not instantiated"):
            drbg.generate(16)

    def test_generate_returns_correct_length(self):
        drbg = self._make_drbg()
        assert len(drbg.generate(32)) == 32
        assert len(drbg.generate(1)) == 1
        assert len(drbg.generate(100)) == 100

    def test_generate_is_nondeterministic_across_instances(self):
        """Two DRBGs with different entropy produce different output."""
        drbg1 = HashDRBG(strength=192, _skip_kat=True)
        drbg1.instantiate(b'\x00' * 111, b'\x00' * 16)
        drbg2 = HashDRBG(strength=192, _skip_kat=True)
        drbg2.instantiate(b'\xff' * 111, b'\x00' * 16)
        assert drbg1.generate(32) != drbg2.generate(32)

    def test_reseed_counter_increments(self):
        drbg = self._make_drbg()
        assert drbg._reseed_counter == 1
        drbg.generate(16)
        assert drbg._reseed_counter == 2
        drbg.generate(16)
        assert drbg._reseed_counter == 3

    def test_reseed_resets_counter(self):
        drbg = self._make_drbg()
        drbg.generate(16)
        drbg.generate(16)
        assert drbg._reseed_counter == 3
        drbg.reseed(b'\xab' * 111)
        assert drbg._reseed_counter == 1

    def test_uninstantiate(self):
        drbg = self._make_drbg()
        drbg.generate(16)  # advance counter to 2
        drbg.uninstantiate()
        assert not drbg.is_instantiated()
        assert drbg._reseed_counter == 0
        with pytest.raises(RuntimeError):
            drbg.generate(16)

    def test_strength_128_uses_sha256_seedlen_440(self):
        drbg = HashDRBG(strength=128, _skip_kat=True)
        drbg.instantiate(b'\x00' * 55, b'\x00' * 16)
        assert drbg._seedlen == 55
        assert drbg._hashbits == 256

    def test_strength_192_uses_sha384_seedlen_888(self):
        drbg = HashDRBG(strength=192, _skip_kat=True)
        assert drbg._seedlen == 111
        assert drbg._hashbits == 384
