import pytest
from randpassgen.crypto import derive_kek, wrap_key, unwrap_key, KeyWrapError


class TestPBKDF2:
    def test_derive_kek_returns_32_bytes(self):
        kek = derive_kek("a_strong_passphrase_here")
        assert len(kek) == 32

    def test_derive_kek_deterministic(self):
        k1 = derive_kek("same_passphrase_value1")
        k2 = derive_kek("same_passphrase_value1")
        assert k1 == k2

    def test_derive_kek_different_passphrases_differ(self):
        k1 = derive_kek("passphrase_AAAA_sixteen")
        k2 = derive_kek("passphrase_BBBB_sixteen")
        assert k1 != k2

    def test_short_passphrase_raises(self):
        with pytest.raises(ValueError, match="16"):
            derive_kek("short")


class TestKeyWrap:
    TEST_PASSPHRASE = "9fXMi5JvoHDIGQBM9fXMi5JvoHDIGQBM"

    def test_wrap_returns_bytes(self):
        key_hex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        wrapped = wrap_key(key_hex, self.TEST_PASSPHRASE)
        assert isinstance(wrapped, bytes)
        assert len(wrapped) > 0

    def test_wrap_unwrap_roundtrip(self):
        passphrase = "a_valid_passphrase_16chars"
        key_hex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        wrapped = wrap_key(key_hex, passphrase)
        recovered = unwrap_key(wrapped, passphrase)
        # unwrap returns the UTF-8 bytes of the hex string
        assert recovered == key_hex.encode("utf-8")

    def test_wrong_passphrase_raises(self):
        passphrase = "correct_passphrase_16c"
        key_hex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        wrapped = wrap_key(key_hex, passphrase)
        with pytest.raises(KeyWrapError):
            unwrap_key(wrapped, "wrong_passphrase_16ch")
