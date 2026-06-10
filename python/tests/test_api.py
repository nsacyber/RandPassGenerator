import pytest
from randpassgen import generate_password, generate_passphrase, generate_key


def test_generate_password_returns_string():
    pw = generate_password()
    assert isinstance(pw, str)
    assert len(pw) == 27  # ceil(160/6) for DEFAULT_USABLE


def test_generate_password_custom_strength():
    pw = generate_password(strength=256)
    assert len(pw) == 43  # ceil(256/6)


def test_generate_passphrase_returns_words():
    pp = generate_passphrase()
    words = pp.split()
    assert len(words) >= 8  # 160 bits at ~16 bits/word


def test_generate_key_returns_hex():
    key = generate_key()
    assert len(key) == 40  # 160 bits = 20 bytes = 40 hex chars
    bytes.fromhex(key)  # valid hex


def test_generate_key_custom_strength():
    key = generate_key(strength=256)
    assert len(key) == 64


def test_two_passwords_differ():
    assert generate_password() != generate_password()


def test_two_keys_differ():
    assert generate_key() != generate_key()
