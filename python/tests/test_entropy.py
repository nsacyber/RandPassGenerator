import pytest
from randpassgen.entropy import collect_entropy, ENTROPY_GATE_BITS, EntropyError


def test_collect_entropy_returns_correct_length():
    data = collect_entropy(256)
    assert len(data) == 32  # 256 bits = 32 bytes


def test_collect_entropy_nist_gate():
    """Default gate is 888 bits = 111 bytes."""
    data = collect_entropy(ENTROPY_GATE_BITS)
    assert len(data) == 111


def test_collect_entropy_zero_raises():
    with pytest.raises(ValueError):
        collect_entropy(0)


def test_collect_entropy_negative_raises():
    with pytest.raises(ValueError):
        collect_entropy(-1)
