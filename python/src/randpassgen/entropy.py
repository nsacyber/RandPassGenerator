"""OS entropy source with minimum-bits gate."""

import os

ENTROPY_GATE_BITS = 888  # minimum entropy for SHA-384 Hash DRBG (seedlen=888 bits)


class EntropyError(RuntimeError):
    """Raised when the OS cannot provide sufficient entropy."""


def collect_entropy(num_bits: int) -> bytes:
    """Collect num_bits of entropy from os.urandom.

    Raises ValueError for non-positive num_bits.
    Raises EntropyError if the OS returns fewer bytes than requested.
    """
    if num_bits <= 0:
        raise ValueError(f"num_bits must be positive, got {num_bits}")
    num_bytes = (num_bits + 7) // 8
    data = os.urandom(num_bytes)
    if len(data) < num_bytes:
        raise EntropyError(f"OS returned {len(data)} bytes, needed {num_bytes}")
    return data
