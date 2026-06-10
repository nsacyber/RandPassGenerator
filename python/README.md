# RandPassGenerator — Python

Python implementation of RandPassGenerator. Full feature parity with the Java version.

## Install

```bash
pip install randpassgen
```

## CLI

```bash
randpassgen -pw 3            # 3 passwords (160-bit, default charset)
randpassgen -pp 1 -str 256   # 1 passphrase at 256-bit strength
randpassgen -k 1             # 1 hex key
randpassgen --help           # all options
```

Both single-dash (`-pw`) and double-dash (`--pw`) forms are accepted.

## Library

```python
from randpassgen import generate_password, generate_passphrase, generate_key

pw  = generate_password(strength=160)
pp  = generate_passphrase(strength=160)
key = generate_key(strength=256)
```

## Test

```bash
pip install -e .[dev]
pytest
```

## Build

Requires Python 3.11+.

```bash
pip install hatchling
python -m hatchling build
```
