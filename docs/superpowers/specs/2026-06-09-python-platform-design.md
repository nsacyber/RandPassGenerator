# Design: Python Platform Support for RandPassGenerator

**Date:** 2026-06-09  
**Status:** Approved  
**Scope:** Add Python as a first-class implementation alongside Java in the existing monorepo

---

## Context and Motivation

RandPassGenerator is a mature Java CLI tool (v1.3.4) for generating cryptographically strong passwords, passphrases, and hex keys. It is built on a NIST SP800-90 Hash DRBG (SHA-384) with mandatory runtime self-tests and is published under CC0.

The goal is to make the tool accessible to the Python ecosystem — both as a CLI (installable via `pip`) and as an importable library — without disturbing the existing Java implementation. Python is the first new language target; others (Go, Rust) may follow once the monorepo pattern is established.

---

## Decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| Repo organization | Monorepo, Java stays at `RandPassGenerator/` | Avoids breaking existing paths; Python goes in new `python/` sibling |
| Feature scope | Full parity with Java | Passwords, passphrases, hex keys, AES Key Wrap, NIST KATs, same CLI flags, Key ID logging |
| External dependencies | `cryptography` (PyCA) required | Stdlib has no AES Key Wrap; `cryptography` is the ecosystem standard |
| Python API surface | CLI + importable library | `pip install randpassgen` installs both `randpassgen` command and public Python API |
| Distribution | PyPI only for now | GitHub Releases binary and CI/CD are follow-on work |
| Python minimum version | 3.11+ | `importlib.resources` stable API for package data; `tomllib` in stdlib |

---

## Repository Structure

The repo root gains a `python/` directory alongside the existing `RandPassGenerator/` (Java) subdir. No Java files are moved or renamed.

```text
RandPassGenerator/                    ← repo root
├── RandPassGenerator/                ← Java (unchanged)
│   ├── build.xml
│   ├── BUILD.txt / README.txt / CHANGELOG.txt
│   ├── data/
│   │   └── wordlist.txt              ← 117,435-word dictionary (source of truth)
│   └── src/gov/nsa/ia/
│       ├── drbg/  gen/  pass/  util/
│
├── python/                           ← NEW
│   ├── pyproject.toml
│   ├── README.md
│   ├── tests/
│   │   ├── test_drbg.py              ← NIST SP800-90 known-answer tests
│   │   ├── test_generators.py        ← CharacterSet, WordSet, HexKeyGen
│   │   ├── test_crypto.py            ← AES Key Wrap round-trips
│   │   └── test_cli.py               ← CLI integration (subprocess)
│   └── src/randpassgen/
│       ├── __init__.py               ← public library API
│       ├── drbg.py                   ← NIST SP800-90 Hash DRBG
│       ├── entropy.py                ← os.urandom entropy source + gating
│       ├── generators.py             ← CharacterSet, WordSet, HexKeyGen
│       ├── crypto.py                 ← AES Key Wrap / PBKDF2
│       ├── cli.py                    ← argparse CLI
│       └── data/
│           └── wordlist.txt          ← copy of RandPassGenerator/data/wordlist.txt
│
├── docs/
│   ├── PROJECT_OVERVIEW.md           ← update to cover both implementations
│   └── superpowers/specs/            ← this file lives here
├── AGENTS.md                         ← update with Python build/test commands
└── README.md                         ← update to link both implementations
```

---

## Python Module Architecture

Each module has a single responsibility and maps to the Java layered design.

### `drbg.py` — NIST SP800-90 Hash DRBG

Direct port of `HashDRBG.java`. Uses `hashlib.sha384` as the underlying hash. Implements:

- `HashDRBG`: `instantiate(entropy, nonce, personalization)`, `generate(num_bits, additional_input)`, `reseed(entropy, additional_input)`, `uninstantiate()`
- `HashDRBGKnownAnswerTest`: runs the same NIST published test vectors as the Java `HashDRBGKnownAnswerTest` class
- Internal strength fixed at 192 bits (SHA-384), matching `RandManager.DRBG_STRENGTH`
- Known-answer tests run at `HashDRBG` instantiation time (before any output); raise `RuntimeError` on failure (same abort behavior as Java — mirrors when `RandManager.performDRBGKATest()` is called)

**Stdlib only** — no external dependencies.

### `entropy.py` — Entropy Source

Wraps `os.urandom`. Provides `collect_entropy(num_bits) -> bytes`. Enforces the ≥ 888-bit entropy gate before DRBG instantiation — raises `EntropyError` if the OS cannot provide enough entropy. This matches the minimum-entropy check in Java's `RandManager`.

**Stdlib only.**

### `generators.py` — Output Generators

Three classes, directly ported from Java:

**`CharacterSet`**

- Builds a de-duplicated character list from a pattern string or custom file
- `bits_per_item` = `math.log2(len(charset))`
- `get_random_string(strength_bits, drbg)` — computes `length = ceil(strength / bits_per_item)`, draws uniform chars via rejection sampling
- Default charset: same 64 unambiguous characters as Java (`DEFAULT_USABLE`)

**`WordSet`**

- Loads `data/wordlist.txt` via `importlib.resources`
- Filters by word length (`min_len=3`, `max_len=8` by default)
- `get_random_words(strength_bits, drbg)` — computes word count from `math.log2(len(wordlist))`; rejection sampling for uniformity
- `random_upcase(word, n)` — applies random camelCase to first `n` letters at 50% per letter

**`HexKeyGen`**

- `generate_key(strength_bits, drbg) -> str` — returns a hex-encoded key of the requested bit length

**Stdlib only** (plus `importlib.resources` for wordlist access).

### `crypto.py` — AES Key Wrap

Implements NIST SP800-38F / RFC 3394 AES Key Wrap and PBKDF2 key derivation, matching `KeyWrapper.java` and `KeyUnwrapper.java`:

- `derive_kek(passphrase: str, salt: bytes, iterations: int) -> bytes` — PBKDF2-HMAC-SHA256 key derivation (NIST SP800-132)
- `wrap_key(key: bytes, passphrase: str) -> bytes` — AES Key Wrap; writes `<KEY_ID>.enc` file
- `unwrap_key(wrapped: bytes, passphrase: str) -> bytes` — decrypts and unwraps

**External dependency:** `cryptography` (PyCA).

### `cli.py` — Command-Line Interface

`argparse`-based CLI. Entry point: `randpassgen.cli:main`. Each flag is registered with both single-dash short form and double-dash long form (e.g. `-pw` and `--pw`) so the Python CLI accepts the same invocations as the Java CLI. Full flag mapping:

| Java flag | Python flag | Description |
| --- | --- | --- |
| `-pw N` | `-pw / --pw N` | Generate N passwords |
| `-pp N` | `-pp / --pp N` | Generate N passphrases |
| `-k N` | `-k / --k N` | Generate N hex keys |
| `-str S` | `-str / --str S` | Bit strength (default 160) |
| `-v` | `-v / --verbose` | Verbose output |
| `-pwcs P` | `-pwcs / --pwcs P` | Password charset pattern |
| `-pwcustom F` | `-pwcustom / --pwcustom F` | Custom charset file |
| `-pplen M` | `-pplen / --pplen M` | Max passphrase word length |
| `-ppurl U` | `-ppurl / --ppurl U` | External wordlist URL |
| `-rcc N` | `-rcc / --rcc N` | Random camelCase first N letters |
| `-enc` | `-enc / --enc` | Encrypt generated key(s) |
| `-decrypt` | `-decrypt / --decrypt` | Decrypt a key file |
| `-log F` | `-log / --log F` | Log file path (default `randpass.log`) |
| `-out F` | `-out / --out F` | Output file path (default stdout) |
| `-c N` | `-c / --c N` | Chunk output into groups of N chars |
| `-sep S` | `-sep / --sep S` | Chunk separator (default `-`) |

Key ID generation: same scheme as Java — `yyyyMMdd_HHmmss` timestamp + hex of first 8 bytes of SHA-384(key). Logged to `randpassGenKeys.log`; key value never logged.

### `__init__.py` — Public Library API

```python
from randpassgen import generate_password, generate_passphrase, generate_key

pw  = generate_password(strength=160, charset=None)           # -> str
pp  = generate_passphrase(strength=160, max_word_len=8)       # -> str
key = generate_key(strength=160)                               # -> str (hex)
```

Each function instantiates a fresh `HashDRBG` (with KAT self-test) and returns one output. For batch generation (N > 1) or advanced options (custom charset, Key Wrap), users use the CLI or import the lower-level classes directly.

---

## Packaging (`pyproject.toml`)

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "randpassgen"
version = "1.4.0"
requires-python = ">=3.11"
dependencies = ["cryptography"]

[project.scripts]
randpassgen = "randpassgen.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/randpassgen"]
# wordlist.txt included as package data via MANIFEST / include-pattern
```

The `wordlist.txt` is included in the wheel as package data and accessed at runtime via `importlib.resources.files("randpassgen.data").joinpath("wordlist.txt")`.

---

## Testing Strategy

All tests live in `python/tests/` and run with `pytest`.

| Test file | What it covers |
| --- | --- |
| `test_drbg.py` | NIST SP800-90 Hash DRBG known-answer tests (same vectors as Java) |
| `test_generators.py` | CharacterSet: correct length, charset uniformity; WordSet: word count, length filtering; HexKeyGen: output length and hex validity |
| `test_crypto.py` | AES Key Wrap round-trip (wrap → unwrap → assert equal); PBKDF2 determinism |
| `test_cli.py` | Subprocess invocations of `randpassgen` covering all major flag combinations; self-test abort on bad DRBG |

Run tests: `cd python && pip install -e .[dev] && pytest`

---

## Data File Strategy

`RandPassGenerator/data/wordlist.txt` remains the **single source of truth**. During development, `python/src/randpassgen/data/wordlist.txt` is either:

- A **copy** committed to the repo (simplest; slightly redundant), or
- A **symlink** to `../../RandPassGenerator/data/wordlist.txt` (stays in sync automatically but symlinks can be fragile on Windows)

Recommended: copy, kept in sync manually. The wordlist changes rarely (not since v1.0). Document this in `AGENTS.md`.

---

## Documentation Updates

Three existing docs require updates once implementation is done:

| File | Update needed |
| --- | --- |
| `README.md` | Add Python quickstart section alongside the Java build instructions |
| `docs/PROJECT_OVERVIEW.md` | Add Python architecture section; update repo layout diagram |
| `AGENTS.md` | Add Python build/test/run commands; note the `python/` subdir and `pyproject.toml` conventions |

---

## Out of Scope

The following are explicitly deferred:

- GitHub Actions CI/CD (`.github/workflows/`) — added as follow-on
- PyInstaller binary releases — added as follow-on
- Additional language targets (Go, Rust, Node.js) — future; this design establishes the monorepo pattern they will follow
- Versioning automation / release scripts — future

---

## Version

The Python implementation will be versioned starting at `1.4.0` to signal feature parity with Java 1.3.4 plus the addition of a new platform. Both `pyproject.toml` and `RandPassGenerator.java` (VERSION constant) should be updated to `1.4.0` when the Python port is complete.
