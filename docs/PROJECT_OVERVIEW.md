# RandPassGenerator — Project Overview

> Version 1.3.4 (2023-12-22) · CC0 1.0 Public Domain · Originally an [NSA Cybersecurity (nsacyber)](https://github.com/nsacyber) project

## What It Is

RandPassGenerator is a command-line utility for generating cryptographically strong random **passwords**, **passphrases**, and **raw hexadecimal keys**. It is designed conservatively: every generated output offers the full cryptographic bit-strength the user requests, with no shortcuts.

The tool is built on a NIST SP800-90 Hash DRBG (deterministic random bit generator) using SHA-384 as the underlying hash. It seeds exclusively from the JVM's `SecureRandom` entropy mechanism and requires at least **888 bits of entropy** before generating any output. Runtime self-tests (NIST known-answer tests + statistical checks) run on every invocation; the tool refuses to proceed if any test fails.

Primary author: **Neal Ziring** (`@nziring`). CC0 1.0 Universal (public domain dedication). See [LICENSE.md](../LICENSE.md) and [DISCLAIMER.md](../DISCLAIMER.md).

---

## Key Features

| Feature | Detail |
|---|---|
| Password generation | Character-set–based; uniform rejection-sampling; default 64-char unambiguous set (no 0/O or 1/l confusion) |
| Passphrase generation | 117,435-word bundled dictionary; uniform word selection; optional random camelCase (`-rcc`) |
| Hex key generation | Raw cryptographic keys at any requested bit strength |
| Strength model | Output length/word-count computed from `ceil(strength / bitsPerChar\|bitsPerWord)` to *meet or exceed* the requested bits |
| Default strength | 160 bits |
| DRBG internal strength | 192 bits (SHA-384 Hash DRBG per NIST SP800-90) |
| Self-tests | NIST known-answer tests + statistical size/range checks; executed before every output |
| AES Key Wrap | Encrypt/decrypt generated keys using PBKDF2-derived KEK (NIST SP800-38F/RFC 3394, SP800-132) |
| Key transaction log | Separate `randpassGenKeys.log`; records Key ID = timestamp + first 64 bits of SHA-384(key); never logs the key itself |
| Logging | `java.util.logging` to configurable log file; never records key, seed, or random material |
| Dependencies | Zero external libraries; pure JDK + Apache Ant |

---

## Architecture

The code is organized in four layers, each a Java package under `gov.nsa.ia`:

```
Entropy Sources  →  DRBG  →  RandManager  →  Generators  →  Application
   (drbg/)          (drbg/)    (pass/)          (gen/)         (pass/)
```

### `drbg/` — Entropy and DRBG Core

| Class | Role |
|---|---|
| `EntropySource` | Interface for all entropy sources |
| `JavaSecRandEntropySource` | Production source — wraps `java.security.SecureRandom` |
| `FileEntropySource`, `UnixDevRandomEntropySource` | Alternate production-capable sources |
| `LousyEntropySource`, `FixedValuesEntropySource` | Weak/deterministic sources used only in self-tests |
| `EntropyUtil` | Helpers for entropy measurement |
| `DRBG` | Interface for the DRBG |
| `AbstractDRBG` | Abstract base — `generateInteger()`, `generateByte()`, `BigInteger`↔`byte[]` conversion |
| `HashDRBG` | NIST SP800-90 Hash DRBG with SHA-384 (extends `AbstractDRBG`) |
| `HashDRBGKnownAnswerTest` | NIST published test vectors for `HashDRBG` |
| `DRBGConstants` | Status codes (e.g. `STATUS_SUCCESS`) |

### `gen/` — Generators

| Class | Role |
|---|---|
| `CharacterSet` | Builds a de-duped character list; computes `bitsPerItem = log2(size)`; produces a random string of the required length by rejection-sampling uniform characters |
| `WordSet` | Loads the bundled `wordlist.txt` (or a URL-supplied list) into a de-duped, length-filtered set; selects words by rejection-sampling; applies random camelCase (`randomUpcase`) |
| `HexKeyGen` | Produces raw hex keys of the requested bit strength from the DRBG |

### `pass/` — Application Entry Point and DRBG Lifecycle

| Class | Role |
|---|---|
| `RandManager` | Owns the `HashDRBG` lifecycle — instantiation, reseeding, known-answer and self-tests; exposes `getDRBG()` and `generateKey(numBytes)` |
| `RandPassGenerator` | `main()` entry point; CLI parsing via `OptionManager`; orchestrates `RandManager` + generators; chunk formatting; key transaction logging |

### `util/` — Utilities

| Class | Role |
|---|---|
| `OptionManager` | CLI option parser and usage-message generator |
| `Hash` | Hashing wrapper |
| `KeyWrapper` / `KeyUnwrapper` | AES Key Wrap encryption/decryption (PBKDF2 KEK) |
| `SelfTestable` | Interface for components with runtime self-tests |
| `LousyEntropySource`, `FixedValuesEntropySource` | (also in `drbg/`; test-support entropy sources) |

---

## Repository Layout

```
RandPassGenerator/               ← git repo root
├── README.md                    ← User-facing README (v1.3.3 — slightly behind code)
├── CONTRIBUTING.md              ← CC0 contributor waiver
├── LICENSE.md                   ← CC0 1.0 Universal
├── DISCLAIMER.md                ← U.S. Government warranty/endorsement disclaimer
├── .gitignore
├── docs/
│   └── PROJECT_OVERVIEW.md      ← this file
└── RandPassGenerator/           ← project subdir (the actual build root)
    ├── build.xml                ← Apache Ant build file
    ├── BUILD.txt                ← Build and unit-test instructions
    ├── README.txt               ← Usage reference (v1.3.4)
    ├── CHANGELOG.txt            ← Full history 1.0.1 → 1.3.4
    ├── data/
    │   ├── wordlist.txt         ← 117,435-word passphrase dictionary
    │   └── custom-sample.txt    ← Sample custom character-set file (4 lines)
    └── src/gov/nsa/ia/
        ├── drbg/                ← 10 Java files — entropy sources + HashDRBG
        ├── gen/                 ← 3 Java files — CharacterSet, WordSet, HexKeyGen
        ├── pass/                ← 2 Java files — RandPassGenerator, RandManager
        └── util/                ← 7 Java files — OptionManager, Hash, KeyWrapper, …
```

---

## Build and Run

### Requirements

- Java SDK 9 or higher (Java 11+ recommended)
- Apache Ant

### Ant Targets

All commands run from `RandPassGenerator/` (the project subdir containing `build.xml`):

```bash
cd RandPassGenerator

ant jar      # compile + package → build/jar/PassGenerator.jar
             #   also copies data/wordlist.txt into the jar
ant clean    # delete the build/ directory
ant run      # jar (if needed) then run with no arguments (prints usage)
```

> **Note:** `build.xml` produces `PassGenerator.jar`. The file `RandPassGenerator/README.txt` references `RandPassGenerator.jar` — that name is incorrect; the actual built artifact is `PassGenerator.jar`.

### Running the Jar

```bash
java -jar RandPassGenerator/build/jar/PassGenerator.jar [options]
```

Run with no arguments to print usage and exit. At minimum one of `-pw N`, `-pp N`, or `-k N` is required.

**Main class:** `gov.nsa.ia.pass.RandPassGenerator`

---

## CLI Options

| Option | Argument | Description |
|---|---|---|
| `-pw N` | integer | Generate N passwords |
| `-pp N` | integer | Generate N passphrases |
| `-k N` | integer | Generate N hex keys |
| `-str S` | integer | Bit strength target (default 160) |
| `-v` | — | Verbose output |
| `-pwcs P` | string | Password character-set pattern (see README) |
| `-pwcustom F` | file path | Custom character-set file (mutually exclusive with `-pwcs`) |
| `-pplen M` | integer | Max passphrase word length in chars (min 3, default 8) |
| `-ppurl U` | URL | External wordlist URL (replaces bundled list) |
| `-rcc N` | integer | Random camelCase first N letters of each passphrase word |
| `-enc` | — | Encrypt generated key(s) to `<KEY_ID>.enc` files |
| `-decrypt` | — | Decrypt a key file (prompts on console) |
| `-log F` | file path | Log file path (default `randpass.log`) |
| `-out F` | file path | Output file path (default stdout) |
| `-c N` | integer | Chunk output into groups of N characters |
| `-sep S` | string | Chunk separator string (default `-`) |

---

## Testing

There is no formal test framework (no JUnit, no test directory). Testing is done in two ways:

### 1. Runtime Self-Tests (automatic)

`RandManager.performDRBGKATest()` and `performSelfTest()` run automatically on every invocation before any output is produced. These execute:
- NIST SP800-90 Hash DRBG known-answer tests (`HashDRBGKnownAnswerTest`)
- Statistical range/size checks on the DRBG output

The tool **aborts** if any self-test fails.

### 2. Per-Class Main Methods (manual)

Most core classes contain a `main()` method that exercises the class in isolation. To run them, compile first, then invoke from `build/classes`:

```bash
cd RandPassGenerator
ant compile

cd build/classes
java gov.nsa.ia.gen.CharacterSet
java gov.nsa.ia.gen.WordSet file:///usr/share/dict/words
java gov.nsa.ia.drbg.HashDRBG
java gov.nsa.ia.pass.RandManager
```

See [`RandPassGenerator/BUILD.txt`](../RandPassGenerator/BUILD.txt) for the full list.

---

## Dependencies

| Dependency | Purpose | Notes |
|---|---|---|
| Java JDK 9+ | Runtime + compile | Uses `java.security.SecureRandom`, `javax.crypto`, `java.util.logging`, `java.math.BigInteger`, `java.net.URL` |
| Apache Ant | Build system only | No runtime dependency |

No external Java libraries. Everything is standard JDK.

---

## License and Authorship

- **License:** [CC0 1.0 Universal](../LICENSE.md) — public domain dedication. Work prepared by a U.S. Government employee; excluded from copyright protection under 17 U.S.C. § 105.
- **Primary author:** Neal Ziring (`@nziring` / `nlzirin`)
- **Updates:** `amsagos`
- **Origin:** [NSA Cybersecurity (nsacyber)](https://github.com/nsacyber)
- **Current version:** 1.3.4 (2023-12-22)
- **Warranty:** See [DISCLAIMER.md](../DISCLAIMER.md)

---

## Python Implementation

A complete Python port lives in `python/`. It is installable via `pip install randpassgen` and provides both a `randpassgen` CLI (compatible with all Java flags) and an importable library.

### Python Module Architecture

| Module | Role |
|---|---|
| `entropy.py` | `collect_entropy(num_bits)` — wraps `os.urandom` with ≥888-bit gate |
| `drbg.py` | `HashDRBG` — NIST SP800-90A Hash DRBG (SHA-384); NIST KATs on first instantiation |
| `generators.py` | `CharacterSet`, `WordSet`, `HexKeyGen` — direct ports of the Java generator classes |
| `crypto.py` | `wrap_key` / `unwrap_key` — AES Key Wrap + PBKDF2-HMAC-SHA512 via `cryptography` (PyCA) |
| `cli.py` | `argparse`-based CLI; mirrors all 16 Java flags |
| `__init__.py` | Public library API: `generate_password()`, `generate_passphrase()`, `generate_key()` |

### Python Testing

71 tests covering NIST known-answer vectors, generator uniformity, AES Key Wrap round-trips, and CLI integration. Run:

```bash
cd python && pip install -e .[dev] && pytest -v
```

### Python Repository Layout

```text
python/
├── pyproject.toml             ← hatchling build config; version 1.4.0
├── README.md
├── tests/
│   ├── test_drbg.py           ← NIST SP800-90A KAT vectors
│   ├── test_generators.py     ← CharacterSet, WordSet, HexKeyGen
│   ├── test_crypto.py         ← AES Key Wrap round-trips
│   ├── test_api.py            ← public library API
│   └── test_cli.py            ← CLI subprocess integration
└── src/randpassgen/
    ├── __init__.py            ← public API
    ├── __main__.py            ← enables python -m randpassgen
    ├── drbg.py
    ├── entropy.py
    ├── generators.py
    ├── crypto.py
    ├── cli.py
    └── data/
        └── wordlist.txt       ← copy of RandPassGenerator/data/wordlist.txt
```
