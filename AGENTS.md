# AGENTS.md — RandPassGenerator

Operational reference for AI agents working on this repository.

---

## Project Snapshot

RandPassGenerator is a **Java CLI tool** for generating cryptographically strong random passwords, passphrases, and hexadecimal keys. It is built on a NIST SP800-90 Hash DRBG (SHA-384) that seeds from `java.security.SecureRandom` and requires ≥ 888 bits of entropy before producing any output. Runtime NIST known-answer tests and self-tests run on every invocation.

- Language: **Java** (JDK 9+)
- Build: **Apache Ant**
- License: **CC0 1.0 (public domain)** — see `LICENSE.md`
- Origin: NSA Cybersecurity ([nsacyber](https://github.com/nsacyber)); primary author Neal Ziring

For full context see [`docs/PROJECT_OVERVIEW.md`](docs/PROJECT_OVERVIEW.md).

---

## Repository Structure

```
RandPassGenerator/               ← git repo root
├── AGENTS.md                    ← this file
├── README.md
├── LICENSE.md / DISCLAIMER.md / CONTRIBUTING.md
├── docs/
│   └── PROJECT_OVERVIEW.md
├── python/                      ← Python port (pip install -e .[dev])
│   ├── pyproject.toml
│   ├── README.md
│   ├── tests/
│   │   ├── test_drbg.py
│   │   ├── test_generators.py
│   │   ├── test_crypto.py
│   │   ├── test_api.py
│   │   └── test_cli.py
│   └── src/randpassgen/
│       ├── __init__.py
│       ├── __main__.py
│       ├── drbg.py
│       ├── entropy.py
│       ├── generators.py
│       ├── crypto.py
│       ├── cli.py
│       └── data/
│           └── wordlist.txt
└── RandPassGenerator/           ← Ant project root (run all ant commands here)
    ├── build.xml
    ├── BUILD.txt                ← canonical build + test instructions
    ├── CHANGELOG.txt
    ├── data/
    │   ├── wordlist.txt         ← 117,435-word dictionary (bundled into jar)
    │   └── custom-sample.txt
    └── src/gov/nsa/ia/
        ├── drbg/                ← EntropySource implementations + HashDRBG
        ├── gen/                 ← CharacterSet, WordSet, HexKeyGen
        ├── pass/                ← RandPassGenerator (main), RandManager
        └── util/                ← OptionManager, Hash, KeyWrapper, KeyUnwrapper, …
```

---

## Build, Run, and Test Commands

All Ant commands run from `RandPassGenerator/` (the subdir containing `build.xml`).

```bash
# Compile + package (produces build/jar/PassGenerator.jar)
cd RandPassGenerator && ant jar

# Remove all build artifacts
ant clean

# Build and run with no args (prints usage)
ant run

# Run the built jar directly
java -jar RandPassGenerator/build/jar/PassGenerator.jar [options]

# --- Per-class manual tests (no framework) ---
# Compile first, then run individual class mains from build/classes:
ant compile
cd RandPassGenerator/build/classes
java gov.nsa.ia.gen.CharacterSet
java gov.nsa.ia.gen.WordSet file:///usr/share/dict/words
java gov.nsa.ia.drbg.HashDRBG
java gov.nsa.ia.pass.RandManager
# See BUILD.txt for the complete list
```

> **Runtime self-tests are mandatory.** `RandManager` runs NIST known-answer tests and statistical self-tests before any output. The tool aborts if they fail — this is expected and correct behavior, not a bug.

> **Jar name:** `build.xml` outputs `PassGenerator.jar`. The file `README.txt` says `RandPassGenerator.jar` — that is a documentation error; the actual artifact is `PassGenerator.jar`.

### Python (`python/`)

```bash
# Install in editable mode (run once after cloning)
cd python && pip install -e .[dev]

# Run tests
cd python && pytest -v

# Run a specific test file
cd python && pytest tests/test_drbg.py -v

# Run the CLI
randpassgen -pw 3
randpassgen --help

# Build wheel
cd python && pip install hatchling && python -m hatchling build
```

> **Runtime self-tests are mandatory.** `HashDRBG` runs NIST known-answer tests on first instantiation per process. `RuntimeError` is raised if they fail — this is expected behavior, not a bug.

---

## Code Conventions

- **Naming:** `PascalCase` for classes, `camelCase` for methods and fields, `UPPER_SNAKE_CASE` for constants.
- **Javadoc:** Thorough on all public classes and methods; often includes algorithm citations (e.g. SP800-90 section numbers), reviewer notes (`POST-REVIEW NOTES`), and inline `TODO` comments.
- **Error handling:** Generation-path methods return `-1` or `null` on failure rather than throwing. Reserve exceptions for truly exceptional conditions. Log failures at `WARNING` or `SEVERE` via `java.util.logging`.
- **Logging:** Use `java.util.logging.Logger`. Log at `FINE` for trace-level, `INFO` for normal events, `WARNING`/`SEVERE` for failures.
- **Never log secret material:** Key values, DRBG seed/entropy bytes, and raw random output must never appear in any log file — not even at `FINE` level.

**Python:** `snake_case` for functions, methods, and variables; `PascalCase` for classes; `UPPER_SNAKE_CASE` for constants; `_` prefix for private helpers. Type hints on all public functions. No public API should expose DRBG state or internal implementation details.

---

## Security Constraints — Do Not Violate

This is cryptographic code. The following constraints are non-negotiable:

1. **Do not weaken the DRBG.** `HashDRBG` (NIST SP800-90 Hash DRBG, SHA-384) must remain the sole random source for all output. Do not substitute `java.util.Random`, `Math.random()`, `SecureRandom.nextBytes()` directly, or any other generator in generation paths.

2. **Do not reduce entropy gating.** `RandManager` requires ≥ 888 bits of entropy before the DRBG is instantiated. Do not lower this threshold.

3. **Keep the self-tests intact.** `RandManager.performDRBGKATest()` and `performSelfTest()` run before any output. Do not remove, skip, or weaken them. Known-answer test vectors in `HashDRBGKnownAnswerTest` must not be altered.

4. **Preserve the Key ID scheme.** Key IDs are `timestamp + hex(SHA-384(key)[0..7])`. The Key ID is logged; the key itself is not. Do not reverse this.

5. **Preserve the CLI option surface.** The flags `-pw`, `-pp`, `-k`, `-str`, `-enc`, `-decrypt`, `-pwcs`, `-pwcustom`, `-pplen`, `-ppurl`, `-rcc`, `-log`, `-out`, `-c`, `-sep`, `-v` and their documented semantics must remain unchanged unless explicitly instructed otherwise.

6. **AES Key Wrap uses approved algorithms.** `KeyWrapper`/`KeyUnwrapper` implement NIST SP800-38F/RFC 3394 with a PBKDF2 (SP800-132) KEK. Do not replace or simplify this cipher path.

---

## Key Constants (Reference)

Defined in `RandPassGenerator.java`:

| Constant | Value |
|---|---|
| `VERSION` | `"RandPassGen 1.3.4 - 2023-12-22"` |
| `DEFAULT_STRENGTH` | `160` (bits) |
| `MAX_WORD_LEN` | `8` |
| `MIN_WORD_LEN` | `3` |
| `DEFAULT_LOGFILE` | `randpass.log` |
| `DEFAULT_KEYLOGFILE` | `randpassGenKeys.log` |
| `DEFAULT_CHUNK_SEPARATOR` | `-` |

Defined in `RandManager.java`:

| Constant | Value |
|---|---|
| `DRBG_STRENGTH` | `192` (bits, internal DRBG strength, SHA-384) |

---

## Further Reading

| File | Content |
|---|---|
| [`docs/PROJECT_OVERVIEW.md`](docs/PROJECT_OVERVIEW.md) | Full architecture, CLI reference, build guide |
| [`RandPassGenerator/BUILD.txt`](RandPassGenerator/BUILD.txt) | Canonical build + per-class test instructions |
| [`RandPassGenerator/CHANGELOG.txt`](RandPassGenerator/CHANGELOG.txt) | Full version history (1.0.1 → 1.3.4) |
| [`README.md`](README.md) | User-facing README (references v1.3.3 — slightly out of date) |
| [`RandPassGenerator/README.txt`](RandPassGenerator/README.txt) | Up-to-date usage reference (v1.3.4) |

---

## Python Implementation

The `python/` directory contains a full Python port of RandPassGenerator. It is installed with `pip install -e .[dev]` from the `python/` directory. See `python/README.md` for usage.

The Java codebase at `RandPassGenerator/` remains the authoritative reference. The Python port matches Java's behavior exactly, including DRBG state machine, KAT vectors, rejection sampling, AES Key Wrap parameters, and Key ID scheme.
