"""Command-line interface for randpassgen.

Mirrors the Java RandPassGenerator CLI surface exactly.
Both -flag and --flag forms are accepted for each option.
"""

import argparse
import hashlib
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from randpassgen.drbg import HashDRBG
from randpassgen.entropy import collect_entropy, ENTROPY_GATE_BITS
from randpassgen.generators import CharacterSet, WordSet, HexKeyGen, DEFAULT_USABLE


def _make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="randpassgen",
        description="Generate cryptographically strong passwords, passphrases, and keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # At least one of these is required (enforced in main)
    p.add_argument("-pw",  "--pw",  type=int, metavar="N", help="Generate N passwords")
    p.add_argument("-pp",  "--pp",  type=int, metavar="N", help="Generate N passphrases")
    p.add_argument("-k",   "--k",   type=int, metavar="N", help="Generate N hex keys")
    # Options
    p.add_argument("-str",    "--str",      type=int, default=160, metavar="S", help="Bit strength (default 160)")
    p.add_argument("-v",      "--verbose",  action="store_true",                help="Verbose output")
    p.add_argument("-pwcs",   "--pwcs",     metavar="P",                        help="Password charset pattern")
    p.add_argument("-pwcustom","--pwcustom",metavar="F",                        help="Custom charset file (mutually exclusive with -pwcs)")
    p.add_argument("-pplen",  "--pplen",    type=int, default=8,   metavar="M", help="Max passphrase word length (default 8)")
    p.add_argument("-ppurl",  "--ppurl",    metavar="U",                        help="External wordlist URL")
    p.add_argument("-rcc",    "--rcc",      type=int, default=0,   metavar="N", help="Random camelCase first N letters per word")
    p.add_argument("-enc",    "--enc",      action="store_true",                help="Encrypt generated key(s)")
    p.add_argument("-decrypt","--decrypt",  action="store_true",                help="Decrypt a key file")
    p.add_argument("-log",    "--log",      default="randpass.log",metavar="F", help="Log file path")
    p.add_argument("-out",    "--out",      metavar="F",                        help="Output file path (default stdout)")
    p.add_argument("-c",      "--c",        type=int,              metavar="N", help="Chunk output into groups of N chars")
    p.add_argument("-sep",    "--sep",      default="-",           metavar="S", help="Chunk separator (default '-')")
    return p


def _setup_drbg() -> HashDRBG:
    entropy = collect_entropy(ENTROPY_GATE_BITS)
    nonce = os.urandom(16)
    drbg = HashDRBG(strength=192)  # always SHA-384 per DRBG_STRENGTH=192
    drbg.instantiate(entropy, nonce)
    return drbg


def _chunk(text: str, size: int, sep: str) -> str:
    if size <= 0:
        return text
    return sep.join(text[i:i + size] for i in range(0, len(text), size))


def _key_id(key_hex: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    digest = hashlib.sha384(key_hex.encode("utf-8")).digest()
    return ts + "_" + digest[:8].hex()


def main() -> None:
    parser = _make_parser()
    args = parser.parse_args()

    if not any([args.pw, args.pp, args.k, args.decrypt]):
        parser.print_help()
        sys.exit(1)

    if args.pwcs and args.pwcustom:
        parser.error("-pwcs and -pwcustom are mutually exclusive")

    # Logging
    logging.basicConfig(
        filename=args.log,
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    log = logging.getLogger("randpassgen")

    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout

    try:
        # Key decrypt mode
        if args.decrypt:
            _do_decrypt(args, log)
            return

        drbg = _setup_drbg()
        log.info("DRBG instantiated at strength %d", args.str)

        # Passwords
        if args.pw:
            if args.pwcustom:
                with open(args.pwcustom, encoding="utf-8") as f:
                    charset_str = f.read()
                cs = CharacterSet(charset_str)
            elif args.pwcs:
                cs = CharacterSet(args.pwcs)
            else:
                cs = CharacterSet()
            for _ in range(args.pw):
                pw = cs.get_random_string_by_entropy(args.str, drbg)
                if args.c:
                    pw = _chunk(pw, args.c, args.sep)
                print(pw, file=out)

        # Passphrases
        if args.pp:
            ws = WordSet(max_word_len=args.pplen)
            for _ in range(args.pp):
                words = ws.get_random_words(args.str, drbg, rcc=args.rcc)
                phrase = " ".join(words)
                if args.c:
                    phrase = _chunk(phrase, args.c, args.sep)
                print(phrase, file=out)

        # Keys
        if args.k:
            key_log = logging.getLogger("randpassgen.keys")
            key_handler = logging.FileHandler("randpassGenKeys.log")
            key_log.addHandler(key_handler)

            for _ in range(args.k):
                key_hex = HexKeyGen.generate_key(args.str, drbg)
                kid = _key_id(key_hex)
                key_log.info("KEY_ID=%s", kid)
                log.info("Generated key, KEY_ID=%s", kid)

                output = key_hex
                if args.c:
                    output = _chunk(output, args.c, args.sep)
                print(output, file=out)

                if args.enc:
                    _do_encrypt(key_hex, kid, log)

    finally:
        if out is not sys.stdout:
            out.close()


def _do_encrypt(key_hex: str, kid: str, log: logging.Logger) -> None:
    from randpassgen.crypto import wrap_key
    import getpass
    passphrase = getpass.getpass("Enter passphrase for key encryption (>=16 chars): ")
    wrapped = wrap_key(key_hex, passphrase)
    enc_path = f"{kid}.enc"
    with open(enc_path, "wb") as f:
        f.write(wrapped)
    log.info("Key wrapped and written to %s", enc_path)
    print(f"Key encrypted to {enc_path}", file=sys.stderr)


def _do_decrypt(args: argparse.Namespace, log: logging.Logger) -> None:
    from randpassgen.crypto import unwrap_key, KeyWrapError
    import getpass
    enc_file = input("Enter path to .enc file: ").strip()
    with open(enc_file, "rb") as f:
        wrapped = f.read()
    passphrase = getpass.getpass("Enter passphrase: ")
    try:
        key_bytes = unwrap_key(wrapped, passphrase)
        print(key_bytes.decode("utf-8"))
        log.info("Key decrypted successfully from %s", enc_file)
    except KeyWrapError as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)
