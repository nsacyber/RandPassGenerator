"""CLI integration tests — invokes randpassgen as a subprocess."""

import re
import subprocess
import sys


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "randpassgen", *args],
        capture_output=True, text=True
    )


class TestCLIBasic:
    def test_no_args_exits_nonzero(self):
        result = run()
        assert result.returncode != 0

    def test_help_exits_zero(self):
        result = run("--help")
        assert result.returncode == 0
        assert "-pw" in result.stdout

    def test_generate_one_password(self):
        result = run("-pw", "1")
        assert result.returncode == 0
        lines = result.stdout.strip().splitlines()
        assert len(lines) == 1
        assert len(lines[0]) == 27  # ceil(160/6)

    def test_generate_three_passwords(self):
        result = run("-pw", "3")
        assert result.returncode == 0
        assert len(result.stdout.strip().splitlines()) == 3

    def test_generate_passphrase(self):
        result = run("-pp", "1")
        assert result.returncode == 0
        words = result.stdout.strip().split()
        assert len(words) >= 8

    def test_generate_key(self):
        result = run("-k", "1")
        assert result.returncode == 0
        key = result.stdout.strip()
        assert len(key) == 40  # 160-bit key = 40 hex chars
        bytes.fromhex(key)  # validates it's valid hex

    def test_strength_256_password(self):
        result = run("-pw", "1", "-str", "256")
        assert result.returncode == 0
        pw = result.stdout.strip()
        assert len(pw) == 43  # ceil(256/6)

    def test_chunk_output(self):
        result = run("-pw", "1", "-c", "5", "-sep", "-")
        assert result.returncode == 0
        pw = result.stdout.strip()
        assert "-" in pw  # chunked output contains separator

    def test_pwcs_custom_charset(self):
        result = run("-pw", "5", "-pwcs", "abc")
        assert result.returncode == 0
        for line in result.stdout.strip().splitlines():
            assert all(c in "abc" for c in line)

    def test_pwcs_and_pwcustom_mutually_exclusive(self):
        result = run("-pw", "1", "-pwcs", "abc", "-pwcustom", "nonexistent.txt")
        assert result.returncode != 0

    def test_two_passwords_are_different(self):
        r1 = run("-pw", "1")
        r2 = run("-pw", "1")
        assert r1.stdout != r2.stdout

    def test_verbose_flag(self):
        result = run("-pw", "1", "-v")
        assert result.returncode == 0

    def test_pplen_respected(self):
        result = run("-pp", "10", "-pplen", "5")
        assert result.returncode == 0
        for line in result.stdout.strip().splitlines():
            for word in line.split():
                assert len(word) <= 5

    def test_multiple_output_types(self):
        result = run("-pw", "2", "-pp", "2", "-k", "2")
        assert result.returncode == 0
        assert len(result.stdout.strip().splitlines()) == 6
