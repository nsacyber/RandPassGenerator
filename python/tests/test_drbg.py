import hashlib
import pytest
from randpassgen.drbg import _pbi2ba, _hash_df, HashDRBG
from randpassgen.entropy import collect_entropy, ENTROPY_GATE_BITS


class TestPbi2ba:
    def test_zero(self):
        assert _pbi2ba(0) == b'\x00'

    def test_single_byte_low(self):
        assert _pbi2ba(0x01) == b'\x01'

    def test_single_byte_high(self):
        # 0xFF has bit 7 set; pbi2ba returns [0xFF] (1 byte), not [0x00, 0xFF]
        assert _pbi2ba(0xFF) == b'\xff'

    def test_two_bytes(self):
        assert _pbi2ba(0x0100) == b'\x01\x00'

    def test_leading_zero_stripped(self):
        # 0x80 = 128: minimal representation is [0x80] (1 byte)
        assert _pbi2ba(0x80) == b'\x80'

    def test_seedlen_sized_value(self):
        # 111-byte value (888 bits): should return exactly 111 bytes
        n = (1 << 887)  # first 888-bit number
        result = _pbi2ba(n)
        assert len(result) == 111
        assert result[0] == 0x80


class TestHashDf:
    def test_hash_df_sha256_output_length(self):
        """hash_df with SHA-256 and 440-bit request produces 55 bytes."""
        result = _hash_df(b"test", 440, 256)
        assert len(result) == 55

    def test_hash_df_sha384_output_length(self):
        """hash_df with SHA-384 and 888-bit request produces 111 bytes."""
        result = _hash_df(b"test", 888, 384)
        assert len(result) == 111

    def test_hash_df_deterministic(self):
        r1 = _hash_df(b"same input", 256, 256)
        r2 = _hash_df(b"same input", 256, 256)
        assert r1 == r2

    def test_hash_df_different_inputs_differ(self):
        r1 = _hash_df(b"input A", 256, 256)
        r2 = _hash_df(b"input B", 256, 256)
        assert r1 != r2


class TestHashDRBGBasic:
    def _make_drbg(self, strength: int = 192) -> HashDRBG:
        drbg = HashDRBG(strength=strength, _skip_kat=True)
        entropy = b'\x00' * (ENTROPY_GATE_BITS // 8)
        nonce = b'\x00' * 16
        drbg.instantiate(entropy, nonce)
        return drbg

    def test_not_instantiated_raises(self):
        drbg = HashDRBG(strength=192, _skip_kat=True)
        with pytest.raises(RuntimeError, match="not instantiated"):
            drbg.generate(16)

    def test_generate_returns_correct_length(self):
        drbg = self._make_drbg()
        assert len(drbg.generate(32)) == 32
        assert len(drbg.generate(1)) == 1
        assert len(drbg.generate(100)) == 100

    def test_generate_is_nondeterministic_across_instances(self):
        """Two DRBGs with different entropy produce different output."""
        drbg1 = HashDRBG(strength=192, _skip_kat=True)
        drbg1.instantiate(b'\x00' * 111, b'\x00' * 16)
        drbg2 = HashDRBG(strength=192, _skip_kat=True)
        drbg2.instantiate(b'\xff' * 111, b'\x00' * 16)
        assert drbg1.generate(32) != drbg2.generate(32)

    def test_reseed_counter_increments(self):
        drbg = self._make_drbg()
        assert drbg._reseed_counter == 1
        drbg.generate(16)
        assert drbg._reseed_counter == 2
        drbg.generate(16)
        assert drbg._reseed_counter == 3

    def test_reseed_resets_counter(self):
        drbg = self._make_drbg()
        drbg.generate(16)
        drbg.generate(16)
        assert drbg._reseed_counter == 3
        drbg.reseed(b'\xab' * 111)
        assert drbg._reseed_counter == 1

    def test_uninstantiate(self):
        drbg = self._make_drbg()
        drbg.generate(16)  # advance counter to 2
        drbg.uninstantiate()
        assert not drbg.is_instantiated()
        assert drbg._reseed_counter == 0
        with pytest.raises(RuntimeError):
            drbg.generate(16)

    def test_strength_128_uses_sha256_seedlen_440(self):
        drbg = HashDRBG(strength=128, _skip_kat=True)
        drbg.instantiate(b'\x00' * 55, b'\x00' * 16)
        assert drbg._seedlen == 55
        assert drbg._hashbits == 256

    def test_strength_192_uses_sha384_seedlen_888(self):
        drbg = HashDRBG(strength=192, _skip_kat=True)
        assert drbg._seedlen == 111
        assert drbg._hashbits == 384


class TestHashDRBGKnownAnswerTests:
    """NIST SP800-90A Hash DRBG test vectors from Hash_DRBG.txt (Java HashDRBG.java line 643).

    Two tests:
      KAT-1: strength=128, SHA-256, seedlen=440 bits (55 bytes)
      KAT-2: strength=192, SHA-384, seedlen=888 bits (111 bytes)
    """

    # --- KAT-1 (strength=128, SHA-256) ---
    KAT1_ENTROPY_INST   = bytes.fromhex("63363377e41e86468deb0ab4a8ed683f6a134e47e014c700454e81e95358a569")
    KAT1_NONCE          = bytes.fromhex("808aa38f2a72a62359915a9f8a04ca68")
    KAT1_ENTROPY_RESEED = bytes.fromhex("e62b8a8ee8f141b6980566e3bfe3c04903dad4ac2cdf9f2280010a6739bc83d3")

    KAT1_V_AFTER_INST   = int("32ab605ddc8d5651093b8a59bd9d3adea1249e21a69e2e4a3967515fa03ad41ccf5b126eb9f3b268080c952df88241fe4cc27bbcbbbed5", 16)
    KAT1_C_AFTER_INST   = int("8ea2691d1915ebb4975593ca3fbad0ba137026d901a95950a207c41dc7773e15c1e85f4a5f91002866830bebe5c4ee1785b839323fbb44", 16)

    KAT1_V_AFTER_RESEED = int("59177d93843f0550f33933a51eb488168699ab9c85651536a61f7ec71e8b274a151f17e56becaf531dcfc955f2f1adb6536d51b256d53c", 16)
    KAT1_C_AFTER_RESEED = int("897c02699f4254e1f33c94f7bfa85da3826df6c2590ed0815cbced36d77aa3375a1582ffc1c887416afd1ba0f04b6ddff81a2b0e5b844d", 16)

    KAT1_V_AFTER_GEN1   = int("e2937ffd23815a32e675c89cde5ce5ba0907a25ede73e61c9ec76d67da582c94001fda32b60ec40202a164c6a4d66411cc6b99b1284617", 16)

    KAT1_V_AFTER_GEN2   = int("6c0f8266c2c3af14d9b25d949e05435d8b7599213782b6eac6cd90a10d48e1c96088f5dba20241b68cb64bb05028c35e5558ef8a6edca6", 16)
    KAT1_OUTPUT         = bytes.fromhex(
        "04eec63bb231df2c630a1afbe724949d005a587851e1aa795e477347c8b056621"
        "c18bddcdd8d99fc5fc2b92053d8cfacfb0bb8831205fad1ddd6c071318a6018f0"
        "3b73f5ede4d4d071f9de03fd7aea105d9299b8af99aa075bdb4db9aa28c18d174"
        "b56ee2a014d098896ff2282c955a81969e069fa8ce007a180183a07dfae17"
    )  # 128 bytes (1024 bits)

    # --- KAT-2 (strength=192, SHA-384) ---
    KAT2_ENTROPY_INST   = bytes.fromhex("2d3e072e78b3d5af2d60424b37a1ca56b24ad1b1fb27a9c327db0651cb75341c")
    KAT2_NONCE          = bytes.fromhex("147d214920513cd539ce383f810d9551")
    KAT2_ENTROPY_RESEED = bytes.fromhex("7597a56fdbaa0cb66cef235ccb6bbb423ef2a2f19e5a65a7b86dd11d0cee6cd4")

    KAT2_V_AFTER_INST   = int("bd9fe59036c728dbe30392569dedd9cca0cfaf9e7be20745e28e3a86615149caf4d970062c59b8f0ae7235f5d52762820ce6443cd313289d1c84e1b0e12ee992435008dc32904ea28fad4abfa00ff54adfb7186cb4d335b54ceff76b1992ae1ee3997054e76f88108783744324df96", 16)
    KAT2_C_AFTER_INST   = int("d2b4ad747db0dafd96edded2a41d9cb7e189cc727066da2d1253a6818ce97870cd3e07de9736eec58536a271e1955931e4bb7832604ea487c3fbb5f510c465e9985ef066d70631d4b98e77dae9b6397103d6564798a6320d9716a6826945687a3557be1132a1a23007c89c362a52c3", 16)

    KAT2_V_AFTER_RESEED = int("fbcb667f386b611aadf6d76999427af0adeabae5b4b2898bf37a57554f6dbf0758b2095f4b4f06415c8a06f27773cf0f7e48b8c41eb5d7d4d48f628067c773f7ae0b9e24adaf4999b4330d73b0c9340f51b6e9e6f2e3f3d43fb8f4421349bc4e05c4e09202124b76c83b3ecf821f30", 16)
    KAT2_C_AFTER_RESEED = int("46c505af058b37dfd9f59932ac17048fb307ffc5c27195d8bacf5521f811c1f157ce7589258ef328a55f3aea70e4ab09880c59f55ea211681c18584465ce1732503d991566cb3651ddf5a59fbb3ac82399d358226e94204c1f5b712dbb7aa07f1868dcf0278edcc37708102bdd3b60", 16)

    KAT2_V_AFTER_GEN1   = int("42906c2e3df698fa87ec709c45597f8060f2baab77241f64ae49ac77477f80f8b0807ee870ddf96a01e941dce8587a19065512b97d57e93cf0a7bac4cd958c1ca086254c329645369fd5f46d3907eda0be1c1e1243fbf3a30fa70edda40b7e81c39ea329990dfc9a0c249fd3b4f93a", 16)

    KAT2_V_AFTER_GEN2   = int("895571dd4381d0da61e209cef170841013faba713995b53d691901993f9142ea084ef471966cec92a7487cc7593d25228e616caedbf9faa50cc013093363a424e8e24142aff71616c8b170d37b7a7a4ef1cd0c16766ee8b4af40f5005b8255caa42f6d5d17bf67f7e6d11a49b363e4", 16)
    KAT2_OUTPUT         = bytes.fromhex(
        "5d3d1c5ea9e8c219d43511288fc65dbc1a2f6284c59b26d4375f156b75d383d01"
        "ac6773cad41bf5b6d9fc41416933c0459f9b6d481412e38e9dde34cec3529a313"
        "d2e7815bc5c29a550dfd6be3365d0f8fbbe3a33bc07b6b96351834462a2e624d4"
        "ffa0bd1bf9adda378f4ddb6d4f6a99f7e3fa2556e52006b40fe9caa30ff4cbed3"
        "e574e2b3752680ce7117ab880dd3890be9c19f6442b0e2e04684e05f4fffd90f9"
        "7112f0766a589ed82c07af7cba239c36a3d2bf52a25df2c84678556cedf"
    )  # 192 bytes (1536 bits)

    def _run_kat(self, strength, entropy_inst, nonce, entropy_reseed,
                 V_inst, C_inst, V_reseed, C_reseed,
                 gen1_bits, V_gen1, gen2_bits, V_gen2, expected_output):
        drbg = HashDRBG(strength=strength, _skip_kat=True)

        # Step 2: instantiate
        drbg.instantiate(entropy_inst, nonce)
        assert drbg._V == V_inst,   f"V after instantiate mismatch: {drbg._V:#x}"
        assert drbg._C == C_inst,   f"C after instantiate mismatch: {drbg._C:#x}"
        assert drbg._reseed_counter == 1

        # Step 3: reseed (no additional input)
        drbg.reseed(entropy_reseed)
        assert drbg._V == V_reseed, f"V after reseed mismatch: {drbg._V:#x}"
        assert drbg._C == C_reseed, f"C after reseed mismatch: {drbg._C:#x}"
        assert drbg._reseed_counter == 1

        # Step 4: generate 1
        _ = drbg.generate(gen1_bits // 8)
        assert drbg._V == V_gen1,   f"V after generate-1 mismatch: {drbg._V:#x}"
        assert drbg._C == C_reseed, "C should not change during generate"
        assert drbg._reseed_counter == 2

        # Step 5: generate 2
        output = drbg.generate(gen2_bits // 8)
        assert drbg._V == V_gen2,   f"V after generate-2 mismatch: {drbg._V:#x}"
        assert drbg._reseed_counter == 3
        assert output == expected_output, (
            f"Output mismatch:\n  got: {output.hex()}\n  exp: {expected_output.hex()}"
        )

    def test_kat1_strength128(self):
        self._run_kat(
            strength=128,
            entropy_inst=self.KAT1_ENTROPY_INST,
            nonce=self.KAT1_NONCE,
            entropy_reseed=self.KAT1_ENTROPY_RESEED,
            V_inst=self.KAT1_V_AFTER_INST,
            C_inst=self.KAT1_C_AFTER_INST,
            V_reseed=self.KAT1_V_AFTER_RESEED,
            C_reseed=self.KAT1_C_AFTER_RESEED,
            gen1_bits=1024, V_gen1=self.KAT1_V_AFTER_GEN1,
            gen2_bits=1024, V_gen2=self.KAT1_V_AFTER_GEN2,
            expected_output=self.KAT1_OUTPUT,
        )

    def test_kat2_strength192(self):
        self._run_kat(
            strength=192,
            entropy_inst=self.KAT2_ENTROPY_INST,
            nonce=self.KAT2_NONCE,
            entropy_reseed=self.KAT2_ENTROPY_RESEED,
            V_inst=self.KAT2_V_AFTER_INST,
            C_inst=self.KAT2_C_AFTER_INST,
            V_reseed=self.KAT2_V_AFTER_RESEED,
            C_reseed=self.KAT2_C_AFTER_RESEED,
            gen1_bits=1536, V_gen1=self.KAT2_V_AFTER_GEN1,
            gen2_bits=1536, V_gen2=self.KAT2_V_AFTER_GEN2,
            expected_output=self.KAT2_OUTPUT,
        )
