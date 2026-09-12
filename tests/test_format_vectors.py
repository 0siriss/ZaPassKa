"""
The golden vectors are the contract between implementations.

Every value here was produced once by tools/make_vectors.py and checked in.
If a change to the crypto or the snapshot format breaks these, it breaks
every other client reading the same vault, so the vectors must never be
regenerated to make a failing test pass.
"""
import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import crypto        # noqa: E402
import sync          # noqa: E402

VECTORS = json.loads(
    (Path(__file__).resolve().parent.parent / "docs" / "format" / "vectors.json")
    .read_text("utf-8")
)


class TestParameters(unittest.TestCase):

    def test_the_scrypt_parameters_are_the_documented_ones(self):
        params = VECTORS["scrypt"]

        self.assertEqual(params["n"], crypto._SCRYPT_N)
        self.assertEqual(params["r"], crypto._SCRYPT_R)
        self.assertEqual(params["p"], crypto._SCRYPT_P)
        self.assertEqual(params["key_length"], crypto._KEY_LEN)

    def test_the_aead_parameters_are_the_documented_ones(self):
        self.assertEqual(VECTORS["aead"]["nonce_length"], crypto._NONCE_LEN)
        self.assertEqual(VECTORS["aead"]["algorithm"], "AES-256-GCM")


class TestKeyDerivation(unittest.TestCase):
    """Slow by design: these run the real scrypt cost, not a test-sized one."""

    def test_each_password_and_salt_gives_the_recorded_key(self):
        for case in VECTORS["key_derivation"]:
            with self.subTest(note=case["note"]):
                key = crypto.derive_kek(case["password"],
                                        bytes.fromhex(case["salt_hex"]))
                self.assertEqual(key.hex(), case["key_hex"])


class TestKeyWrapping(unittest.TestCase):

    def test_the_recorded_blob_unwraps_to_the_recorded_data_key(self):
        case = VECTORS["key_wrapping"]

        unwrapped = crypto.unwrap_dek(bytes.fromhex(case["kek_hex"]),
                                      bytes.fromhex(case["wrapped_hex"]))

        self.assertEqual(unwrapped.hex(), case["data_key_hex"])

    def test_a_wrong_key_unwraps_to_nothing(self):
        case = VECTORS["key_wrapping"]
        wrong = bytes(32)

        self.assertIsNone(crypto.unwrap_dek(wrong,
                                            bytes.fromhex(case["wrapped_hex"])))


class TestFieldEncryption(unittest.TestCase):

    def test_every_recorded_blob_decrypts_to_its_plaintext(self):
        data_key = bytes.fromhex(VECTORS["field_encryption"]["data_key_hex"])

        for case in VECTORS["field_encryption"]["cases"]:
            with self.subTest(plaintext=case["plaintext"]):
                self.assertEqual(
                    crypto.decrypt(data_key, bytes.fromhex(case["blob_hex"])),
                    case["plaintext"])

    def test_the_blob_starts_with_the_recorded_nonce(self):
        nonce_length = VECTORS["aead"]["nonce_length"]

        for case in VECTORS["field_encryption"]["cases"]:
            with self.subTest(plaintext=case["plaintext"]):
                blob = bytes.fromhex(case["blob_hex"])
                self.assertEqual(blob[:nonce_length].hex(), case["nonce_hex"])


class TestSnapshot(unittest.TestCase):

    def setUp(self):
        self.case = VECTORS["snapshot"]
        self.document = self.case["document"]

    def test_it_is_accepted_by_the_reader(self):
        loaded = sync.loads(json.dumps(self.document).encode("utf-8"))

        self.assertEqual(loaded["vault_id"], self.document["vault_id"])

    def test_its_digest_still_matches(self):
        self.assertEqual(sync.snapshot_digest(self.document), self.case["digest"])

    def test_the_master_password_opens_it(self):
        method = self.document["unlock_methods"][0]

        kek = crypto.derive_kek(self.case["master_password"],
                                bytes.fromhex(method["salt"]))
        data_key = crypto.unwrap_dek(kek, base64.b64decode(method["wrapped_dek"]))

        self.assertEqual(data_key.hex(), self.case["data_key_hex"])

    def test_the_live_entries_read_back_exactly(self):
        data_key = bytes.fromhex(self.case["data_key_hex"])

        live = [e for e in self.document["entries"] if not e["deleted"]]
        read = [
            {
                "uuid":     entry["uuid"],
                "service":  crypto.decrypt(data_key, base64.b64decode(entry["service"])),
                "login":    crypto.decrypt(data_key, base64.b64decode(entry["login"])),
                "password": crypto.decrypt(data_key, base64.b64decode(entry["password"])),
            }
            for entry in live
        ]

        self.assertEqual(read, self.case["expected_entries"])

    def test_the_tombstone_is_not_an_entry(self):
        tombstones = [e for e in self.document["entries"] if e["deleted"]]

        self.assertTrue(tombstones, "the vector should carry a tombstone")
        for tombstone in tombstones:
            self.assertNotIn(tombstone["uuid"],
                             [e["uuid"] for e in self.case["expected_entries"]])


if __name__ == "__main__":
    unittest.main()
