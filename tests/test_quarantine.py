"""
Unit tests for the Quarantine and Remediation module (core/remediation.py).
"""

import hashlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.remediation import (
    _xor_transform_file,
    delete_file_permanently,
    delete_quarantined_file,
    get_quarantine_dir,
    list_quarantined_files,
    purge_all_quarantine,
    quarantine_file,
    restore_quarantined_file,
)


class TestQuarantineModule(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="malyx_test_q_")
        self.orig_dir = Path(self.temp_dir) / "source"
        self.orig_dir.mkdir()
        self.mock_qdir = Path(self.temp_dir) / "quarantine"
        self.mock_qdir.mkdir()

    def tearDown(self):
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass

    def test_xor_symmetry_and_integrity(self):
        """Verify that XOR(XOR(data)) produces byte-for-byte identical content."""
        sample_data = b"Malicious payload binary simulation 1234567890 \x00\xFF\xAA\x55\xDE\xAD\xBE\xEF" * 100
        src_file = self.orig_dir / "sample.bin"
        enc_file = self.orig_dir / "sample.enc"
        dec_file = self.orig_dir / "sample.dec"

        with open(src_file, "wb") as f:
            f.write(sample_data)

        orig_hash = hashlib.sha256(sample_data).hexdigest()

        # Encrypt
        _xor_transform_file(str(src_file), str(enc_file))
        with open(enc_file, "rb") as f:
            enc_data = f.read()
        self.assertNotEqual(enc_data, sample_data, "Encrypted payload must differ from plaintext")

        # Decrypt
        _xor_transform_file(str(enc_file), str(dec_file))
        with open(dec_file, "rb") as f:
            dec_data = f.read()

        dec_hash = hashlib.sha256(dec_data).hexdigest()
        self.assertEqual(orig_hash, dec_hash, "Decrypted file hash must match original hash exactly")

    def test_quarantine_lifecycle(self):
        """Verify full lifecycle: quarantine -> list -> restore -> verify hash -> delete."""
        test_payload = b"CRITICAL_TROJAN_EMULATION_PAYLOAD_TEST" * 50
        test_file = self.orig_dir / "trojan_test.exe"

        with open(test_file, "wb") as f:
            f.write(test_payload)

        orig_hash = hashlib.sha256(test_payload).hexdigest()

        with patch("core.remediation.get_quarantine_dir", return_value=str(self.mock_qdir)):
            # 1. Quarantine file
            success, msg, qpath = quarantine_file(str(test_file), metadata={"risk": {"score": 90, "verdict": "malicious"}})
            self.assertTrue(success, msg)
            self.assertFalse(test_file.exists(), "Original file must be removed from source location")
            self.assertTrue(os.path.exists(qpath), "Quarantined file must exist in quarantine dir")

            # 2. List quarantined files
            items = list_quarantined_files()
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["original_name"], "trojan_test.exe")
            qid = items[0]["id"]

            # 3. Restore quarantined file
            restore_success, restore_msg = restore_quarantined_file(qid)
            self.assertTrue(restore_success, restore_msg)
            self.assertTrue(test_file.exists(), "Restored file must reappear at original path")

            with open(test_file, "rb") as f:
                restored_data = f.read()
            restored_hash = hashlib.sha256(restored_data).hexdigest()
            self.assertEqual(orig_hash, restored_hash, "Restored content must be byte-for-byte identical")

            # Verify quarantine files were cleaned up after restore
            self.assertEqual(len(list_quarantined_files()), 0)

    def test_delete_quarantined_file(self):
        """Verify that delete_quarantined_file completely shreds and deletes from quarantine."""
        test_file = self.orig_dir / "ransomware_sample.exe"
        with open(test_file, "wb") as f:
            f.write(b"RANSOM_SAMPLE_TEST_PAYLOAD" * 20)

        with patch("core.remediation.get_quarantine_dir", return_value=str(self.mock_qdir)):
            success, _, qpath = quarantine_file(str(test_file))
            self.assertTrue(success)

            items = list_quarantined_files()
            self.assertEqual(len(items), 1)
            qid = items[0]["id"]

            del_success, del_msg = delete_quarantined_file(qid)
            self.assertTrue(del_success, del_msg)
            self.assertEqual(len(list_quarantined_files()), 0)


if __name__ == "__main__":
    unittest.main()
