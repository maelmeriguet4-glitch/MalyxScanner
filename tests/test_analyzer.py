import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from core.analyzer import analyze_file
from core.entropy import entropy_bytes, classify
from core.report import render_txt, save_json, save_txt
from i18n.translator import Translator

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

MZ_STUB = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"\x00" * 4000


def write_sample(directory, name, data):
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


class AnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="malyx_tests_")
        cls.t = Translator("fr")
        cls.txt_path = write_sample(cls.tmp, "note.txt", b"hello world\n")
        cls.png_path = write_sample(
            cls.tmp,
            "image.png",
            b"\x89PNG\r\n\x1a\n" + os.urandom(2048),
        )
        cls.zip_path = write_sample(
            cls.tmp,
            "archive.zip",
            b"PK\x03\x04" + os.urandom(1024),
        )
        cls.eicar_path = write_sample(cls.tmp, "eicar.com", EICAR.encode("ascii"))
        cls.fake_pe_path = write_sample(cls.tmp, "app.exe", MZ_STUB + os.urandom(512))
        cls.decoy_path = write_sample(cls.tmp, "photo.jpg.exe", MZ_STUB + os.urandom(256))
        cls.random_path = write_sample(cls.tmp, "random.bin", os.urandom(65536))

    def analyze(self, path, **kwargs):
        return analyze_file(path, **kwargs)

    def test_structure(self):
        result = self.analyze(self.txt_path)
        for key in ("file", "hashes", "identity", "entropy", "pe", "yara", "risk", "privacy"):
            self.assertIn(key, result)
        self.assertIn("verdict", result["risk"])
        self.assertIn("score", result["risk"])

    def test_hashes_known_value(self):
        import hashlib

        result = self.analyze(self.txt_path)
        expected = hashlib.sha256(b"hello world\n").hexdigest()
        self.assertEqual(result["hashes"]["sha256"], expected)

    def test_txt_is_clean_text(self):
        result = self.analyze(self.txt_path)
        self.assertEqual(result["identity"]["family"], "document")
        self.assertFalse(result["identity"]["mismatch"])
        self.assertEqual(result["entropy"]["level"], "normal")
        self.assertEqual(result["risk"]["verdict"], "clean")

    def test_png_family_image(self):
        result = self.analyze(self.png_path)
        self.assertEqual(result["identity"]["family"], "image")
        self.assertEqual(result["risk"]["verdict"], "clean")

    def test_zip_family_archive(self):
        result = self.analyze(self.zip_path)
        self.assertEqual(result["identity"]["family"], "archive")

    def _eicar_available(self):
        if not os.path.exists(self.eicar_path):
            return False
        try:
            with open(self.eicar_path, "rb") as f:
                return EICAR.encode() in f.read()
        except OSError:
            return False

    def test_eicar_detected(self):
        import core.yara_scanner as ys

        compiled_list = ys._compile_all()[0]
        matches = []
        for ruleset in compiled_list:
            matches.extend(ruleset.match(data=EICAR.encode()))
        rule_names = [m.rule for m in matches]
        self.assertTrue(any("EICAR" in name for name in rule_names), f"EICAR not matched in-memory: {rule_names}")

    def test_eicar_end_to_end(self):
        if not self._eicar_available():
            self.skipTest("EICAR sample removed by local antivirus (expected behavior)")
        result = self.analyze(self.eicar_path)
        rules = [m["rule"] for m in result["yara"]["matches"]]
        self.assertTrue(any("EICAR" in rule for rule in rules), f"EICAR not matched: {rules}")
        self.assertGreaterEqual(result["risk"]["score"], 35)
        self.assertIn(result["risk"]["verdict"], ("suspicious", "malicious"))

    def test_fake_pe_no_crash_and_flags(self):
        result = self.analyze(self.fake_pe_path)
        self.assertTrue(result["pe"]["applicable"])
        self.assertFalse(result["pe"]["parsed"])
        self.assertGreater(result["risk"]["score"], 0)
        codes = {f["code"] for f in result["pe"]["findings"]}
        self.assertIn("pe.parse_failed", codes)

    def test_decoy_double_extension(self):
        result = self.analyze(self.decoy_path)
        all_codes = set()
        identity_codes = {f["code"] for f in result["identity"]["findings"]}
        all_codes |= identity_codes
        yara_matches = {m["rule"] for m in result["yara"]["matches"]}
        self.assertIn("find.double_ext", identity_codes)
        self.assertNotEqual(result["risk"]["verdict"], "clean")

    def test_high_entropy_random(self):
        ent = entropy_bytes(os.urandom(4096))
        self.assertGreater(ent, 7.2)
        self.assertEqual(classify(ent), "high")
        result = self.analyze(self.random_path)
        self.assertEqual(result["entropy"]["level"], "high")

    def test_vt_disabled_by_default(self):
        result = self.analyze(self.txt_path, vt_enabled=False, vt_api_key="")
        self.assertEqual(result["virustotal"]["status"], "disabled")
        self.assertFalse(result["privacy"]["vt_hash_only"])
        self.assertFalse(result["privacy"]["file_uploaded"])

    def test_report_exports(self):
        result = self.analyze(self.decoy_path)
        txt = render_txt(result, self.t)
        self.assertIn("MalyxScanner", txt)
        self.assertIn(result["hashes"]["sha256"], txt)

        out_json = os.path.join(self.tmp, "report_test.json")
        save_json(result, out_json)
        with open(out_json, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        self.assertEqual(loaded["hashes"]["sha256"], result["hashes"]["sha256"])

        out_txt = os.path.join(self.tmp, "report_test.txt")
        save_txt(txt, out_txt)
        with open(out_txt, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("SHA-256", content)

    def test_translator_fallback(self):
        t = Translator("fr")
        self.assertEqual(t.t("verdict.clean"), "SAIN")
        self.assertIn("MalyxScanner", t.t("app.title"))
        missing = t.t("nonexistent.key.xyz")
        self.assertEqual(missing, "nonexistent.key.xyz")

    def test_script_family_ps1(self):
        ps1_path = write_sample(self.tmp, "script.ps1", b"Write-Host 'test'\n")
        result = self.analyze(ps1_path)
        self.assertIn(result["identity"]["family"], ("executable", "code", "script"))
        codes = {f["code"] for f in result["identity"]["findings"]}
        self.assertIn("find.dangerous_ext", codes)

    def test_script_family_bat(self):
        bat_path = write_sample(self.tmp, "launcher.bat", b"@echo off\necho hello\n")
        result = self.analyze(bat_path)
        self.assertIn(result["identity"]["family"], ("executable", "code", "script"))
        codes = {f["code"] for f in result["identity"]["findings"]}
        self.assertIn("find.dangerous_ext", codes)

    def test_entropy_not_in_identity(self):
        result = self.analyze(self.random_path)
        identity_codes = [f["code"] for f in result["identity"]["findings"]]
        self.assertNotIn("find.entropy_high", identity_codes)
        self.assertEqual(result["entropy"]["level"], "high")

    def test_extended_hashes(self):
        result = self.analyze(self.txt_path)
        self.assertIn("sha512", result["hashes"])
        self.assertIn("crc32", result["hashes"])
        self.assertEqual(len(result["hashes"]["sha512"]), 128)
        self.assertEqual(len(result["hashes"]["crc32"]), 8)

    def test_block_entropy_structure(self):
        result = self.analyze(self.random_path)
        blocks = result["entropy"].get("blocks", {})
        self.assertIn("total_blocks", blocks)
        self.assertIn("min", blocks)
        self.assertIn("max", blocks)
        self.assertIn("avg", blocks)
        self.assertIn("samples", blocks)

    def test_strings_extraction_ioc(self):
        sample = write_sample(
            self.tmp,
            "dropper_test.ps1",
            b'powershell.exe -enc AAAA\nhttp://evil-c2.com/payload.exe\n192.168.1.50\n'
        )
        result = self.analyze(sample)
    def test_threat_classification_clean(self):
        result = self.analyze(self.txt_path)
        self.assertIn("threat", result)
        self.assertEqual(result["threat"]["type"], "clean")
        self.assertIn("execution_advice", result)
        self.assertEqual(result["execution_advice"]["advice_status"], "safe")

    def test_threat_classification_ransomware(self):
        ransom_sample = write_sample(
            self.tmp,
            "ransom_note.exe",
            MZ_STUB + b"\nvssadmin delete shadows /all /quiet\nYour files have been encrypted with RSA-4096! Send bitcoin to wallet\n"
        )
    def test_performance_config_options(self):
        result = self.analyze(
            self.txt_path,
            perf_config={"enable_strings_scan": False, "enable_yara": False, "entropy_block_size_kb": 32}
        )
        self.assertEqual(result["strings"]["total_strings"], 0)
        self.assertFalse(result["yara"]["available"])

    def test_theme_manager_presets(self):
        from gui.theme_manager import get_theme, available_themes
        themes = available_themes()
        self.assertIn("cyber_dark", themes)
        self.assertIn("midnight_blue", themes)
        t = get_theme("cyber_dark")
        self.assertIn("bg", t)

    def test_universal_categories(self):
        tests = [
            ("archive.rar", b"Rar!\x1a\x07\x00", "archive"),
            ("archive.7z", b"7z\xbc\xaf\x27\x1c", "archive"),
            ("document.md", b"# Title\nSome notes", "document"),
            ("office.docx", b"PK\x03\x04\x14\x00", "office"),
            ("ebook.pdf", b"%PDF-1.4\n...", "ebook"),
            ("audio.mp3", b"ID3\x03\x00\x00", "audio"),
            ("video.mp4", b"\x00\x00\x00\x18ftypmp42", "video"),
            ("script.py", b"import os\nprint('hello')", "code"),
            ("database.sqlite3", b"SQLite format 3\x00", "database"),
            ("game_asset.pak", b"PACK\x00\x00", "game"),
            ("config.reg", b"Windows Registry Editor Version 5.00", "system"),
        ]
        for fname, content, expected_fam in tests:
            sample = write_sample(self.tmp, fname, content)
            res = self.analyze(sample)
            self.assertEqual(res["identity"]["family"], expected_fam, f"Failed family for {fname}: got {res['identity']['family']}")

    def test_large_simulated_archive_no_freeze(self):
        # 2 MB sample with random bytes to verify instant entropy + strings performance
        large_sample = write_sample(self.tmp, "huge_backup.rar", b"Rar!\x1a\x07\x00" + os.urandom(2 * 1024 * 1024))
        res = self.analyze(large_sample)
        self.assertEqual(res["identity"]["family"], "archive")
        self.assertIn("hashes", res)
        self.assertIn("entropy", res)
        self.assertIn("blocks", res["entropy"])

    def test_ai_analyst_prompt_and_payload(self):
        from core.ai_analyst import build_system_prompt, build_user_payload
        sys_fr = build_system_prompt("fr")
        sys_en = build_system_prompt("en")
        self.assertIn("Cybersécurité", sys_fr)
        self.assertIn("Cybersecurity", sys_en)

        res = self.analyze(self.txt_path)
        payload_fr = build_user_payload(res, "fr")
        self.assertIn("sha256", payload_fr)
        self.assertIn("risk_verdict", payload_fr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

