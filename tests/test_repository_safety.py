from __future__ import annotations

import sys
import tempfile
import unittest
import contextlib
import io
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import secret_scan  # noqa: E402
import verify_repository as verify  # noqa: E402


class RepositorySafetyTests(unittest.TestCase):
    def test_current_tree_is_release_only(self) -> None:
        verify.verify_release_only_inventory()

    def test_android_source_and_keystore_are_rejected(self) -> None:
        for name in ("MainActivity.kt", "build.gradle", "staging.jks", "candidate.apk"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / name).write_bytes(b"fixture")
                with mock.patch.object(verify, "ROOT", root), self.assertRaises(verify.RepositoryError):
                    verify.verify_release_only_inventory()

    def test_secret_scanner_rejects_key_and_token_forms(self) -> None:
        fixtures = (
            ("key.txt", "-----BEGIN " + "PRIVATE KEY-----\nfixture"),
            ("token.txt", "gh" + "p_abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
        )
        for name, content in fixtures:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / name).write_text(content, encoding="utf-8")
                with mock.patch.object(secret_scan, "ROOT", root), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(secret_scan.main(), 1)

    def test_current_tree_secret_scan_passes(self) -> None:
        self.assertEqual(secret_scan.main(), 0)

    def test_owner_setup_covers_every_external_control(self) -> None:
        setup = (ROOT / "docs/OWNER_SETUP.md").read_text(encoding="utf-8")
        for required in (
            "android-paper-preview-signing",
            "required reviewer",
            "prevent self-review",
            "ruleset or branch-protection",
            "repository-verify",
            "SOURCE_REPO_READ_TOKEN",
            "Actions: read",
            "ANDROID_PREVIEW_KEYSTORE_BASE64",
            "ANDROID_PREVIEW_KEYSTORE_PASSWORD",
            "ANDROID_PREVIEW_KEY_ALIAS",
            "ANDROID_PREVIEW_KEY_PASSWORD",
            "ANDROID_PREVIEW_CERTIFICATE_SHA256",
            "RELEASE_POLICY_READ_TOKEN",
            "Administration: read",
            "staging key custodian",
            "offline encrypted backup",
            "has not performed or approved",
        ):
            with self.subTest(required=required):
                self.assertIn(required, setup)


if __name__ == "__main__":
    unittest.main()
