from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import release_gate as gate  # noqa: E402


CERTIFICATE = "ab" * 32
COMMIT = gate.EXPECTED_SOURCE_COMMIT
PUBLIC_COMMIT = "2" * 40


def toolchain() -> dict:
    return {
        "schemaVersion": "1",
        "kind": "nytshift.android.audited-sdk-inventory",
        "components": [
            {
                "component": name,
                "sourceProperties": values[0],
                "revision": values[1],
                "sourcePropertiesSha256": f"{index:x}" * 64,
            }
            for index, (name, values) in enumerate(gate.EXPECTED_DEVICE_COMPONENTS.items(), 1)
        ],
    }


def evidence() -> tuple[dict, dict]:
    audited = toolchain()
    source = {
        "repository": gate.EXPECTED_SOURCE_REPOSITORY,
        "commitSha": COMMIT,
        "sourceTreeClean": True,
    }
    release = {
        "schemaVersion": "2",
        "kind": "nytshift.android.unsigned-release-evidence",
        "source": source,
        "authority": {
            "executionEnabled": False,
            "allowMainnet": False,
            "executionAuthority": "none",
        },
        "verification": {
            "androidTests": "compiled-not-executed-in-verify-job; see separate device evidence",
            "jvmTests": {
                "suites": 12,
                "tests": gate.EXPECTED_JVM_TESTS,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
            },
            "productionLint": "passed-before-evidence-step",
            "productionManifest": "verified-before-evidence-step",
            "screenshotReferences": "validated-before-evidence-step",
            "stagingManifest": "verified-before-evidence-step",
        },
        "inventory": {
            "androidTestAnnotations": gate.EXPECTED_ANDROID_TESTS,
            "jvmTestAnnotations": gate.EXPECTED_JVM_TESTS,
            "reviewedScreenshotReferences": gate.EXPECTED_SCREENSHOT_REFERENCES,
        },
        "versionSource": {"expected": {"versionCode": 42, "versionName": "1.2.3"}},
        "variants": {
            "stagingRelease": {
                "applicationId": gate.EXPECTED_PACKAGE,
                "versionCode": 42,
                "versionName": "1.2.3-staging",
                "environment": "staging",
                "signing": "unsigned",
            }
        },
        "files": [
            {
                "path": "artifacts/app-staging-release-unsigned.apk",
                "bytes": 10,
                "role": "unsignedApk",
                "sha256": "a" * 64,
            },
            {
                "path": "manifests/stagingRelease-BuildConfig.java",
                "bytes": 10,
                "role": "buildConfig",
                "sha256": "b" * 64,
            },
        ],
    }
    device = {
        "schemaVersion": "1",
        "kind": "nytshift.android.emulator-test-evidence",
        "source": source,
        # Extra retained device diagnostics are allowed, but the two authority fields are exact.
        "device": {
            "apiLevel": 36,
            "image": "google_apis;x86_64",
            "avd": "nytshiftApi36",
            "logcatRetained": True,
        },
        "androidTest": {
            "stepOutcome": "success",
            "collectionError": None,
            "suites": 2,
            "tests": gate.EXPECTED_ANDROID_TESTS,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
        },
        "toolchain": audited,
    }
    return release, device


def decoded_manifest() -> str:
    return f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
      package="{gate.EXPECTED_PACKAGE}" android:versionCode="42" android:versionName="1.2.3-staging">
      <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="36" />
      <uses-permission android:name="android.permission.INTERNET" />
      <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
      <uses-permission android:name="{gate.EXPECTED_PACKAGE}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" />
      <application android:name="xyz.nytshift.app.NytshiftApplication" android:allowBackup="false"
        android:usesCleartextTraffic="false" android:debuggable="false" android:testOnly="false">
        <activity android:name="xyz.nytshift.app.MainActivity" android:exported="true" />
        <receiver android:name="androidx.profileinstaller.ProfileInstallReceiver" android:exported="true"
          android:permission="android.permission.DUMP" />
        <provider android:name="androidx.core.content.FileProvider"
          android:authorities="{gate.EXPECTED_PACKAGE}.fileprovider" android:exported="false"
          android:grantUriPermissions="true" />
      </application>
    </manifest>'''


def signer_output(certificate: str = CERTIFICATE) -> str:
    return "\n".join(
        [
            "Verifies",
            "Verified using v1 scheme (JAR signing): false",
            "Verified using v2 scheme (APK Signature Scheme v2): true",
            "Verified using v3 scheme (APK Signature Scheme v3): true",
            "Verified using v4 scheme (APK Signature Scheme v4): false",
            f"Signer #1 certificate SHA-256 digest: {certificate}",
        ]
    )


class EvidenceTests(unittest.TestCase):
    def test_superseded_source_commit_fails_before_handoff_access(self) -> None:
        args = SimpleNamespace(
            handoff=Path("handoff"),
            output=Path("output"),
            source_commit="c2a95bebb772d7d76db33df864de41fb231ff14c",
            source_run_id="123",
            public_commit=PUBLIC_COMMIT,
            certificate_sha256=CERTIFICATE,
            configured_reviewer="user:release-reviewer",
            key_owner="key-owner",
            public_repository=gate.EXPECTED_PUBLIC_REPOSITORY,
        )
        with mock.patch.object(gate, "read_json") as read_json:
            with self.assertRaisesRegex(gate.ReleaseGateError, "source or public commit is malformed"):
                gate.verify_and_stage(args)
        read_json.assert_not_called()

    def test_exact_green_evidence_accepts_retained_device_diagnostics(self) -> None:
        self.assertEqual(
            (
                gate.EXPECTED_JVM_TESTS,
                gate.EXPECTED_ANDROID_TESTS,
                gate.EXPECTED_SCREENSHOT_REFERENCES,
            ),
            (338, 39, 46),
        )
        release, device = evidence()
        version_name, version_code, _, _ = gate.validate_evidence_summaries(release, device, COMMIT)
        self.assertEqual((version_name, version_code), ("1.2.3-staging", 42))

    def test_device_image_drift_fails(self) -> None:
        release, device = evidence()
        device["device"]["image"] = "default;x86_64"
        with self.assertRaises(gate.ReleaseGateError):
            gate.validate_evidence_summaries(release, device, COMMIT)

    def test_stale_or_missing_inventory_fails(self) -> None:
        for section, field, stale in (
            ("verification", "jvmTests", None),
            ("inventory", "jvmTestAnnotations", 337),
            ("inventory", "androidTestAnnotations", 38),
            ("inventory", "reviewedScreenshotReferences", 45),
        ):
            with self.subTest(section=section, field=field):
                release, device = evidence()
                if stale is None:
                    release[section][field]["tests"] = 337
                else:
                    release[section][field] = stale
                with self.assertRaises(gate.ReleaseGateError):
                    gate.validate_evidence_summaries(release, device, COMMIT)

    def test_toolchain_revision_drift_fails(self) -> None:
        audited = toolchain()
        audited["components"][0]["revision"] = "latest"
        with self.assertRaises(gate.ReleaseGateError):
            gate.validate_audited_toolchain(audited)


class ManifestAndAuthorityTests(unittest.TestCase):
    def test_decoded_final_manifest_accepts_exact_surface(self) -> None:
        gate.validate_decoded_manifest(decoded_manifest(), "1.2.3-staging", 42)

    def test_decoded_final_manifest_rejects_wrong_package(self) -> None:
        manifest = decoded_manifest().replace(gate.EXPECTED_PACKAGE, "xyz.nytshift.app")
        with self.assertRaises(gate.ReleaseGateError):
            gate.validate_decoded_manifest(manifest, "1.2.3-staging", 42)

    def test_decoded_final_manifest_rejects_extra_permission(self) -> None:
        manifest = decoded_manifest().replace(
            "<application",
            '<uses-permission android:name="android.permission.CAMERA" /><application',
        )
        with self.assertRaises(gate.ReleaseGateError):
            gate.validate_decoded_manifest(manifest, "1.2.3-staging", 42)

    def test_build_config_requires_paper_authority_off(self) -> None:
        valid = "\n".join(
            [
                "public static final boolean DEBUG = false;",
                f'public static final String APPLICATION_ID = "{gate.EXPECTED_PACKAGE}";',
                'public static final String BUILD_TYPE = "release";',
                'public static final String FLAVOR = "staging";',
                "public static final int VERSION_CODE = 42;",
                'public static final String VERSION_NAME = "1.2.3-staging";',
                "public static final boolean ALLOW_MAINNET = false;",
                'public static final String ENVIRONMENT = "staging";',
                'public static final String EXECUTION_AUTHORITY = "none";',
                "public static final boolean EXECUTION_ENABLED = false;",
            ]
        )
        gate.validate_build_config(valid, "1.2.3-staging", 42)
        with self.assertRaises(gate.ReleaseGateError):
            gate.validate_build_config(valid.replace("EXECUTION_ENABLED = false", "EXECUTION_ENABLED = true"), "1.2.3-staging", 42)


class SignatureTests(unittest.TestCase):
    def test_signature_validator_returns_correct_digest(self) -> None:
        # Regression for the source validator's previously misplaced signature return.
        self.assertEqual(gate.validate_apksigner_output(signer_output(), CERTIFICATE), CERTIFICATE)

    def test_signature_warning_fails(self) -> None:
        with self.assertRaises(gate.ReleaseGateError):
            gate.validate_apksigner_output(signer_output() + "\nWARNING: weak algorithm", CERTIFICATE)

    def test_signature_scheme_or_signer_drift_fails(self) -> None:
        with self.assertRaises(gate.ReleaseGateError):
            gate.validate_apksigner_output(signer_output().replace("v3): true", "v3): false"), CERTIFICATE)
        with self.assertRaises(gate.ReleaseGateError):
            gate.validate_apksigner_output(signer_output() + f"\nSigner #2 certificate SHA-256 digest: {CERTIFICATE}", CERTIFICATE)

    def test_apksigner_invocation_uses_werr(self) -> None:
        with mock.patch.object(gate, "regular_file"), mock.patch.object(
            gate, "run_tool", return_value=signer_output()
        ) as run_tool:
            actual = gate.verify_apk_signature(Path("apksigner"), Path("candidate.apk"), CERTIFICATE)
        self.assertEqual(actual, CERTIFICATE)
        self.assertIn("--Werr", run_tool.call_args.args[0])


class PackageAndStagingTests(unittest.TestCase):
    @staticmethod
    def make_apk(path: Path, dex: bytes = b"dex") -> None:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"binary-manifest")
            archive.writestr("classes.dex", dex)

    def test_signed_zip_payload_must_equal_unsigned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned, signed = root / "unsigned.apk", root / "signed.apk"
            self.make_apk(unsigned)
            self.make_apk(signed)
            gate.require_unchanged_payload(unsigned, signed)
            self.make_apk(signed, b"changed")
            with self.assertRaises(gate.ReleaseGateError):
                gate.require_unchanged_payload(unsigned, signed)

    def test_checksum_package_rejects_extra_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "payload.txt").write_text("payload", encoding="utf-8")
            (root / gate.CHECKSUM_NAME).write_text(
                f"{gate.sha256(root / 'payload.txt')} *payload.txt\n", encoding="ascii"
            )
            gate.verify_checksum_package(root, [gate.CHECKSUM_NAME, "payload.txt"])
            (root / "extra.txt").write_text("extra", encoding="utf-8")
            with self.assertRaises(gate.ReleaseGateError):
                gate.verify_checksum_package(root, [gate.CHECKSUM_NAME, "payload.txt"])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_regular_file_rejects_symlink_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, link = root / "target", root / "link"
            target.write_text("x", encoding="utf-8")
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("Windows symlink privilege unavailable")
            with self.assertRaises(gate.ReleaseGateError):
                gate.regular_file(link, 100)

    def test_staged_metadata_contains_public_url_and_provenance_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signed, output = root / "signed.apk", root / "output"
            signed.write_bytes(b"signed APK fixture")
            artifact = {
                "id": 7,
                "name": "fixture",
                "archiveSha256": "3" * 64,
                "artifactDigest": "sha256:" + "4" * 64,
                "evidenceManifestSha256": "5" * 64,
                "checksumManifestSha256": "6" * 64,
                "packageInventoryCount": 3,
                "apiUrl": "https://api.github.com/fixture",
                "archiveDownloadUrl": "https://api.github.com/fixture/zip",
            }
            handoff = {
                "candidate": {
                    "authority": {"executionEnabled": False, "allowMainnet": False, "executionAuthority": "none"},
                    "versionName": "1.2.3-staging",
                    "versionCode": 42,
                    "signingCertificateSha256": CERTIFICATE,
                    "signingKeyOwner": "key-owner",
                },
                "source": {
                    "commitSha": COMMIT,
                    "commitUrl": f"https://github.com/Nytshift/nytshift-android/commit/{COMMIT}",
                    "runUrl": "https://github.com/Nytshift/nytshift-android/actions/runs/123",
                },
                "sourceArtifacts": {"release": artifact, "device": dict(artifact, id=8)},
                "publicPreparation": {
                    "repository": gate.EXPECTED_PUBLIC_REPOSITORY,
                    "commitSha": PUBLIC_COMMIT,
                    "configuredEnvironmentReviewer": "user:release-reviewer",
                    "signingKeyOwner": "key-owner",
                },
            }
            tag, url = gate.stage_public_release(
                output,
                handoff,
                signed,
                public_repository=gate.EXPECTED_PUBLIC_REPOSITORY,
                public_commit=PUBLIC_COMMIT,
                prepared_at="2026-08-31T12:00:00Z",
            )
            self.assertEqual(tag, "android-paper-preview-v1.2.3-staging")
            self.assertEqual(
                url,
                f"https://github.com/{gate.EXPECTED_PUBLIC_REPOSITORY}/releases/download/{tag}/{gate.PUBLIC_APK_NAME}",
            )
            metadata = json.loads((output / "android-paper-preview.json").read_text(encoding="utf-8"))
            provenance = json.loads((output / "provenance.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["packageName"], gate.EXPECTED_PACKAGE)
            self.assertEqual(metadata["channel"], "PAPER")
            self.assertEqual(metadata["artifact"]["downloadUrl"], url)
            self.assertEqual(metadata["artifact"]["signingStatus"], "signed")
            self.assertNotIn("unsigned", metadata["artifact"]["fileName"].lower())
            self.assertNotIn("unsigned", metadata["artifact"]["downloadUrl"].lower())
            self.assertEqual(metadata["evidenceInventory"], {
                "androidTests": 39,
                "jvmTests": 338,
                "reviewedScreenshotReferences": 46,
            })
            self.assertEqual(metadata["publicationPolicy"]["unsignedPublicArtifactsAllowed"], False)
            self.assertEqual(provenance["authority"], {
                "executionEnabled": False,
                "allowMainnet": False,
                "executionAuthority": "none",
            })
            self.assertEqual(provenance["evidence"]["release"]["evidenceManifestSha256"], "5" * 64)
            gate.verify_checksum_package(output, gate.EXPECTED_RELEASE_INVENTORY)


if __name__ == "__main__":
    unittest.main()
