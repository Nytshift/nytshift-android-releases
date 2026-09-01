from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import re
import sys
import unittest
import zlib
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import verify_repository as verify  # noqa: E402
import signing_boundary_reference as boundary  # noqa: E402


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = verify.WORKFLOW_PATH.read_text(encoding="utf-8")

    @staticmethod
    def source_run_payloads() -> list[dict[str, object]]:
        commit = boundary.SOURCE_COMMIT
        run_id = 33493181731

        def artifact(name: str, artifact_id: int, artifact_digest: str) -> dict[str, object]:
            api_url = f"https://api.github.com/repos/{boundary.SOURCE_REPOSITORY}/actions/artifacts/{artifact_id}"
            return {
                "name": name,
                "id": artifact_id,
                "digest": artifact_digest,
                "expired": False,
                "workflow_run": {
                    "id": run_id,
                    "head_branch": boundary.SOURCE_BRANCH,
                    "head_sha": commit,
                },
                "url": api_url,
                "archive_download_url": f"{api_url}/zip",
            }

        return [
            {
                "name": boundary.SOURCE_WORKFLOW,
                "path": boundary.SOURCE_WORKFLOW_PATH,
                "head_branch": boundary.SOURCE_BRANCH,
                "head_sha": commit,
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "repository": {"full_name": boundary.SOURCE_REPOSITORY},
                "head_repository": {"full_name": boundary.SOURCE_REPOSITORY},
            },
            {
                "total_count": 2,
                "jobs": [
                    {"id": 99809214893, "name": "verify", "status": "completed", "conclusion": "success", "head_sha": commit},
                    {"id": 99814660114, "name": "device", "status": "completed", "conclusion": "success", "head_sha": commit},
                ],
            },
            {
                "total_count": 3,
                "artifacts": [
                    artifact(
                        f"nytshift-android-device-evidence-{commit}",
                        9795726655,
                        "sha256:ab9fb3d572fb50697a9f8bfbf233db82774bcdf2784bd92b4272274c12f4e361",
                    ),
                    artifact(
                        f"nytshift-android-unsigned-release-evidence-{commit}",
                        9795265308,
                        "sha256:34d5d0505d0db5351c518afbbafe102da15e29c1496727cfabaff6b7c8fc550e",
                    ),
                    artifact(
                        f"nytshift-PAPER-TEST-ONLY-DEBUG-SIGNED-NOT-PLAY-OR-PRODUCTION-NO-LIVE-CAPITAL-{commit}",
                        9795263332,
                        "sha256:cd3bebf07b4d70268e119d3d93d89cbb6d1c500a3b7bd064d02390b168348dc3",
                    ),
                ],
            },
        ]

    def test_complete_repository_contract(self) -> None:
        verify.verify_policy()
        verify.verify_workflow()
        verify.verify_python()

    def test_jobs_have_split_trust(self) -> None:
        sign = verify.job_block(self.workflow, "sign")
        stage = verify.job_block(self.workflow, "verify-and-stage")
        publish = verify.job_block(self.workflow, "publish")
        post = verify.job_block(self.workflow, "postpublish")
        self.assertIn("permissions: {}", sign)
        self.assertNotIn("actions/checkout", sign)
        self.assertNotIn("contents: write", sign)
        self.assertNotIn("secrets.", stage)
        self.assertEqual(self.workflow.count("contents: write"), 1)
        self.assertIn("contents: write", publish)
        self.assertNotIn("secrets.", publish + post)

    def test_all_actions_are_full_reviewed_pins(self) -> None:
        uses = re.findall(r"uses:\s*([^@\s]+)@([^\s#]+)", self.workflow)
        self.assertGreater(len(uses), 0)
        for action, revision in uses:
            self.assertRegex(revision, r"^[a-f0-9]{40}$")
            self.assertEqual(verify.ACTION_PINS[action], revision)

    def test_every_downloaded_executable_or_archive_has_its_reviewed_digest(self) -> None:
        for artifact, digest in verify.EXECUTABLE_PINS.items():
            with self.subTest(artifact=artifact):
                self.assertIn(artifact, self.workflow)
                self.assertIn(digest, self.workflow)

    def test_inline_boundary_equals_reviewed_reference(self) -> None:
        match = re.search(r"^          BOUNDARY_ZLIB_B64: (\S+)$", self.workflow, re.MULTILINE)
        self.assertIsNotNone(match)
        payload = zlib.decompress(base64.b64decode(match.group(1), validate=True))
        self.assertEqual(payload, verify.BOUNDARY_PATH.read_bytes())
        self.assertEqual(hashlib.sha256(payload).hexdigest(), verify.BOUNDARY_SHA256)

    def test_corrected_signature_return_is_inside_function(self) -> None:
        boundary_source = verify.BOUNDARY_PATH.read_text(encoding="utf-8")
        tree = ast.parse(boundary_source)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "verify_signature")
        returns = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
        self.assertEqual(len(returns), 1)
        self.assertIsInstance(returns[0].value, ast.Call)
        source = ast.get_source_segment(boundary_source, returns[0])
        self.assertIn("normalize_certificate(certificates[0][1])", source)

    def test_source_token_is_not_forwarded_to_redirect_storage_or_signer(self) -> None:
        source = verify.BOUNDARY_PATH.read_text(encoding="utf-8")
        self.assertIn("NO_REDIRECT_OPENER.open(request", source)
        self.assertIn('headers={"User-Agent": "nytshift-android-paper-release-boundary"}', source)
        self.assertIn('("SOURCE_REPO_READ_TOKEN", "KEYSTORE_BASE64", "KEY_ALIAS")', source)
        self.assertIn("signing_env.pop(secret_not_needed_by_signer, None)", source)

    def test_reviewed_private_source_validator_pin_is_exact(self) -> None:
        policy = json.loads(verify.POLICY_PATH.read_text(encoding="utf-8"))
        reviewed = policy["source"]["reviewedValidator"]
        self.assertEqual(reviewed["commit"], verify.REVIEWED_SOURCE_COMMIT)
        self.assertEqual(reviewed["sha256"], verify.REVIEWED_SOURCE_VALIDATOR_SHA256)
        self.assertEqual(reviewed["commit"], "61f837f304b3942f65cb3d99f1a4236bcd420e41")
        self.assertEqual(reviewed["sha256"], "7e1193b38d8588bbc9f7e2c1c5806008d4d18e3b3261deead27accdae53e4475")

    def test_inline_boundary_requires_exact_source_and_evidence_inventory(self) -> None:
        source = verify.BOUNDARY_PATH.read_text(encoding="utf-8")
        for required in (
            'SOURCE_COMMIT = "61f837f304b3942f65cb3d99f1a4236bcd420e41"',
            "EXPECTED_JVM_TESTS = 338",
            "EXPECTED_ANDROID_TESTS = 39",
            "EXPECTED_SCREENSHOT_REFERENCES = 46",
            '"reviewedScreenshotReferences": EXPECTED_SCREENSHOT_REFERENCES',
            'source_commit != SOURCE_COMMIT',
            'artifacts_payload.get("total_count") != 3',
            'f"nytshift-PAPER-TEST-ONLY-DEBUG-SIGNED-NOT-PLAY-OR-PRODUCTION-NO-LIVE-CAPITAL-{commit}"',
        ):
            self.assertIn(required, source)

    def test_debug_only_source_artifact_is_validated_but_not_forwarded(self) -> None:
        payloads = self.source_run_payloads()
        with mock.patch.object(boundary, "api_json", side_effect=payloads):
            release, device = boundary.validate_source_run(
                "source-read-token", boundary.SOURCE_COMMIT, 33493181731
            )
        self.assertEqual(release["id"], 9795265308)
        self.assertEqual(device["id"], 9795726655)
        self.assertNotEqual(release["id"], 9795263332)
        self.assertNotEqual(device["id"], 9795263332)
        release_gate = (ROOT / "tools/release_gate.py").read_text(encoding="utf-8")
        self.assertIn('set(artifacts) != {"device", "release"}', release_gate)
        self.assertNotIn(verify.DEBUG_ONLY_ARTIFACT_PREFIX, release_gate)

    def test_invalid_debug_only_metadata_fails_the_source_run_gate(self) -> None:
        payloads = copy.deepcopy(self.source_run_payloads())
        payloads[2]["artifacts"][2]["digest"] = "sha256:not-a-digest"
        with mock.patch.object(boundary, "api_json", side_effect=payloads):
            with self.assertRaises(boundary.BoundaryError):
                boundary.validate_source_run("source-read-token", boundary.SOURCE_COMMIT, 33493181731)

    def test_accountable_environment_and_owner_key_are_fail_closed(self) -> None:
        preflight = verify.job_block(self.workflow, "preflight")
        sign = verify.job_block(self.workflow, "sign")
        stage = verify.job_block(self.workflow, "verify-and-stage")
        for required in (
            "prevent_self_review",
            "one accountable user reviewer",
            "ANDROID_PREVIEW_KEY_OWNER",
            "deployment-branch-policies",
            'reviewer == key_owner',
        ):
            self.assertIn(required, preflight)
        self.assertIn("CONFIGURED_REVIEWER_IDENTITY", sign)
        self.assertIn("KEY_OWNER_IDENTITY", sign)
        self.assertIn("--configured-reviewer", stage)
        self.assertIn("--key-owner", stage)

    def test_postpublish_rejects_unsigned_or_live_metadata(self) -> None:
        post = verify.job_block(self.workflow, "postpublish")
        for required in (
            '"signingStatus": "signed"',
            '"unsignedPublicArtifactsAllowed": False',
            '"executionEnabled": False',
            '"allowMainnet": False',
            '"executionAuthority": "none"',
            '"isImmutable": True',
            "gh release verify-asset",
        ):
            self.assertIn(required, post)

    def test_postpublish_verifies_release_and_every_asset(self) -> None:
        post = verify.job_block(self.workflow, "postpublish")
        self.assertIn("gh release verify ", post)
        self.assertIn("gh release verify-asset ", post)
        for asset in (
            "nytshift-staging-release.apk",
            "android-paper-preview.json",
            "provenance.json",
            "release-notes.md",
            "SHA256SUMS",
        ):
            self.assertIn(asset, post)


if __name__ == "__main__":
    unittest.main()
