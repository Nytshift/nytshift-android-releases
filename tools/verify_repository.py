#!/usr/bin/env python3
"""Fail closed when the public release-only repository drifts from its trust model."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
import sys
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config/release-policy.json"
WORKFLOW_PATH = ROOT / ".github/workflows/publish-paper-preview.yml"
BOUNDARY_PATH = ROOT / "tools/signing_boundary_reference.py"
BOUNDARY_SHA256 = "ccaff059680da9a5d8011fd65bc019ac78f20f4966ee779e220366fb599c235e"
REVIEWED_SOURCE_COMMIT = "681a1329de80fb54996bce54d814ec425a721a4c"
REVIEWED_SOURCE_VALIDATOR_SHA256 = (
    "6ce828bbb2ff8203f73314397f3a7d4d727381f460c84b5551f3f9df45ce365a"
)
ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/download-artifact": "018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
    "actions/upload-artifact": "b7c566a772e6b6bfb58ed0dc250532a479d7789f",
}
EXECUTABLE_PINS = {
    "microsoft-jdk-17.0.20.1-linux-x64.tar.gz": "d00e5b04e9726b63d915706c7049e5297c9f40239ce8a12fcc68b7267fa91ad2",
    "$RUNNER_TEMP/jdk/bin/java": "e60625cbc7bebb2695d39f01b0dba0f9b534981386ab78bb73a327fd7cc3447f",
    "build-tools_r36_linux.zip": "5d9ac77fb6ff43d9da518a337b4fcf8f9097113df531d99ccefe80ef7ce8250b",
    "$RUNNER_TEMP/build-tools/android-16/aapt2": "1a6a396b9cd071f7040071fdd108718cb98c3c9f4960044f373b288993d19eb7",
    "$RUNNER_TEMP/build-tools/android-16/apksigner": "b47549e373b895ce6ca620d0c7887e674d9615ffa837a86ac601dcfd04adb0f0",
    "$RUNNER_TEMP/build-tools/android-16/lib/apksigner.jar": "3716d9311e55d2b0918a2fd9d54ba9e406c5f6abeea700b287f11259bc163dec",
    "commandlinetools-linux-15859902_latest.zip": "4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583",
    "$RUNNER_TEMP/cmdline-tools/cmdline-tools/bin/apkanalyzer": "c3912376ada67603a09a45701397b8d1ccec2ea138122b8aaae9dc57b47064b0",
    "$RUNNER_TEMP/cmdline-tools/cmdline-tools/lib/apkanalyzer-classpath.jar": "a41766a6bf679feae9d8c65cfead8ba7573bd7762feedd808715a72a808328b2",
    "gh_2.97.0_linux_amd64.tar.gz": "a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112",
    "$RUNNER_TEMP/gh_2.97.0_linux_amd64/bin/gh": "141507c337e8b202ad398550c3b73d72f5af92e86f71665214538a81efd4c409",
}
EXPECTED_SECRETS = {
    "RELEASE_POLICY_READ_TOKEN",
    "SOURCE_REPO_READ_TOKEN",
    "ANDROID_PREVIEW_KEYSTORE_BASE64",
    "ANDROID_PREVIEW_KEYSTORE_PASSWORD",
    "ANDROID_PREVIEW_KEY_ALIAS",
    "ANDROID_PREVIEW_KEY_PASSWORD",
}
FORBIDDEN_SUFFIXES = {
    ".aab", ".apk", ".der", ".gradle", ".jks", ".key", ".keystore",
    ".kt", ".kts", ".p12", ".pem", ".pfx",
}
FORBIDDEN_NAMES = {"gradlew", "gradlew.bat", "local.properties", ".env"}


class RepositoryError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def job_block(workflow: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        workflow,
    )
    if not match:
        raise RepositoryError(f"workflow job is missing: {name}")
    return match.group(0)


def verify_release_only_inventory() -> None:
    for path in ROOT.rglob("*"):
        if ".git" in path.parts:
            continue
        if path.is_symlink():
            raise RepositoryError(f"repository contains a symlink: {path.relative_to(ROOT)}")
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise RepositoryError(f"Android source, signing material, or build output is forbidden: {relative}")


def verify_policy() -> None:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    expected = {
        "android": {
            "buildVariant": "stagingRelease",
            "channel": "PAPER",
            "packageName": "xyz.nytshift.app.staging",
        },
        "publicRepository": "Nytshift/nytshift-android-releases",
        "source": {
            "branch": "main",
            "deviceApiLevel": 36,
            "deviceImage": "google_apis;x86_64",
            "repository": "Nytshift/nytshift-android",
            "workflowName": "android-ci",
            "workflowPath": ".github/workflows/ci.yml",
            "reviewedValidator": {
                "commit": REVIEWED_SOURCE_COMMIT,
                "path": "stage_signed_preview_release.py",
                "sha256": REVIEWED_SOURCE_VALIDATOR_SHA256,
            },
        },
    }
    if policy != expected:
        raise RepositoryError("fixed release policy differs")


def verify_boundary(workflow: str) -> None:
    if digest(BOUNDARY_PATH) != BOUNDARY_SHA256:
        raise RepositoryError("reviewed no-checkout signing boundary differs")
    match = re.search(r"^          BOUNDARY_ZLIB_B64: (\S+)$", workflow, re.MULTILINE)
    if not match:
        raise RepositoryError("workflow-inline signing boundary is missing")
    try:
        inline = zlib.decompress(base64.b64decode(match.group(1), validate=True))
    except (ValueError, zlib.error) as error:
        raise RepositoryError("workflow-inline signing boundary is malformed") from error
    if hashlib.sha256(inline).hexdigest() != BOUNDARY_SHA256 or inline != BOUNDARY_PATH.read_bytes():
        raise RepositoryError("workflow-inline and reviewed signing boundaries differ")

    tree = ast.parse(inline, filename="signing_boundary_reference.py")
    signature = next(
        (node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "verify_signature"),
        None,
    )
    if signature is None:
        raise RepositoryError("signing boundary lacks verify_signature")
    returns = [node for node in ast.walk(signature) if isinstance(node, ast.Return)]
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Call):
        raise RepositoryError("signature verifier return flow differs from reviewed correction")
    source = inline.decode("utf-8")
    if (
        '"--Werr"' not in source
        or "validate_manifest(decoded_manifest(apkanalyzer, signed)" not in source
        or '"google_apis;x86_64"' not in source
        or "NO_REDIRECT_OPENER.open(request" not in source
        or 'headers={"User-Agent": "nytshift-android-paper-release-boundary"}' not in source
        or 'signing_env.pop(secret_not_needed_by_signer, None)' not in source
    ):
        raise RepositoryError("signing boundary warning/decoded-manifest gates are missing")
    if "path.is_symlink()" not in source:
        raise RepositoryError("signing boundary symlink rejection is missing")


def verify_workflow() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    if "runs-on: self-hosted" in workflow:
        raise RepositoryError("release workflow must use fresh GitHub-hosted runners")
    for unsafe_trigger in ("pull_request_target:", "workflow_run:", "repository_dispatch:", "schedule:"):
        if unsafe_trigger in workflow:
            raise RepositoryError(f"unsafe release trigger present: {unsafe_trigger}")
    if workflow.count("contents: write") != 1 or "id-token: write" in workflow:
        raise RepositoryError("write permissions are not bounded to one contents publisher")

    blocks = {name: job_block(workflow, name) for name in (
        "preflight", "sign", "verify-and-stage", "publish", "postpublish"
    )}
    if "contents: write" not in blocks["publish"]:
        raise RepositoryError("publisher lacks its one bounded contents-write grant")
    for name in ("preflight", "sign", "verify-and-stage", "postpublish"):
        if "contents: write" in blocks[name]:
            raise RepositoryError(f"non-publisher job can write contents: {name}")
    if "permissions: {}" not in blocks["sign"] or "environment: android-paper-preview-signing" not in blocks["sign"]:
        raise RepositoryError("signing job lacks zero token permissions or protected environment")
    if (
        "actions/checkout" in blocks["sign"]
        or "python3 tools/" in blocks["sign"]
        or "python tools/" in blocks["sign"]
    ):
        raise RepositoryError("signing job must not checkout or execute repository code")
    if "secrets." in blocks["verify-and-stage"] or "secrets." in blocks["publish"] or "secrets." in blocks["postpublish"]:
        raise RepositoryError("post-signing jobs must not receive owner-managed secrets")
    if "secrets.RELEASE_POLICY_READ_TOKEN" not in blocks["preflight"]:
        raise RepositoryError("read-only repository immutability preflight is missing")
    if "/immutable-releases" not in blocks["preflight"] or 'immutable.get("enabled") is not True' not in blocks["preflight"]:
        raise RepositoryError("immutable release setting is not fail-closed")
    secrets = set(re.findall(r"secrets\.([A-Z][A-Z0-9_]*)", workflow))
    if secrets != EXPECTED_SECRETS:
        raise RepositoryError(f"workflow secret contract differs: {sorted(secrets)}")
    if "vars.ANDROID_PREVIEW_CERTIFICATE_SHA256" not in blocks["sign"] or "vars.ANDROID_PREVIEW_CERTIFICATE_SHA256" not in blocks["verify-and-stage"]:
        raise RepositoryError("certificate authority is not independently checked on both runners")
    if "gh release create" not in blocks["publish"] or "--draft" not in blocks["publish"] or "--draft=false" not in blocks["publish"]:
        raise RepositoryError("complete-draft then immutable-publish sequence is missing")
    if "gh release verify " not in blocks["postpublish"] or "gh release verify-asset " not in blocks["postpublish"]:
        raise RepositoryError("postpublish immutable release/asset verification is missing")
    if "isImmutable" not in blocks["postpublish"] or "EXPECTED_DOWNLOAD_URL" not in blocks["postpublish"]:
        raise RepositoryError("postpublish immutable/download metadata verification is missing")

    uses = re.findall(r"^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)", workflow, re.MULTILINE)
    if not uses:
        raise RepositoryError("workflow has no actions")
    for action, revision in uses:
        if ACTION_PINS.get(action) != revision or not re.fullmatch(r"[a-f0-9]{40}", revision):
            raise RepositoryError(f"action is not on the reviewed full commit pin: {action}@{revision}")
    for action in ACTION_PINS:
        if action not in {item[0] for item in uses}:
            raise RepositoryError(f"required action is absent: {action}")
    for artifact, checksum in EXECUTABLE_PINS.items():
        if artifact not in workflow or checksum not in workflow:
            raise RepositoryError(f"executable archive/tool pin is absent: {artifact}")

    required_contract = (
        "PAPER xyz.nytshift.app.staging",
        "Nytshift/nytshift-android",
        "Nytshift/nytshift-android-releases",
        "android-ci",
        "python3 tools/release_gate.py verify-and-stage",
    )
    for value in required_contract:
        if value not in workflow:
            raise RepositoryError(f"workflow release contract is absent: {value}")
    verify_boundary(workflow)


def verify_python() -> None:
    for path in sorted((ROOT / "tools").glob("*.py")) + sorted((ROOT / "tests").glob("*.py")):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def main() -> int:
    verify_release_only_inventory()
    verify_policy()
    verify_workflow()
    verify_python()
    print("repository contract verified: public release-only, split trust, fixed PAPER authority")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, json.JSONDecodeError, SyntaxError, RepositoryError) as error:
        print(f"repository verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
