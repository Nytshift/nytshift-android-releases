#!/usr/bin/env python3
"""Fail-closed verification and staging for public NYTSHIFT PAPER APK releases.

This repository deliberately contains no Android application source. The signing job
does not execute this file; it runs a small, in-workflow boundary and emits a bounded
handoff. A fresh, secret-free runner executes this verifier before publication.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
import subprocess
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


EXPECTED_SOURCE_REPOSITORY = "Nytshift/nytshift-android"
EXPECTED_PUBLIC_REPOSITORY = "Nytshift/nytshift-android-releases"
EXPECTED_SOURCE_BRANCH = "main"
EXPECTED_SOURCE_WORKFLOW = "android-ci"
EXPECTED_SOURCE_WORKFLOW_PATH = ".github/workflows/ci.yml"
EXPECTED_SOURCE_COMMIT = "61f837f304b3942f65cb3d99f1a4236bcd420e41"
EXPECTED_PACKAGE = "xyz.nytshift.app.staging"
EXPECTED_VARIANT = "stagingRelease"
EXPECTED_CHANNEL = "PAPER"
EXPECTED_JVM_TESTS = 338
EXPECTED_ANDROID_TESTS = 39
EXPECTED_SCREENSHOT_REFERENCES = 46
EXPECTED_DEVICE_API = 36
EXPECTED_DEVICE_IMAGE = "google_apis;x86_64"
SIGNED_APK_NAME = "nytshift-staging-release-signed.apk"
UNSIGNED_APK_NAME = "app-staging-release-unsigned.apk"
PUBLIC_APK_NAME = "nytshift-staging-release.apk"
BUILD_CONFIG_NAME = "stagingRelease-BuildConfig.java"
HANDOFF_MANIFEST_NAME = "signing-handoff.json"
CHECKSUM_NAME = "SHA256SUMS"
RELEASE_EVIDENCE_NAME = "release-evidence.json"
DEVICE_EVIDENCE_NAME = "device-evidence.json"
TOOLCHAIN_EVIDENCE_NAME = "audited-sdk-inventory.json"
ANDROID_XML = "{http://schemas.android.com/apk/res/android}"
EXPECTED_PERMISSIONS = {
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.INTERNET",
    f"{EXPECTED_PACKAGE}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
}
EXPECTED_EXPORTED_COMPONENTS = {
    ("activity", "xyz.nytshift.app.MainActivity", None),
    ("receiver", "androidx.profileinstaller.ProfileInstallReceiver", "android.permission.DUMP"),
}
EXPECTED_DEVICE_COMPONENTS = {
    "emulator": ("emulator/source.properties", "37.1.11"),
    "platformTools": ("platform-tools/source.properties", "37.0.1"),
    "systemImage": ("system-images/android-36/google_apis/x86_64/source.properties", "7"),
}

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-staging$")
CERTIFICATE_RE = re.compile(
    r"^Signer #(\d+) certificate SHA-256 digest: ([0-9A-Fa-f:]{64,95})$",
    re.MULTILINE,
)
SCHEME_RE = re.compile(
    r"^Verified using v([1234]) scheme \([^\r\n]+\): (true|false)$",
    re.MULTILINE,
)
MAX_APK_BYTES = 500 * 1024 * 1024
MAX_APK_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_ZIP_ENTRIES = 20_000
MAX_HANDOFF_BYTES = 1024 * 1024 * 1024

EXPECTED_HANDOFF_INVENTORY = sorted(
    [
        CHECKSUM_NAME,
        BUILD_CONFIG_NAME,
        DEVICE_EVIDENCE_NAME,
        TOOLCHAIN_EVIDENCE_NAME,
        RELEASE_EVIDENCE_NAME,
        SIGNED_APK_NAME,
        HANDOFF_MANIFEST_NAME,
        UNSIGNED_APK_NAME,
    ]
)

EXPECTED_RELEASE_INVENTORY = sorted(
    [
        CHECKSUM_NAME,
        "android-paper-preview.json",
        PUBLIC_APK_NAME,
        "provenance.json",
        "release-notes.md",
    ]
)


class ReleaseGateError(RuntimeError):
    """Raised when any release invariant is absent or contradictory."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_certificate(raw: str) -> str:
    value = raw.replace(":", "").lower()
    if not SHA256_RE.fullmatch(value):
        raise ReleaseGateError("signing certificate SHA-256 is malformed")
    return value


def normalize_login(raw: str) -> str:
    value = raw.strip().lower()
    if not LOGIN_RE.fullmatch(value):
        raise ReleaseGateError("accountable GitHub login is malformed")
    return value


def normalize_reviewer(raw: str) -> str:
    prefix, separator, login = raw.strip().partition(":")
    if separator != ":" or prefix.lower() != "user":
        raise ReleaseGateError("configured environment reviewer must be one exact user")
    return f"user:{normalize_login(login)}"


def safe_relative_path(raw: str) -> str:
    path = PurePosixPath(raw)
    if (
        not raw
        or len(raw) > 512
        or path.is_absolute()
        or "\\" in raw
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ReleaseGateError(f"unsafe relative path: {raw!r}")
    return path.as_posix()


def regular_file(path: Path, maximum_bytes: int) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ReleaseGateError(f"required regular file is missing or unsafe: {path}")
    size = path.stat().st_size
    if size not in range(1, maximum_bytes + 1):
        raise ReleaseGateError(f"required file is empty or exceeds its bound: {path} ({size})")
    return path


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(regular_file(path, MAX_JSON_BYTES).read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseGateError(f"invalid JSON: {path}") from error
    if not isinstance(value, dict):
        raise ReleaseGateError(f"JSON root must be an object: {path}")
    return value


def read_text(path: Path, maximum_bytes: int = MAX_TEXT_BYTES) -> str:
    try:
        return regular_file(path, maximum_bytes).read_text(encoding="utf-8")
    except UnicodeError as error:
        raise ReleaseGateError(f"text file is not UTF-8: {path}") from error


def actual_regular_inventory(root: Path) -> list[str]:
    if root.is_symlink() or not root.is_dir():
        raise ReleaseGateError(f"package root is missing or unsafe: {root}")
    inventory: list[str] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ReleaseGateError(f"package contains a symlink: {path}")
        if path.is_file():
            inventory.append(path.relative_to(root).as_posix())
    return sorted(inventory)


def verify_checksum_package(
    root: Path,
    expected_inventory: Iterable[str],
    *,
    maximum_total_bytes: int = MAX_HANDOFF_BYTES,
) -> None:
    expected = sorted(safe_relative_path(item) for item in expected_inventory)
    if not expected or len(expected) != len(set(expected)) or CHECKSUM_NAME not in expected:
        raise ReleaseGateError("expected package inventory is malformed")
    actual = actual_regular_inventory(root)
    if actual != expected:
        raise ReleaseGateError(f"package inventory differs: expected={expected!r} actual={actual!r}")
    checksums = read_text(root / CHECKSUM_NAME, 2 * 1024 * 1024)
    parsed: dict[str, str] = {}
    for line in checksums.splitlines():
        match = re.fullmatch(r"([a-f0-9]{64}) \*(.+)", line)
        if not match:
            raise ReleaseGateError("checksum manifest contains a malformed line")
        relative = safe_relative_path(match.group(2))
        if relative in parsed:
            raise ReleaseGateError("checksum manifest contains a duplicate path")
        parsed[relative] = match.group(1)
    expected_coverage = set(expected) - {CHECKSUM_NAME}
    if set(parsed) != expected_coverage:
        raise ReleaseGateError("checksum coverage differs from package inventory")
    total = 0
    for relative, digest in parsed.items():
        path = regular_file(root / relative, MAX_APK_BYTES if relative.endswith(".apk") else MAX_TEXT_BYTES)
        total += path.stat().st_size
        if total > maximum_total_bytes or sha256(path) != digest:
            raise ReleaseGateError(f"checksum verification failed: {relative}")


def _exact_source(source: Any, commit: str) -> bool:
    return source == {
        "repository": EXPECTED_SOURCE_REPOSITORY,
        "commitSha": commit,
        "sourceTreeClean": True,
    }


def _green_test_summary(
    value: Any,
    *,
    expected_tests: int,
    step_outcome: bool = False,
) -> bool:
    if not isinstance(value, dict):
        return False
    expected_keys = {"suites", "tests", "failures", "errors", "skipped"}
    if step_outcome:
        expected_keys |= {"stepOutcome", "collectionError"}
    if set(value) != expected_keys:
        return False
    if step_outcome and (value.get("stepOutcome") != "success" or value.get("collectionError") is not None):
        return False
    return (
        isinstance(value.get("suites"), int)
        and value["suites"] > 0
        and isinstance(value.get("tests"), int)
        and value["tests"] == expected_tests
        and value.get("failures") == 0
        and value.get("errors") == 0
        and value.get("skipped") == 0
    )


def _file_record(manifest: dict[str, Any], relative: str) -> dict[str, Any]:
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > 4096:
        raise ReleaseGateError("release evidence file inventory is invalid")
    matches = [item for item in files if isinstance(item, dict) and item.get("path") == relative]
    if len(matches) != 1:
        raise ReleaseGateError(f"release evidence lacks one exact file record: {relative}")
    record = matches[0]
    if (
        set(record) != {"bytes", "path", "role", "sha256"}
        or not isinstance(record.get("bytes"), int)
        or record["bytes"] < 1
        or not SHA256_RE.fullmatch(str(record.get("sha256", "")))
    ):
        raise ReleaseGateError(f"release evidence file record is malformed: {relative}")
    return record


def validate_evidence_summaries(
    release: dict[str, Any],
    device: dict[str, Any],
    commit: str,
) -> tuple[str, int, dict[str, Any], dict[str, Any]]:
    if not COMMIT_RE.fullmatch(commit):
        raise ReleaseGateError("source commit is malformed")
    toolchain = validate_audited_toolchain(device.get("toolchain"))
    if (
        release.get("schemaVersion") != "2"
        or release.get("kind") != "nytshift.android.unsigned-release-evidence"
        or not _exact_source(release.get("source"), commit)
        or release.get("authority")
        != {"executionEnabled": False, "allowMainnet": False, "executionAuthority": "none"}
    ):
        raise ReleaseGateError("release evidence is not the exact fail-closed source candidate")
    verification = release.get("verification")
    variants = release.get("variants")
    version_source = release.get("versionSource")
    expected_verification = {
        "androidTests": "compiled-not-executed-in-verify-job; see separate device evidence",
        "jvmTests": verification.get("jvmTests") if isinstance(verification, dict) else None,
        "productionLint": "passed-before-evidence-step",
        "productionManifest": "verified-before-evidence-step",
        "screenshotReferences": "validated-before-evidence-step",
        "stagingManifest": "verified-before-evidence-step",
    }
    if (
        not isinstance(verification, dict)
        or verification != expected_verification
        or not _green_test_summary(
            verification.get("jvmTests"), expected_tests=EXPECTED_JVM_TESTS
        )
        or release.get("inventory")
        != {
            "androidTestAnnotations": EXPECTED_ANDROID_TESTS,
            "jvmTestAnnotations": EXPECTED_JVM_TESTS,
            "reviewedScreenshotReferences": EXPECTED_SCREENSHOT_REFERENCES,
        }
    ):
        raise ReleaseGateError("release evidence does not contain a green JVM test summary")
    if not isinstance(variants, dict) or not isinstance(version_source, dict):
        raise ReleaseGateError("release evidence version or variant contract is incomplete")
    expected_version = version_source.get("expected")
    staging = variants.get("stagingRelease")
    if not isinstance(expected_version, dict) or not isinstance(staging, dict):
        raise ReleaseGateError("release evidence lacks the staging release identity")
    version_code = expected_version.get("versionCode")
    base_version = expected_version.get("versionName")
    version_name = f"{base_version}-staging"
    if (
        not isinstance(version_code, int)
        or version_code not in range(1, 2_100_000_001)
        or not isinstance(base_version, str)
        or not VERSION_RE.fullmatch(version_name)
        or staging
        != {
            "applicationId": EXPECTED_PACKAGE,
            "versionCode": version_code,
            "versionName": version_name,
            "environment": "staging",
            "signing": "unsigned",
        }
    ):
        raise ReleaseGateError("staging release identity is not exact")
    if (
        device.get("schemaVersion") != "1"
        or device.get("kind") != "nytshift.android.emulator-test-evidence"
        or not _exact_source(device.get("source"), commit)
        or not isinstance(device.get("device"), dict)
        or device["device"].get("apiLevel") != EXPECTED_DEVICE_API
        or device["device"].get("image") != EXPECTED_DEVICE_IMAGE
        or not _green_test_summary(
            device.get("androidTest"),
            expected_tests=EXPECTED_ANDROID_TESTS,
            step_outcome=True,
        )
        or device.get("toolchain") != toolchain
    ):
        raise ReleaseGateError("device evidence is not an exact green API-36 run")
    apk_record = _file_record(release, "artifacts/app-staging-release-unsigned.apk")
    build_config_record = _file_record(release, "manifests/stagingRelease-BuildConfig.java")
    return version_name, version_code, apk_record, build_config_record


def validate_audited_toolchain(payload: Any) -> dict[str, Any]:
    if (
        not isinstance(payload, dict)
        or payload.get("schemaVersion") != "1"
        or payload.get("kind") != "nytshift.android.audited-sdk-inventory"
        or not isinstance(payload.get("components"), list)
    ):
        raise ReleaseGateError("audited device SDK inventory shape differs")
    components = payload["components"]
    names = {item.get("component") for item in components if isinstance(item, dict)}
    if len(components) != len(EXPECTED_DEVICE_COMPONENTS) or names != set(EXPECTED_DEVICE_COMPONENTS):
        raise ReleaseGateError("audited device SDK component inventory differs")
    for item in components:
        if not isinstance(item, dict):
            raise ReleaseGateError("audited device SDK record is invalid")
        component = item.get("component")
        relative, revision = EXPECTED_DEVICE_COMPONENTS[component]
        if (
            item.get("sourceProperties") != relative
            or item.get("revision") != revision
            or not SHA256_RE.fullmatch(str(item.get("sourcePropertiesSha256", "")))
        ):
            raise ReleaseGateError(f"audited device SDK component differs: {component}")
    return payload


def validate_build_config(text: str, version_name: str, version_code: int) -> None:
    required = {
        'public static final boolean DEBUG = false;',
        f'public static final String APPLICATION_ID = "{EXPECTED_PACKAGE}";',
        'public static final String BUILD_TYPE = "release";',
        'public static final String FLAVOR = "staging";',
        f"public static final int VERSION_CODE = {version_code};",
        f'public static final String VERSION_NAME = "{version_name}";',
        'public static final boolean ALLOW_MAINNET = false;',
        'public static final String ENVIRONMENT = "staging";',
        'public static final String EXECUTION_AUTHORITY = "none";',
        'public static final boolean EXECUTION_ENABLED = false;',
    }
    normalized = {line.strip() for line in text.splitlines()}
    missing = sorted(required - normalized)
    if missing:
        raise ReleaseGateError(f"staging BuildConfig is missing fail-closed constants: {missing!r}")
    forbidden = (
        "EXECUTION_ENABLED = true",
        "ALLOW_MAINNET = true",
        'EXECUTION_AUTHORITY = "live"',
        'EXECUTION_AUTHORITY = "venue"',
        "DEBUG = true",
    )
    if any(value in text for value in forbidden):
        raise ReleaseGateError("staging BuildConfig contains an enabled authority or debug constant")


def zip_payload(path: Path) -> dict[str, tuple[int, str]]:
    regular_file(path, MAX_APK_BYTES)
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) not in range(1, MAX_ZIP_ENTRIES + 1):
                raise ReleaseGateError("APK ZIP inventory is empty or exceeds its bound")
            payload: dict[str, tuple[int, str]] = {}
            total = 0
            for item in entries:
                raw = item.filename.rstrip("/")
                if not raw and item.is_dir():
                    continue
                name = safe_relative_path(raw)
                if item.is_dir():
                    continue
                total += item.file_size
                if item.file_size > MAX_APK_BYTES or total > MAX_APK_UNCOMPRESSED_BYTES:
                    raise ReleaseGateError("APK uncompressed payload exceeds its bound")
                if name in payload:
                    raise ReleaseGateError("APK ZIP contains duplicate entries")
                digest = hashlib.sha256()
                with archive.open(item) as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                payload[name] = (item.file_size, digest.hexdigest())
    except (OSError, zipfile.BadZipFile) as error:
        raise ReleaseGateError(f"APK is not a valid ZIP: {path}") from error
    if "AndroidManifest.xml" not in payload or "classes.dex" not in payload:
        raise ReleaseGateError("APK lacks its manifest or primary DEX payload")
    return payload


def require_unchanged_payload(unsigned_apk: Path, signed_apk: Path) -> None:
    if zip_payload(unsigned_apk) != zip_payload(signed_apk):
        raise ReleaseGateError("signed APK payload differs from the CI-verified unsigned APK")


def run_tool(arguments: list[str], *, timeout: int = 60) -> str:
    try:
        process = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReleaseGateError(f"tool invocation failed: {arguments[0]}") from error
    output = f"{process.stdout}\n{process.stderr}"
    if process.returncode != 0:
        raise ReleaseGateError(f"tool rejected the candidate: {arguments[0]}\n{output[-4000:]}")
    return output


def validate_badging_output(output: str, version_name: str, version_code: int) -> None:
    package_match = re.search(
        r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'(?: .*)?$",
        output,
        re.MULTILINE,
    )
    if not package_match or package_match.groups() != (EXPECTED_PACKAGE, str(version_code), version_name):
        raise ReleaseGateError("APK badging package/version identity differs")
    if "minSdkVersion:'28'" not in output or "targetSdkVersion:'36'" not in output:
        raise ReleaseGateError("APK SDK bounds differ from the release contract")
    permissions = set(re.findall(r"^uses-permission: name='([^']+)'$", output, re.MULTILINE))
    expected_permissions = {
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        f"{EXPECTED_PACKAGE}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
    }
    if permissions != expected_permissions:
        raise ReleaseGateError(f"APK permission surface differs: {sorted(permissions)!r}")
    if "application-debuggable" in output or "testOnly='true'" in output:
        raise ReleaseGateError("APK is debuggable or test-only")


def validate_decoded_manifest(manifest_xml: str, version_name: str, version_code: int) -> None:
    if len(manifest_xml.encode("utf-8")) > 2 * 1024 * 1024:
        raise ReleaseGateError("decoded APK manifest exceeds its bound")
    try:
        root = ET.fromstring(manifest_xml)
    except ET.ParseError as error:
        raise ReleaseGateError("decoded APK manifest is not valid XML") from error
    if (
        root.tag != "manifest"
        or root.get("package") != EXPECTED_PACKAGE
        or root.get(f"{ANDROID_XML}versionCode") != str(version_code)
        or root.get(f"{ANDROID_XML}versionName") != version_name
        or root.get(f"{ANDROID_XML}sharedUserId") is not None
    ):
        raise ReleaseGateError("decoded APK package/version identity differs")
    uses_sdk = root.find("uses-sdk")
    if (
        uses_sdk is None
        or uses_sdk.get(f"{ANDROID_XML}minSdkVersion") != "28"
        or uses_sdk.get(f"{ANDROID_XML}targetSdkVersion") != "36"
    ):
        raise ReleaseGateError("decoded APK SDK boundary differs")
    permissions = [
        node.get(f"{ANDROID_XML}name")
        for node in root
        if node.tag in {"uses-permission", "uses-permission-sdk-23"}
    ]
    if len(permissions) != len(EXPECTED_PERMISSIONS) or set(permissions) != EXPECTED_PERMISSIONS:
        raise ReleaseGateError("decoded APK permission surface differs")
    application = root.find("application")
    if application is None or (
        application.get(f"{ANDROID_XML}name") != "xyz.nytshift.app.NytshiftApplication"
        or application.get(f"{ANDROID_XML}debuggable") not in {None, "false"}
        or application.get(f"{ANDROID_XML}testOnly") not in {None, "false"}
        or application.get(f"{ANDROID_XML}allowBackup") != "false"
        or application.get(f"{ANDROID_XML}usesCleartextTraffic") != "false"
    ):
        raise ReleaseGateError("decoded APK application security surface differs")
    components = [
        (tag, node)
        for tag in ("activity", "activity-alias", "service", "receiver", "provider")
        for node in application.findall(tag)
    ]
    exported = {
        (tag, node.get(f"{ANDROID_XML}name"), node.get(f"{ANDROID_XML}permission"))
        for tag, node in components
        if node.get(f"{ANDROID_XML}exported") == "true"
    }
    if exported != EXPECTED_EXPORTED_COMPONENTS:
        raise ReleaseGateError("decoded APK exported-component allowlist differs")
    providers = [
        node
        for tag, node in components
        if tag == "provider" and node.get(f"{ANDROID_XML}name") == "androidx.core.content.FileProvider"
    ]
    if len(providers) != 1 or (
        providers[0].get(f"{ANDROID_XML}authorities") != f"{EXPECTED_PACKAGE}.fileprovider"
        or providers[0].get(f"{ANDROID_XML}exported") != "false"
        or providers[0].get(f"{ANDROID_XML}grantUriPermissions") != "true"
    ):
        raise ReleaseGateError("decoded APK FileProvider surface differs")


def verify_apk_manifest(
    aapt2: Path,
    apkanalyzer: Path,
    apk: Path,
    version_name: str,
    version_code: int,
) -> None:
    regular_file(aapt2, 64 * 1024 * 1024)
    badging = run_tool([str(aapt2), "dump", "badging", str(apk)])
    validate_badging_output(badging, version_name, version_code)
    regular_file(apkanalyzer, 64 * 1024 * 1024)
    decoded = run_tool([str(apkanalyzer), "manifest", "print", str(apk)])
    validate_decoded_manifest(decoded.strip(), version_name, version_code)


def validate_apksigner_output(output: str, expected_certificate: str) -> str:
    if "WARNING:" in output.upper() or "DOES NOT VERIFY" in output.upper():
        raise ReleaseGateError("APK signature verifier returned a warning or failure")
    digests = CERTIFICATE_RE.findall(output)
    if len(digests) != 1 or digests[0][0] != "1":
        raise ReleaseGateError("signed APK must contain exactly one signer")
    actual = normalize_certificate(digests[0][1])
    schemes = {version: value == "true" for version, value in SCHEME_RE.findall(output)}
    if (
        actual != normalize_certificate(expected_certificate)
        or schemes.get("1") is not False
        or schemes.get("2") is not True
        or schemes.get("3") is not True
    ):
        raise ReleaseGateError("APK signer identity or signing schemes differ")
    return actual


def verify_apk_signature(apksigner: Path, apk: Path, expected_certificate: str) -> str:
    regular_file(apksigner, 64 * 1024 * 1024)
    output = run_tool(
        [str(apksigner), "verify", "--verbose", "--print-certs", "--Werr", str(apk)]
    )
    return validate_apksigner_output(output, expected_certificate)


def validate_handoff_provenance(
    handoff: dict[str, Any],
    *,
    source_commit: str,
    source_run_id: str,
    public_repository: str,
    public_commit: str,
    certificate: str,
    configured_reviewer: str,
    key_owner: str,
) -> None:
    if (
        handoff.get("schemaVersion") != "1"
        or handoff.get("kind") != "nytshift.android.paper-signing-handoff"
        or handoff.get("channel") != EXPECTED_CHANNEL
        or handoff.get("packageInventory") != EXPECTED_HANDOFF_INVENTORY
    ):
        raise ReleaseGateError("signing handoff schema, channel, or inventory differs")
    source = handoff.get("source")
    expected_source = {
        "branch": EXPECTED_SOURCE_BRANCH,
        "commitSha": source_commit,
        "commitUrl": f"https://github.com/{EXPECTED_SOURCE_REPOSITORY}/commit/{source_commit}",
        "event": "push",
        "repository": EXPECTED_SOURCE_REPOSITORY,
        "runId": int(source_run_id),
        "runUrl": f"https://github.com/{EXPECTED_SOURCE_REPOSITORY}/actions/runs/{source_run_id}",
        "workflowName": EXPECTED_SOURCE_WORKFLOW,
        "workflowPath": EXPECTED_SOURCE_WORKFLOW_PATH,
    }
    if source != expected_source:
        raise ReleaseGateError("signing handoff source provenance differs")
    public = handoff.get("publicPreparation")
    if (
        not isinstance(public, dict)
        or public.get("repository") != public_repository
        or public.get("commitSha") != public_commit
        or public.get("commitUrl") != f"https://github.com/{public_repository}/commit/{public_commit}"
        or public.get("configuredEnvironmentReviewer") != configured_reviewer
        or public.get("signingKeyOwner") != key_owner
        or not isinstance(public.get("workflowRunId"), int)
        or public.get("workflowRunId", 0) < 1
        or public.get("workflowRunUrl")
        != f"https://github.com/{public_repository}/actions/runs/{public['workflowRunId']}"
    ):
        raise ReleaseGateError("public preparation provenance differs")
    artifacts = handoff.get("sourceArtifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"device", "release"}:
        raise ReleaseGateError("source artifact provenance is incomplete")
    expected_names = {
        "release": f"nytshift-android-unsigned-release-evidence-{source_commit}",
        "device": f"nytshift-android-device-evidence-{source_commit}",
    }
    for role, expected_name in expected_names.items():
        value = artifacts.get(role)
        if (
            not isinstance(value, dict)
            or value.get("name") != expected_name
            or not isinstance(value.get("id"), int)
            or value["id"] < 1
            or not SHA256_RE.fullmatch(str(value.get("archiveSha256", "")))
            or not SHA256_RE.fullmatch(str(value.get("artifactDigest", "")).removeprefix("sha256:"))
            or value.get("archiveSha256")
            != str(value.get("artifactDigest", "")).removeprefix("sha256:")
            or not SHA256_RE.fullmatch(str(value.get("evidenceManifestSha256", "")))
            or not SHA256_RE.fullmatch(str(value.get("checksumManifestSha256", "")))
            or not isinstance(value.get("packageInventoryCount"), int)
            or value["packageInventoryCount"] < 2
            or value.get("apiUrl")
            != f"https://api.github.com/repos/{EXPECTED_SOURCE_REPOSITORY}/actions/artifacts/{value['id']}"
            or value.get("archiveDownloadUrl")
            != f"https://api.github.com/repos/{EXPECTED_SOURCE_REPOSITORY}/actions/artifacts/{value['id']}/zip"
        ):
            raise ReleaseGateError(f"source {role} artifact provenance differs")
    candidate = handoff.get("candidate")
    if (
        not isinstance(candidate, dict)
        or candidate.get("authority")
        != {"executionEnabled": False, "allowMainnet": False, "executionAuthority": "none"}
        or candidate.get("buildVariant") != EXPECTED_VARIANT
        or candidate.get("channel") != EXPECTED_CHANNEL
        or candidate.get("debuggable") is not False
        or candidate.get("packageName") != EXPECTED_PACKAGE
        or candidate.get("signingKeyOwner") != key_owner
        or normalize_certificate(str(candidate.get("signingCertificateSha256", ""))) != certificate
    ):
        raise ReleaseGateError("signing handoff candidate is not exact and fail-closed")


def _require_record_matches(record: dict[str, Any], path: Path) -> None:
    if record.get("bytes") != path.stat().st_size or record.get("sha256") != sha256(path):
        raise ReleaseGateError(f"evidence file record differs from handoff file: {path.name}")


def _validate_handoff_file_records(
    handoff: dict[str, Any],
    unsigned_apk: Path,
    signed_apk: Path,
    build_config: Path,
    toolchain_inventory: Path,
    apk_record: dict[str, Any],
    build_config_record: dict[str, Any],
) -> None:
    _require_record_matches(apk_record, unsigned_apk)
    _require_record_matches(build_config_record, build_config)
    audited = validate_audited_toolchain(read_json(toolchain_inventory))
    if read_json(unsigned_apk.parent / DEVICE_EVIDENCE_NAME).get("toolchain") != audited:
        raise ReleaseGateError("retained audited SDK inventory differs from device evidence")
    candidate = handoff["candidate"]
    for key, path in (("unsignedApk", unsigned_apk), ("signedApk", signed_apk)):
        value = candidate.get(key)
        if (
            not isinstance(value, dict)
            or value.get("fileName") != path.name
            or value.get("bytes") != path.stat().st_size
            or value.get("sha256") != sha256(path)
        ):
            raise ReleaseGateError(f"handoff {key} record differs from the retained APK")
    artifacts = handoff["sourceArtifacts"]
    release_manifest = Path(RELEASE_EVIDENCE_NAME)
    device_manifest = Path(DEVICE_EVIDENCE_NAME)
    if artifacts["release"]["evidenceManifestSha256"] != sha256(unsigned_apk.parent / release_manifest):
        raise ReleaseGateError("release evidence manifest hash differs")
    if artifacts["device"]["evidenceManifestSha256"] != sha256(unsigned_apk.parent / device_manifest):
        raise ReleaseGateError("device evidence manifest hash differs")


def stage_public_release(
    output: Path,
    handoff: dict[str, Any],
    signed_apk: Path,
    *,
    public_repository: str,
    public_commit: str,
    prepared_at: str,
) -> tuple[str, str]:
    if output.exists() and (output.is_symlink() or not output.is_dir() or any(output.iterdir())):
        raise ReleaseGateError("release output must be a new or empty directory")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", prepared_at):
        raise ReleaseGateError("prepared-at must be UTC without fractional seconds")
    candidate = handoff["candidate"]
    source = handoff["source"]
    version_name = candidate["versionName"]
    version_code = candidate["versionCode"]
    certificate = candidate["signingCertificateSha256"]
    tag = f"android-paper-preview-v{version_name}"
    release_url = f"https://github.com/{public_repository}/releases/tag/{tag}"
    download_url = f"https://github.com/{public_repository}/releases/download/{tag}/{PUBLIC_APK_NAME}"
    output.mkdir(parents=True, exist_ok=True)
    apk = output / PUBLIC_APK_NAME
    shutil.copyfile(signed_apk, apk)
    apk_digest = sha256(apk)
    metadata = {
        "artifact": {
            "bytes": apk.stat().st_size,
            "downloadUrl": download_url,
            "fileName": PUBLIC_APK_NAME,
            "sha256": apk_digest,
            "signingStatus": "signed",
        },
        "accountability": {
            "configuredEnvironmentReviewer": handoff["publicPreparation"][
                "configuredEnvironmentReviewer"
            ],
            "signingKeyOwner": candidate["signingKeyOwner"],
        },
        "buildVariant": EXPECTED_VARIANT,
        "channel": EXPECTED_CHANNEL,
        "debuggable": False,
        "evidenceInventory": {
            "androidTests": EXPECTED_ANDROID_TESTS,
            "jvmTests": EXPECTED_JVM_TESTS,
            "reviewedScreenshotReferences": EXPECTED_SCREENSHOT_REFERENCES,
        },
        "packageName": EXPECTED_PACKAGE,
        "platform": "android",
        "preparedAt": prepared_at,
        "publicationPolicy": {
            "immutableReleaseRequired": True,
            "postPublicationVerificationRequired": True,
            "unsignedPublicArtifactsAllowed": False,
        },
        "publicRelease": {
            "repository": public_repository,
            "releaseUrl": release_url,
            "tag": tag,
            "targetCommit": public_commit,
        },
        "schemaVersion": "1",
        "signature": {
            "certificateSha256": certificate,
            "schemes": ["v2", "v3"],
            "verified": True,
        },
        "status": "available",
        "versionCode": version_code,
        "versionName": version_name,
    }
    provenance = {
        "accountability": metadata["accountability"],
        "authority": candidate["authority"],
        "candidate": {
            "apkSha256": apk_digest,
            "certificateSha256": certificate,
            "packageName": EXPECTED_PACKAGE,
            "signingStatus": "signed",
            "versionCode": version_code,
            "versionName": version_name,
        },
        "evidenceInventory": metadata["evidenceInventory"],
        "evidence": {
            "device": handoff["sourceArtifacts"]["device"],
            "release": handoff["sourceArtifacts"]["release"],
        },
        "publicPreparation": handoff["publicPreparation"],
        "schemaVersion": "1",
        "source": source,
    }
    (output / "android-paper-preview.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (output / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    escaped = {key: html.escape(str(value), quote=True) for key, value in {
        "version": version_name,
        "code": version_code,
        "package": EXPECTED_PACKAGE,
        "source": source["commitSha"],
        "source_run": source["runUrl"],
        "apk": apk_digest,
        "certificate": certificate,
        "download": download_url,
        "key_owner": candidate["signingKeyOwner"],
        "reviewer": handoff["publicPreparation"]["configuredEnvironmentReviewer"],
    }.items()}
    (output / "release-notes.md").write_text(
        "# NYTSHIFT Android PAPER preview\n\n"
        "This is a signed, non-debug staging build for public market reads and deterministic local "
        "PAPER trading only. It cannot place a live venue order, sign a wallet or transaction, "
        "transfer funds, or withdraw funds.\n\n"
        f"- Version: `{escaped['version']}` (`{escaped['code']}`)\n"
        f"- Package: `{escaped['package']}`\n"
        f"- Source commit: [`{escaped['source']}`]({source['commitUrl']})\n"
        f"- Green source run: [Actions run]({escaped['source_run']})\n"
        f"- APK SHA-256: `{escaped['apk']}`\n"
        f"- Certificate SHA-256: `{escaped['certificate']}`\n"
        f"- Signing key owner: `{escaped['key_owner']}`\n"
        f"- Configured environment reviewer: `{escaped['reviewer']}`\n"
        f"- Verified evidence inventory: `{EXPECTED_JVM_TESTS}` JVM / "
        f"`{EXPECTED_ANDROID_TESTS}` AndroidTest / "
        f"`{EXPECTED_SCREENSHOT_REFERENCES}` reviewed screenshots\n"
        f"- Immutable public download: {escaped['download']}\n\n"
        "Verify the checksum, certificate, immutable release attestation, and package name before installation.\n",
        encoding="utf-8",
        newline="\n",
    )
    content = sorted(path for path in output.iterdir() if path.is_file())
    (output / CHECKSUM_NAME).write_text(
        "".join(f"{sha256(path)} *{path.name}\n" for path in content),
        encoding="ascii",
        newline="\n",
    )
    verify_checksum_package(output, EXPECTED_RELEASE_INVENTORY)
    return tag, download_url


def verify_and_stage(args: argparse.Namespace) -> int:
    handoff_root = args.handoff.resolve()
    output = args.output.resolve()
    source_commit = args.source_commit.lower()
    source_run_id = str(args.source_run_id)
    public_commit = args.public_commit.lower()
    certificate = normalize_certificate(args.certificate_sha256)
    configured_reviewer = normalize_reviewer(args.configured_reviewer)
    key_owner = normalize_login(args.key_owner)
    if configured_reviewer == f"user:{key_owner}":
        raise ReleaseGateError("signing key owner and environment reviewer must be independent")
    if args.public_repository != EXPECTED_PUBLIC_REPOSITORY:
        raise ReleaseGateError("public repository identity differs from the fixed policy")
    if source_commit != EXPECTED_SOURCE_COMMIT or not COMMIT_RE.fullmatch(public_commit):
        raise ReleaseGateError("source or public commit is malformed")
    if not RUN_ID_RE.fullmatch(source_run_id):
        raise ReleaseGateError("source run id is malformed")
    handoff = read_json(handoff_root / HANDOFF_MANIFEST_NAME)
    verify_checksum_package(handoff_root, handoff.get("packageInventory", []))
    validate_handoff_provenance(
        handoff,
        source_commit=source_commit,
        source_run_id=source_run_id,
        public_repository=args.public_repository,
        public_commit=public_commit,
        certificate=certificate,
        configured_reviewer=configured_reviewer,
        key_owner=key_owner,
    )
    release = read_json(handoff_root / RELEASE_EVIDENCE_NAME)
    device = read_json(handoff_root / DEVICE_EVIDENCE_NAME)
    version_name, version_code, apk_record, build_config_record = validate_evidence_summaries(
        release, device, source_commit
    )
    candidate = handoff["candidate"]
    if candidate.get("versionName") != version_name or candidate.get("versionCode") != version_code:
        raise ReleaseGateError("handoff version differs from source evidence")
    unsigned_apk = regular_file(handoff_root / UNSIGNED_APK_NAME, MAX_APK_BYTES)
    signed_apk = regular_file(handoff_root / SIGNED_APK_NAME, MAX_APK_BYTES)
    build_config = regular_file(handoff_root / BUILD_CONFIG_NAME, MAX_TEXT_BYTES)
    toolchain_inventory = regular_file(handoff_root / TOOLCHAIN_EVIDENCE_NAME, 128 * 1024)
    _validate_handoff_file_records(
        handoff,
        unsigned_apk,
        signed_apk,
        build_config,
        toolchain_inventory,
        apk_record,
        build_config_record,
    )
    validate_build_config(read_text(build_config), version_name, version_code)
    require_unchanged_payload(unsigned_apk, signed_apk)
    verify_apk_manifest(
        args.aapt2.resolve(),
        args.apkanalyzer.resolve(),
        signed_apk,
        version_name,
        version_code,
    )
    verified_certificate = verify_apk_signature(
        args.apksigner.resolve(), signed_apk, certificate
    )
    if verified_certificate != certificate:
        raise ReleaseGateError("verified certificate differs unexpectedly")
    tag, download_url = stage_public_release(
        output,
        handoff,
        signed_apk,
        public_repository=args.public_repository,
        public_commit=public_commit,
        prepared_at=args.prepared_at,
    )
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"release_tag={tag}\n")
            stream.write(f"download_url={download_url}\n")
    print(
        "verified and staged NYTSHIFT PAPER release: "
        f"source={source_commit} run={source_run_id} tag={tag} apk={sha256(output / PUBLIC_APK_NAME)}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify-and-stage")
    verify.add_argument("--handoff", required=True, type=Path)
    verify.add_argument("--aapt2", required=True, type=Path)
    verify.add_argument("--apkanalyzer", required=True, type=Path)
    verify.add_argument("--apksigner", required=True, type=Path)
    verify.add_argument("--certificate-sha256", required=True)
    verify.add_argument("--configured-reviewer", required=True)
    verify.add_argument("--key-owner", required=True)
    verify.add_argument("--source-commit", required=True)
    verify.add_argument("--source-run-id", required=True)
    verify.add_argument("--public-repository", required=True)
    verify.add_argument("--public-commit", required=True)
    verify.add_argument("--prepared-at", required=True)
    verify.add_argument("--output", required=True, type=Path)
    verify.add_argument("--github-output", type=Path)
    verify.set_defaults(handler=verify_and_stage)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.handler(args)
    except (ReleaseGateError, OSError, subprocess.SubprocessError) as error:
        print(f"release gate rejected candidate: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
