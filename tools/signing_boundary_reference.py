#!/usr/bin/env python3
"""Reference for the no-checkout signing boundary embedded in the release workflow.

This file is never executed by the secret-bearing job. The workflow contains a
reviewed inline copy so that the job cannot import or execute checked-out repository
code. Tests keep the critical boundary invariants aligned with this reference.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any


SOURCE_REPOSITORY = "Nytshift/nytshift-android"
SOURCE_BRANCH = "main"
SOURCE_WORKFLOW = "android-ci"
SOURCE_WORKFLOW_PATH = ".github/workflows/ci.yml"
SOURCE_COMMIT = "c2a95bebb772d7d76db33df864de41fb231ff14c"
PUBLIC_REPOSITORY = "Nytshift/nytshift-android-releases"
PACKAGE = "xyz.nytshift.app.staging"
EXPECTED_JVM_TESTS = 338
EXPECTED_ANDROID_TESTS = 39
EXPECTED_SCREENSHOT_REFERENCES = 46
ANDROID = "{http://schemas.android.com/apk/res/android}"
EXPECTED_PERMISSIONS = {
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.INTERNET",
    f"{PACKAGE}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
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
LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
CERTIFICATE_RE = re.compile(
    r"^Signer #(\d+) certificate SHA-256 digest: ([0-9A-Fa-f:]{64,95})$", re.MULTILINE
)
SCHEME_RE = re.compile(
    r"^Verified using v([1234]) scheme \([^\r\n]+\): (true|false)$", re.MULTILINE
)
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_EVIDENCE_BYTES = 200 * 1024 * 1024
MAX_APK_BYTES = 500 * 1024 * 1024
MAX_UNCOMPRESSED_APK_BYTES = 1024 * 1024 * 1024
MAX_FILES = 4096
MAX_ZIP_ENTRIES = 20_000


class BoundaryError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Make every credential-bearing GitHub API redirect an explicit failure."""

    def redirect_request(self, request: Any, file_pointer: Any, code: int, message: str, headers: Any, new_url: str) -> None:
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirect)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def regular_file(path: Path, maximum: int) -> Path:
    if path.is_symlink() or not path.is_file() or path.stat().st_size not in range(1, maximum + 1):
        raise BoundaryError(f"missing, empty, oversized, or unsafe file: {path}")
    return path


def safe_path(raw: str) -> str:
    value = PurePosixPath(raw)
    if (
        not raw
        or len(raw) > 512
        or value.is_absolute()
        or "\\" in raw
        or any(part in ("", ".", "..") for part in value.parts)
    ):
        raise BoundaryError(f"unsafe archive/evidence path: {raw!r}")
    return value.as_posix()


def api_json(path: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "nytshift-android-paper-release-boundary",
            "X-GitHub-Api-Version": "2026-03-10",
        },
    )
    try:
        with NO_REDIRECT_OPENER.open(request, timeout=60) as response:
            if response.status != 200:
                raise BoundaryError(f"GitHub API returned {response.status}: {path}")
            body = response.read(8 * 1024 * 1024 + 1)
    except (urllib.error.URLError, TimeoutError) as error:
        raise BoundaryError(f"GitHub API request failed: {path}") from error
    if len(body) > 8 * 1024 * 1024:
        raise BoundaryError("GitHub API response exceeds its bound")
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise BoundaryError("GitHub API returned invalid JSON") from error
    if not isinstance(value, dict):
        raise BoundaryError("GitHub API response is not an object")
    return value


def download_archive(url: str, token: str, destination: Path) -> None:
    expected_prefix = f"https://api.github.com/repos/{SOURCE_REPOSITORY}/actions/artifacts/"
    if not url.startswith(expected_prefix) or not re.fullmatch(r"[1-9][0-9]*/zip", url.removeprefix(expected_prefix)):
        raise BoundaryError("source artifact archive API URL differs")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "nytshift-android-paper-release-boundary",
            "X-GitHub-Api-Version": "2026-03-10",
        },
    )
    try:
        try:
            NO_REDIRECT_OPENER.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            if error.code != 302:
                raise
            location = error.headers.get("Location")
        else:
            raise BoundaryError("source artifact API did not return its required temporary redirect")
        if not location:
            raise BoundaryError("source artifact redirect lacks a location")
        redirected = urllib.parse.urlsplit(location)
        if (
            redirected.scheme != "https"
            or not redirected.hostname
            or redirected.username is not None
            or redirected.password is not None
            or redirected.port not in (None, 443)
            or redirected.fragment
        ):
            raise BoundaryError("source artifact redirect URL is unsafe")
        public_request = urllib.request.Request(
            location,
            headers={"User-Agent": "nytshift-android-paper-release-boundary"},
        )
        # The presigned URL deliberately receives no private-repository Authorization header.
        with NO_REDIRECT_OPENER.open(public_request, timeout=120) as response, destination.open("xb") as stream:
            if response.status != 200:
                raise BoundaryError(f"source artifact storage returned {response.status}")
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise BoundaryError("source artifact archive exceeds its bound")
                stream.write(chunk)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise BoundaryError("source artifact download failed") from error
    regular_file(destination, MAX_ARCHIVE_BYTES)


def extract_archive(archive: Path, output: Path) -> None:
    if output.exists():
        raise BoundaryError("artifact extraction target already exists")
    output.mkdir(parents=True)
    try:
        with zipfile.ZipFile(archive) as source:
            entries = source.infolist()
            if len(entries) not in range(1, MAX_FILES + 1):
                raise BoundaryError("artifact archive file count differs")
            names: set[str] = set()
            total = 0
            for item in entries:
                raw = item.filename.rstrip("/")
                if not raw and item.is_dir():
                    continue
                relative = safe_path(raw)
                if relative in names:
                    raise BoundaryError("artifact archive contains duplicate entries")
                names.add(relative)
                unix_mode = item.external_attr >> 16
                if unix_mode and stat.S_IFMT(unix_mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise BoundaryError("artifact archive contains a non-regular entry")
                total += item.file_size
                if item.file_size > MAX_EVIDENCE_BYTES or total > MAX_EVIDENCE_BYTES:
                    raise BoundaryError("artifact archive uncompressed payload exceeds its bound")
                target = output / relative
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(item) as reader, target.open("xb") as writer:
                    shutil.copyfileobj(reader, writer, length=1024 * 1024)
    except (OSError, zipfile.BadZipFile) as error:
        raise BoundaryError("source artifact is not a safe ZIP") from error


def read_json(path: Path, maximum: int = 4 * 1024 * 1024) -> dict[str, Any]:
    try:
        value = json.loads(regular_file(path, maximum).read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BoundaryError(f"invalid evidence JSON: {path}") from error
    if not isinstance(value, dict):
        raise BoundaryError(f"evidence JSON is not an object: {path}")
    return value


def verify_package(root: Path, manifest: dict[str, Any]) -> None:
    inventory = manifest.get("packageInventory")
    if not isinstance(inventory, list) or not inventory or len(inventory) > MAX_FILES:
        raise BoundaryError("evidence package inventory is invalid")
    expected = [safe_path(item) for item in inventory if isinstance(item, str)]
    if len(expected) != len(inventory) or len(set(expected)) != len(expected):
        raise BoundaryError("evidence package inventory is duplicated or malformed")
    discovered = list(root.rglob("*"))
    if any(path.is_symlink() or (not path.is_file() and not path.is_dir()) for path in discovered):
        raise BoundaryError("evidence package contains an unsafe filesystem entry")
    actual = sorted(path.relative_to(root).as_posix() for path in discovered if path.is_file())
    if actual != sorted(expected):
        raise BoundaryError("evidence package inventory differs from retained files")
    sums = regular_file(root / "SHA256SUMS", 2 * 1024 * 1024).read_text(encoding="ascii")
    parsed: dict[str, str] = {}
    for line in sums.splitlines():
        match = re.fullmatch(r"([a-f0-9]{64}) \*(.+)", line)
        if not match:
            raise BoundaryError("evidence checksum manifest is malformed")
        relative = safe_path(match.group(2))
        if relative in parsed:
            raise BoundaryError("evidence checksum manifest contains a duplicate")
        parsed[relative] = match.group(1)
    if set(parsed) != set(expected) - {"SHA256SUMS"}:
        raise BoundaryError("evidence checksum coverage differs")
    total = 0
    for relative, expected_digest in parsed.items():
        path = regular_file(root / relative, MAX_EVIDENCE_BYTES)
        total += path.stat().st_size
        if total > MAX_EVIDENCE_BYTES or digest(path) != expected_digest:
            raise BoundaryError(f"evidence checksum failed: {relative}")


def validate_toolchain(payload: Any) -> dict[str, Any]:
    if (
        not isinstance(payload, dict)
        or payload.get("schemaVersion") != "1"
        or payload.get("kind") != "nytshift.android.audited-sdk-inventory"
        or not isinstance(payload.get("components"), list)
    ):
        raise BoundaryError("audited device SDK inventory shape differs")
    components = payload["components"]
    names = {item.get("component") for item in components if isinstance(item, dict)}
    if len(components) != len(EXPECTED_DEVICE_COMPONENTS) or names != set(EXPECTED_DEVICE_COMPONENTS):
        raise BoundaryError("audited device SDK component inventory differs")
    for item in components:
        if not isinstance(item, dict):
            raise BoundaryError("audited device SDK component record is invalid")
        component = item.get("component")
        relative, revision = EXPECTED_DEVICE_COMPONENTS[component]
        if (
            item.get("sourceProperties") != relative
            or item.get("revision") != revision
            or not SHA256_RE.fullmatch(str(item.get("sourcePropertiesSha256", "")))
        ):
            raise BoundaryError(f"audited device SDK component differs: {component}")
    return payload


def validate_evidence(
    release_root: Path, device_root: Path, commit: str
) -> tuple[Path, Path, str, int, dict[str, Any], dict[str, Any]]:
    release = read_json(release_root / "release-evidence.json")
    device = read_json(device_root / "device-evidence.json")
    verify_package(release_root, release)
    verify_package(device_root, device)
    source = {"repository": SOURCE_REPOSITORY, "commitSha": commit, "sourceTreeClean": True}
    authority = {"executionEnabled": False, "allowMainnet": False, "executionAuthority": "none"}
    if (
        release.get("schemaVersion") != "2"
        or release.get("kind") != "nytshift.android.unsigned-release-evidence"
        or release.get("source") != source
        or release.get("authority") != authority
    ):
        raise BoundaryError("release evidence is not the exact fail-closed source candidate")
    expected_version = release.get("versionSource", {}).get("expected")
    staging = release.get("variants", {}).get("stagingRelease")
    verification = release.get("verification")
    tests = verification.get("jvmTests") if isinstance(verification, dict) else None
    expected_verification = {
        "androidTests": "compiled-not-executed-in-verify-job; see separate device evidence",
        "jvmTests": tests,
        "productionLint": "passed-before-evidence-step",
        "productionManifest": "verified-before-evidence-step",
        "screenshotReferences": "validated-before-evidence-step",
        "stagingManifest": "verified-before-evidence-step",
    }
    if (
        not isinstance(expected_version, dict)
        or not isinstance(staging, dict)
        or not isinstance(tests, dict)
        or set(tests) != {"suites", "tests", "failures", "errors", "skipped"}
        or not isinstance(tests.get("suites"), int)
        or tests["suites"] < 1
        or tests.get("tests") != EXPECTED_JVM_TESTS
        or any(tests.get(field) != 0 for field in ("failures", "errors", "skipped"))
        or verification != expected_verification
        or release.get("inventory")
        != {
            "androidTestAnnotations": EXPECTED_ANDROID_TESTS,
            "jvmTestAnnotations": EXPECTED_JVM_TESTS,
            "reviewedScreenshotReferences": EXPECTED_SCREENSHOT_REFERENCES,
        }
    ):
        raise BoundaryError("release JVM evidence is incomplete or failed")
    version_code = expected_version.get("versionCode")
    base_version = expected_version.get("versionName")
    version_name = f"{base_version}-staging"
    if (
        not isinstance(version_code, int)
        or version_code not in range(1, 2_100_000_001)
        or not isinstance(base_version, str)
        or not VERSION_RE.fullmatch(base_version)
        or staging
        != {
            "applicationId": PACKAGE,
            "versionCode": version_code,
            "versionName": version_name,
            "environment": "staging",
            "signing": "unsigned",
        }
    ):
        raise BoundaryError("staging release identity differs")
    toolchain_path = device_root / "toolchain/audited-sdk-inventory.json"
    toolchain = validate_toolchain(read_json(toolchain_path, 128 * 1024))
    android_tests = device.get("androidTest")
    if (
        device.get("schemaVersion") != "1"
        or device.get("kind") != "nytshift.android.emulator-test-evidence"
        or device.get("source") != source
        or not isinstance(device.get("device"), dict)
        or device["device"].get("apiLevel") != 36
        or device["device"].get("image") != "google_apis;x86_64"
        or device.get("toolchain") != toolchain
        or not isinstance(android_tests, dict)
        or android_tests
        != {
            "stepOutcome": "success",
            "collectionError": None,
            "suites": android_tests.get("suites"),
            "tests": EXPECTED_ANDROID_TESTS,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
        }
        or not isinstance(android_tests.get("suites"), int)
        or android_tests["suites"] < 1
    ):
        raise BoundaryError("device evidence is not an exact green API-36 run")
    unsigned = regular_file(
        release_root / "artifacts/app-staging-release-unsigned.apk", MAX_APK_BYTES
    )
    build_config = regular_file(
        release_root / "manifests/stagingRelease-BuildConfig.java", 2 * 1024 * 1024
    )
    build_text = build_config.read_text(encoding="utf-8")
    required = {
        "public static final boolean DEBUG = false;",
        f'public static final String APPLICATION_ID = "{PACKAGE}";',
        'public static final String BUILD_TYPE = "release";',
        'public static final String FLAVOR = "staging";',
        f"public static final int VERSION_CODE = {version_code};",
        f'public static final String VERSION_NAME = "{version_name}";',
        "public static final boolean ALLOW_MAINNET = false;",
        'public static final String ENVIRONMENT = "staging";',
        'public static final String EXECUTION_AUTHORITY = "none";',
        "public static final boolean EXECUTION_ENABLED = false;",
    }
    if not required.issubset({line.strip() for line in build_text.splitlines()}):
        raise BoundaryError("staging BuildConfig authority boundary differs")
    return unsigned, build_config, version_name, version_code, release, device


def validate_manifest(xml: str, version_name: str, version_code: int) -> None:
    if len(xml.encode("utf-8")) > 2 * 1024 * 1024:
        raise BoundaryError("decoded APK manifest exceeds its bound")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as error:
        raise BoundaryError("decoded APK manifest is invalid XML") from error
    if (
        root.tag != "manifest"
        or root.get("package") != PACKAGE
        or root.get(f"{ANDROID}versionCode") != str(version_code)
        or root.get(f"{ANDROID}versionName") != version_name
        or root.get(f"{ANDROID}sharedUserId") is not None
    ):
        raise BoundaryError("decoded APK identity differs")
    uses_sdk = root.find("uses-sdk")
    if (
        uses_sdk is None
        or uses_sdk.get(f"{ANDROID}minSdkVersion") != "28"
        or uses_sdk.get(f"{ANDROID}targetSdkVersion") != "36"
    ):
        raise BoundaryError("decoded APK SDK boundary differs")
    permissions = [
        node.get(f"{ANDROID}name")
        for node in root
        if node.tag in {"uses-permission", "uses-permission-sdk-23"}
    ]
    if len(permissions) != len(EXPECTED_PERMISSIONS) or set(permissions) != EXPECTED_PERMISSIONS:
        raise BoundaryError("decoded APK permission surface differs")
    application = root.find("application")
    if application is None or (
        application.get(f"{ANDROID}name") != "xyz.nytshift.app.NytshiftApplication"
        or application.get(f"{ANDROID}debuggable") not in {None, "false"}
        or application.get(f"{ANDROID}testOnly") not in {None, "false"}
        or application.get(f"{ANDROID}allowBackup") != "false"
        or application.get(f"{ANDROID}usesCleartextTraffic") != "false"
    ):
        raise BoundaryError("decoded APK application security surface differs")
    components = [
        (tag, node)
        for tag in ("activity", "activity-alias", "service", "receiver", "provider")
        for node in application.findall(tag)
    ]
    exported = {
        (tag, node.get(f"{ANDROID}name"), node.get(f"{ANDROID}permission"))
        for tag, node in components
        if node.get(f"{ANDROID}exported") == "true"
    }
    if exported != EXPECTED_EXPORTED_COMPONENTS:
        raise BoundaryError("decoded APK exported component allowlist differs")
    providers = [
        node
        for tag, node in components
        if tag == "provider" and node.get(f"{ANDROID}name") == "androidx.core.content.FileProvider"
    ]
    if len(providers) != 1 or (
        providers[0].get(f"{ANDROID}authorities") != f"{PACKAGE}.fileprovider"
        or providers[0].get(f"{ANDROID}exported") != "false"
        or providers[0].get(f"{ANDROID}grantUriPermissions") != "true"
    ):
        raise BoundaryError("decoded APK FileProvider surface differs")


def run(arguments: list[str], *, timeout: int = 90, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise BoundaryError(f"tool invocation failed: {arguments[0]}") from error


def decoded_manifest(apkanalyzer: Path, apk: Path) -> str:
    process = run([str(regular_file(apkanalyzer, 64 * 1024 * 1024)), "manifest", "print", str(apk)])
    if process.returncode != 0 or process.stderr.strip():
        raise BoundaryError("APK manifest decoder rejected the candidate")
    return process.stdout


def zip_payload(path: Path) -> dict[str, tuple[int, str]]:
    regular_file(path, MAX_APK_BYTES)
    payload: dict[str, tuple[int, str]] = {}
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) not in range(1, MAX_ZIP_ENTRIES + 1):
                raise BoundaryError("APK entry inventory differs")
            for item in archive.infolist():
                raw = item.filename.rstrip("/")
                if not raw and item.is_dir():
                    continue
                name = safe_path(raw)
                if item.is_dir():
                    continue
                total += item.file_size
                if item.file_size > MAX_APK_BYTES or total > MAX_UNCOMPRESSED_APK_BYTES:
                    raise BoundaryError("APK uncompressed payload exceeds its bound")
                if name in payload:
                    raise BoundaryError("APK contains duplicate entries")
                value = hashlib.sha256()
                with archive.open(item) as stream:
                    while chunk := stream.read(1024 * 1024):
                        value.update(chunk)
                payload[name] = (item.file_size, value.hexdigest())
    except (OSError, zipfile.BadZipFile) as error:
        raise BoundaryError("APK is not a valid ZIP") from error
    if "AndroidManifest.xml" not in payload or "classes.dex" not in payload:
        raise BoundaryError("APK lacks manifest or primary DEX")
    return payload


def normalize_certificate(raw: str) -> str:
    value = raw.replace(":", "").lower()
    if not SHA256_RE.fullmatch(value):
        raise BoundaryError("certificate fingerprint is malformed")
    return value


def normalize_login(raw: str) -> str:
    value = raw.strip().lower()
    if not LOGIN_RE.fullmatch(value):
        raise BoundaryError("accountable GitHub login is malformed")
    return value


def normalize_reviewer(raw: str) -> str:
    prefix, separator, login = raw.strip().partition(":")
    if separator != ":" or prefix.lower() != "user":
        raise BoundaryError("configured environment reviewer must be one exact user")
    return f"user:{normalize_login(login)}"


def verify_signature(apksigner: Path, apk: Path, expected_certificate: str) -> str:
    process = run(
        [
            str(regular_file(apksigner, 64 * 1024 * 1024)),
            "verify",
            "--verbose",
            "--print-certs",
            "--Werr",
            str(apk),
        ]
    )
    output = f"{process.stdout}\n{process.stderr}"
    if process.returncode != 0 or "WARNING:" in output.upper():
        raise BoundaryError("signed APK verification failed or warned")
    certificates = CERTIFICATE_RE.findall(output)
    schemes = {number: value == "true" for number, value in SCHEME_RE.findall(output)}
    if (
        len(certificates) != 1
        or certificates[0][0] != "1"
        or normalize_certificate(certificates[0][1]) != normalize_certificate(expected_certificate)
        or schemes.get("1") is not False
        or schemes.get("2") is not True
        or schemes.get("3") is not True
    ):
        raise BoundaryError("signed APK signer identity or schemes differ")
    return normalize_certificate(certificates[0][1])


def validate_source_run(token: str, commit: str, run_id: int) -> tuple[dict[str, Any], dict[str, Any]]:
    if commit != SOURCE_COMMIT:
        raise BoundaryError("source commit differs from the fixed reviewed release candidate")
    run_payload = api_json(f"/repos/{SOURCE_REPOSITORY}/actions/runs/{run_id}", token)
    if (
        run_payload.get("name") != SOURCE_WORKFLOW
        or run_payload.get("path") != SOURCE_WORKFLOW_PATH
        or run_payload.get("head_branch") != SOURCE_BRANCH
        or run_payload.get("head_sha") != commit
        or run_payload.get("event") != "push"
        or run_payload.get("status") != "completed"
        or run_payload.get("conclusion") != "success"
        or run_payload.get("repository", {}).get("full_name") != SOURCE_REPOSITORY
        or run_payload.get("head_repository", {}).get("full_name") != SOURCE_REPOSITORY
    ):
        raise BoundaryError("source workflow run is not the exact green main-branch commit")
    jobs_payload = api_json(
        f"/repos/{SOURCE_REPOSITORY}/actions/runs/{run_id}/jobs?filter=latest&per_page=100", token
    )
    jobs = jobs_payload.get("jobs")
    expected_jobs = {
        "verify": ("completed", "success", commit),
        "device": ("completed", "success", commit),
    }
    actual_jobs = {
        item.get("name"): (item.get("status"), item.get("conclusion"), item.get("head_sha"))
        for item in jobs
        if isinstance(item, dict)
    } if isinstance(jobs, list) else {}
    if jobs_payload.get("total_count") != 2 or actual_jobs != expected_jobs:
        raise BoundaryError("source workflow jobs are not exactly green verify and device jobs")
    artifacts_payload = api_json(
        f"/repos/{SOURCE_REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100", token
    )
    artifacts = artifacts_payload.get("artifacts")
    if not isinstance(artifacts, list) or artifacts_payload.get("total_count") != 2:
        raise BoundaryError("source run artifact inventory differs")
    by_name = {item.get("name"): item for item in artifacts if isinstance(item, dict)}
    expected_names = {
        f"nytshift-android-unsigned-release-evidence-{commit}",
        f"nytshift-android-device-evidence-{commit}",
    }
    if set(by_name) != expected_names:
        raise BoundaryError("source run artifact names differ")
    for value in by_name.values():
        if (
            value.get("expired") is not False
            or not isinstance(value.get("id"), int)
            or value["id"] < 1
            or not SHA256_RE.fullmatch(str(value.get("digest", "")).removeprefix("sha256:"))
            or value.get("workflow_run", {}).get("id") != run_id
            or value.get("workflow_run", {}).get("head_branch") != SOURCE_BRANCH
            or value.get("workflow_run", {}).get("head_sha") != commit
            or value.get("url")
            != f"https://api.github.com/repos/{SOURCE_REPOSITORY}/actions/artifacts/{value['id']}"
            or value.get("archive_download_url")
            != f"https://api.github.com/repos/{SOURCE_REPOSITORY}/actions/artifacts/{value['id']}/zip"
        ):
            raise BoundaryError("source artifact provenance differs")
    return by_name[f"nytshift-android-unsigned-release-evidence-{commit}"], by_name[
        f"nytshift-android-device-evidence-{commit}"
    ]


def artifact_record(artifact: dict[str, Any], archive: Path, root: Path, manifest_name: str) -> dict[str, Any]:
    artifact_digest = str(artifact["digest"])
    archive_digest = digest(archive)
    if archive_digest != artifact_digest.removeprefix("sha256:"):
        raise BoundaryError("downloaded source artifact digest differs from GitHub metadata")
    manifest = read_json(root / manifest_name)
    return {
        "apiUrl": artifact["url"],
        "archiveDownloadUrl": artifact["archive_download_url"],
        "archiveSha256": archive_digest,
        "artifactDigest": artifact_digest,
        "checksumManifestSha256": digest(root / "SHA256SUMS"),
        "evidenceManifestSha256": digest(root / manifest_name),
        "id": artifact["id"],
        "name": artifact["name"],
        "packageInventoryCount": len(manifest["packageInventory"]),
    }


def main() -> None:
    token = os.environ["SOURCE_REPO_READ_TOKEN"]
    source_commit = os.environ["SOURCE_COMMIT"].lower()
    source_run_raw = os.environ["SOURCE_RUN_ID"]
    public_commit = os.environ["PUBLIC_COMMIT"].lower()
    public_run_raw = os.environ["PUBLIC_RUN_ID"]
    certificate = normalize_certificate(os.environ["EXPECTED_CERTIFICATE_SHA256"])
    key_owner = normalize_login(os.environ["KEY_OWNER_IDENTITY"])
    configured_reviewer = normalize_reviewer(os.environ["CONFIGURED_REVIEWER_IDENTITY"])
    if configured_reviewer == f"user:{key_owner}":
        raise BoundaryError("signing key owner and environment reviewer must be independent")
    if (
        not token
        or source_commit != SOURCE_COMMIT
        or not COMMIT_RE.fullmatch(public_commit)
    ):
        raise BoundaryError("token or commit input is missing/malformed")
    if not source_run_raw.isascii() or not source_run_raw.isdigit() or not public_run_raw.isdigit():
        raise BoundaryError("workflow run identity is malformed")
    source_run_id = int(source_run_raw)
    public_run_id = int(public_run_raw)
    if source_run_id not in range(1, 10**18) or public_run_id not in range(1, 10**18):
        raise BoundaryError("workflow run identity is out of range")
    workspace = Path(os.environ["BOUNDARY_ROOT"])
    if workspace.exists() or workspace.is_symlink():
        raise BoundaryError("signing boundary workspace must not pre-exist")
    workspace.mkdir(mode=0o700)
    release_archive = workspace / "release.zip"
    device_archive = workspace / "device.zip"
    release_root = workspace / "release"
    device_root = workspace / "device"
    handoff = Path(os.environ["HANDOFF_ROOT"])
    if handoff.exists() or handoff.is_symlink():
        raise BoundaryError("signing handoff target must not pre-exist")
    handoff.mkdir(mode=0o700)
    release_artifact, device_artifact = validate_source_run(token, source_commit, source_run_id)
    download_archive(release_artifact["archive_download_url"], token, release_archive)
    download_archive(device_artifact["archive_download_url"], token, device_archive)
    extract_archive(release_archive, release_root)
    extract_archive(device_archive, device_root)
    unsigned, build_config, version_name, version_code, release, device = validate_evidence(
        release_root, device_root, source_commit
    )
    apksigner = Path(os.environ["APKSIGNER"])
    apkanalyzer = Path(os.environ["APKANALYZER"])
    unsigned_check = run([str(apksigner), "verify", "--Werr", str(unsigned)])
    if unsigned_check.returncode == 0:
        raise BoundaryError("CI staging candidate is unexpectedly already signed")
    validate_manifest(decoded_manifest(apkanalyzer, unsigned), version_name, version_code)
    keystore = workspace / "staging-release.jks"
    try:
        key_bytes = base64.b64decode(os.environ["KEYSTORE_BASE64"], validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise BoundaryError("keystore secret is not strict base64") from error
    if len(key_bytes) not in range(1, 16 * 1024 * 1024 + 1):
        raise BoundaryError("keystore size is outside its bound")
    keystore.write_bytes(key_bytes)
    keystore.chmod(0o600)
    signed = handoff / "nytshift-staging-release-signed.apk"
    signing_env = os.environ.copy()
    for secret_not_needed_by_signer in ("SOURCE_REPO_READ_TOKEN", "KEYSTORE_BASE64", "KEY_ALIAS"):
        signing_env.pop(secret_not_needed_by_signer, None)
    signing = run(
        [
            str(apksigner),
            "sign",
            "--ks",
            str(keystore),
            "--ks-key-alias",
            os.environ["KEY_ALIAS"],
            "--ks-pass",
            "env:KEYSTORE_PASSWORD",
            "--key-pass",
            "env:KEY_PASSWORD",
            "--v1-signing-enabled",
            "false",
            "--v2-signing-enabled",
            "true",
            "--v3-signing-enabled",
            "true",
            "--v4-signing-enabled",
            "false",
            "--out",
            str(signed),
            str(unsigned),
        ],
        env=signing_env,
    )
    if signing.returncode != 0:
        raise BoundaryError("APK signing failed")
    actual_certificate = verify_signature(apksigner, signed, certificate)
    validate_manifest(decoded_manifest(apkanalyzer, signed), version_name, version_code)
    if zip_payload(unsigned) != zip_payload(signed):
        raise BoundaryError("signed APK payload differs from verified unsigned APK")
    unsigned_handoff = handoff / "app-staging-release-unsigned.apk"
    build_handoff = handoff / "stagingRelease-BuildConfig.java"
    release_summary = handoff / "release-evidence.json"
    device_summary = handoff / "device-evidence.json"
    toolchain_summary = handoff / "audited-sdk-inventory.json"
    shutil.copyfile(unsigned, unsigned_handoff)
    shutil.copyfile(build_config, build_handoff)
    shutil.copyfile(release_root / "release-evidence.json", release_summary)
    shutil.copyfile(device_root / "device-evidence.json", device_summary)
    shutil.copyfile(device_root / "toolchain/audited-sdk-inventory.json", toolchain_summary)
    release_record = artifact_record(
        release_artifact, release_archive, release_root, "release-evidence.json"
    )
    device_record = artifact_record(
        device_artifact, device_archive, device_root, "device-evidence.json"
    )
    inventory = sorted(
        [
            "SHA256SUMS",
            "app-staging-release-unsigned.apk",
            "audited-sdk-inventory.json",
            "device-evidence.json",
            "nytshift-staging-release-signed.apk",
            "release-evidence.json",
            "signing-handoff.json",
            "stagingRelease-BuildConfig.java",
        ]
    )
    manifest = {
        "candidate": {
            "authority": {
                "allowMainnet": False,
                "executionAuthority": "none",
                "executionEnabled": False,
            },
            "buildVariant": "stagingRelease",
            "channel": "PAPER",
            "debuggable": False,
            "packageName": PACKAGE,
            "signingKeyOwner": key_owner,
            "signedApk": {
                "bytes": signed.stat().st_size,
                "fileName": signed.name,
                "sha256": digest(signed),
            },
            "signingCertificateSha256": actual_certificate,
            "unsignedApk": {
                "bytes": unsigned_handoff.stat().st_size,
                "fileName": unsigned_handoff.name,
                "sha256": digest(unsigned_handoff),
            },
            "versionCode": version_code,
            "versionName": version_name,
        },
        "channel": "PAPER",
        "kind": "nytshift.android.paper-signing-handoff",
        "packageInventory": inventory,
        "publicPreparation": {
            "commitSha": public_commit,
            "commitUrl": f"https://github.com/{PUBLIC_REPOSITORY}/commit/{public_commit}",
            "repository": PUBLIC_REPOSITORY,
            "configuredEnvironmentReviewer": configured_reviewer,
            "signingKeyOwner": key_owner,
            "workflowRunId": public_run_id,
            "workflowRunUrl": f"https://github.com/{PUBLIC_REPOSITORY}/actions/runs/{public_run_id}",
        },
        "schemaVersion": "1",
        "source": {
            "branch": SOURCE_BRANCH,
            "commitSha": source_commit,
            "commitUrl": f"https://github.com/{SOURCE_REPOSITORY}/commit/{source_commit}",
            "event": "push",
            "repository": SOURCE_REPOSITORY,
            "runId": source_run_id,
            "runUrl": f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/{source_run_id}",
            "workflowName": SOURCE_WORKFLOW,
            "workflowPath": SOURCE_WORKFLOW_PATH,
        },
        "sourceArtifacts": {"device": device_record, "release": release_record},
    }
    (handoff / "signing-handoff.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    files = sorted(path for path in handoff.iterdir() if path.is_file())
    (handoff / "SHA256SUMS").write_text(
        "".join(f"{digest(path)} *{path.name}\n" for path in files),
        encoding="ascii",
        newline="\n",
    )
    actual_inventory = sorted(path.name for path in handoff.iterdir() if path.is_file())
    if actual_inventory != inventory or any(path.is_symlink() for path in handoff.iterdir()):
        raise BoundaryError("signing handoff allowlist differs")
    print(
        f"signing handoff staged: source={source_commit} run={source_run_id} "
        f"version={version_name} certificate={actual_certificate} reviewer={configured_reviewer}"
    )


if __name__ == "__main__":
    try:
        main()
    except (BoundaryError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"signing boundary rejected candidate: {error}")
