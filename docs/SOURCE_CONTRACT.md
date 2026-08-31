# Private source and evidence contract

The signing boundary accepts one exact source:

- repository: `Nytshift/nytshift-android`;
- branch: `main`;
- event: `push`;
- workflow name/path: `android-ci` / `.github/workflows/ci.yml`;
- caller input: a 40-character commit and numeric run ID;
- run state: completed/success with the same `head_sha` and source repository;
- jobs: exactly successful `verify` and `device` jobs for that commit;
- artifacts: exactly the release and device evidence artifacts named with that commit.

The protected-environment `SOURCE_REPO_READ_TOKEN` uses GitHub’s Actions REST API to read the run/jobs/artifact metadata and download only those two artifact archives. It needs Actions: read on only the private source repository (plus unavoidable metadata read), never source contents or a write scope. Archive SHA-256, API URLs, artifact digests, evidence/checksum manifest SHA-256 values, artifact IDs/names, and inventory counts are retained in public provenance.

Both evidence archives must be regular-file-only, path-safe, bounded, fully checksum covered, and free of symlinks/duplicate paths. The signing job retains only this bounded non-secret handoff:

```text
SHA256SUMS
app-staging-release-unsigned.apk
audited-sdk-inventory.json
device-evidence.json
nytshift-staging-release-signed.apk
release-evidence.json
signing-handoff.json
stagingRelease-BuildConfig.java
```

Before handoff upload, the job deletes the private downloaded archives, full evidence trees, keystore, and executable boundary. A new runner rechecks the complete handoff inventory and checksums rather than trusting the artifact transport.

## Reviewed source correction

The contract records the corrected private validator as:

- commit `681a1329de80fb54996bce54d814ec425a721a4c`;
- path `stage_signed_preview_release.py`;
- SHA-256 `6ce828bbb2ff8203f73314397f3a7d4d727381f460c84b5551f3f9df45ce365a`.

The corresponding public boundary explicitly verifies the audited SDK inventory, rejects symlinks, passes `--Werr` to `apksigner`, decodes and validates the signed APK’s final manifest, emits source-run/evidence provenance, and returns the validated signer digest from the signature function. Static AST and functional tests guard the corrected return flow so the prior misplaced-return failure cannot recur silently.
