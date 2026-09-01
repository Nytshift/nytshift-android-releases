# Private source and evidence contract

The signing boundary accepts one exact source:

- repository: `Nytshift/nytshift-android`;
- branch: `main`;
- event: `push`;
- workflow name/path: `android-ci` / `.github/workflows/ci.yml`;
- caller input: fixed commit `c2a95bebb772d7d76db33df864de41fb231ff14c` and a numeric run ID;
- run state: completed/success with the same `head_sha` and source repository;
- jobs: exactly successful `verify` and `device` jobs for that commit;
- artifacts: exactly the release and device evidence artifacts named with that commit.
- evidence inventory: exactly 338 successful JVM tests, 39 successful API-36 Android tests, and 46 reviewed screenshot references.

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

- commit `c2a95bebb772d7d76db33df864de41fb231ff14c`;
- path `stage_signed_preview_release.py`;
- SHA-256 `7e1193b38d8588bbc9f7e2c1c5806008d4d18e3b3261deead27accdae53e4475`.

The corresponding public boundary explicitly verifies the 338/39/46 evidence inventory, audited SDK inventory, complete checksum packages, artifact/archive/evidence hashes, exact source run and URLs, owner-key/reviewer accountability, and unsigned-to-signed payload identity. It rejects symlinks, passes `--Werr` to `apksigner`, decodes and validates both APK manifests, emits source-run/evidence provenance, and returns the validated signer digest. Static and functional tests guard these contracts.
