# Private source and evidence contract

The signing boundary accepts one exact source:

- repository: `Nytshift/nytshift-android`;
- branch: `main`;
- event: `push`;
- workflow name/path: `android-ci` / `.github/workflows/ci.yml`;
- caller input: fixed commit `61f837f304b3942f65cb3d99f1a4236bcd420e41` and run ID `33493181731`;
- run state: completed/success with the same `head_sha` and source repository;
- jobs: exactly successful `verify` and `device` jobs for that commit;
- artifacts: exactly the unsigned release evidence, device evidence, and explicitly named test-only debug-signed artifacts for that commit;
- evidence inventory: exactly 338 successful JVM tests, 39 successful API-36 Android tests, and 46 reviewed screenshot references.

The protected-environment `SOURCE_REPO_READ_TOKEN` uses GitHub’s Actions REST API to read the run/jobs/artifact metadata and validate all three artifact records. It downloads and forwards only the unsigned release evidence and device evidence archives. The artifact named `nytshift-PAPER-TEST-ONLY-DEBUG-SIGNED-NOT-PLAY-OR-PRODUCTION-NO-LIVE-CAPITAL-61f837f304b3942f65cb3d99f1a4236bcd420e41` is metadata-only at this boundary and cannot enter the signing handoff, public bundle, or release. The token needs Actions: read on only the private source repository (plus unavoidable metadata read), never source contents or a write scope. Archive SHA-256, API URLs, artifact digests, evidence/checksum manifest SHA-256 values, artifact IDs/names, and inventory counts for the two admissible evidence archives are retained in public provenance.

The exact observed source-run evidence is:

- jobs: `verify` ID `99809214893` and `device` ID `99814660114`, both completed/success;
- device evidence: artifact ID `9795726655`, digest `sha256:ab9fb3d572fb50697a9f8bfbf233db82774bcdf2784bd92b4272274c12f4e361`;
- unsigned release evidence: artifact ID `9795265308`, digest `sha256:34d5d0505d0db5351c518afbbafe102da15e29c1496727cfabaff6b7c8fc550e`;
- test-only debug-signed metadata: artifact ID `9795263332`, digest `sha256:cd3bebf07b4d70268e119d3d93d89cbb6d1c500a3b7bd064d02390b168348dc3`.

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

- commit `61f837f304b3942f65cb3d99f1a4236bcd420e41`;
- path `stage_signed_preview_release.py`;
- SHA-256 `7e1193b38d8588bbc9f7e2c1c5806008d4d18e3b3261deead27accdae53e4475`.

The corresponding public boundary explicitly verifies the 338/39/46 evidence inventory, audited SDK inventory, complete checksum packages, artifact/archive/evidence hashes, exact source run and URLs, owner-key/reviewer accountability, and unsigned-to-signed payload identity. It rejects symlinks, passes `--Werr` to `apksigner`, decodes and validates both APK manifests, emits source-run/evidence provenance, and returns the validated signer digest. Static and functional tests guard these contracts.
