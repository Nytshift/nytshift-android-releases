# NYTSHIFT Android public releases

This repository is a minimal public release boundary for the NYTSHIFT Android **PAPER-only** staging APK. It intentionally contains no Android application source, Gradle project, signing key, keystore, private CI evidence, or checked-in APK.

The only admissible package is `xyz.nytshift.app.staging`, variant `stagingRelease`, channel `PAPER`. Its runtime authority must be exactly:

```json
{
  "executionEnabled": false,
  "allowMainnet": false,
  "executionAuthority": "none"
}
```

The manual workflow is designed as five fresh GitHub-hosted jobs:

1. A read-only preflight proves this is the exact public `main` revision and that immutable releases are enabled.
2. A required-reviewer environment releases the least-privilege private-source token and staging key to a zero-permission signing job. That job performs no checkout and materializes only a digest-pinned inline boundary.
3. A fresh job with no owner-managed secrets independently verifies source evidence, audited emulator tooling, package/runtime authority, unsigned-to-signed APK payload identity, decoded final manifest, and v2/v3 signature, then stages a five-file public bundle.
4. A fresh job with only `contents: write` publishes all five assets to a draft and then publishes the prerelease.
5. A fresh read-only job checks immutable state, public download metadata, `gh release verify`, and `gh release verify-asset` for every asset.

The private source contract is fixed to `Nytshift/nytshift-android`, branch `main`, workflow `android-ci`, and source commit `61f837f304b3942f65cb3d99f1a4236bcd420e41`. Both public verification layers require exactly 338 JVM tests, 39 Android tests, and 46 reviewed screenshot references. The reviewed source validator at that commit is `stage_signed_preview_release.py`, SHA-256 `7e1193b38d8588bbc9f7e2c1c5806008d4d18e3b3261deead27accdae53e4475`.

## Current setup status

The public repository now exists at [`Nytshift/nytshift-android-releases`](https://github.com/Nytshift/nytshift-android-releases), with `main` as its default branch. As of 2026-09-01, the owner has configured immutable releases, default read-only Actions permissions, SHA-pinned allowlisting for the three exact action revisions used here, and protected `main`: pull requests and the strict `repository-verify` check are required; linear history, administrator enforcement, and conversation resolution are enabled; force pushes and branch deletion are disabled.

Source commit `61f837f304b3942f65cb3d99f1a4236bcd420e41` now has completed/successful `android-ci` push run `33493181731` on source `main`, with exactly two green jobs (`verify` `99809214893` and `device` `99814660114`) and exactly three nonexpired artifacts. The public boundary validates metadata and provenance for all three, but returns and downloads only the unsigned release and device evidence artifacts; the explicitly named test-only debug-signed artifact is never handed off or published.

This is **not release-ready**. Branch protection currently requires zero approving reviews because no independent reviewer identity is known. The signing environment must have exactly one accountable user reviewer, prevent self-review, and admit only `main`; that reviewer must differ from the dispatcher and named signing-key owner. The environment secrets, `ANDROID_PREVIEW_KEY_OWNER`, independent certificate-fingerprint variable, read-only policy token, owner-key custody/recovery decisions, and first reviewed dispatch all remain blockers. No signing approval, workflow release run, APK, tag, or release is claimed.

The exact completed and blocked owner actions are tracked in [Owner setup](docs/OWNER_SETUP.md). See [Security model](docs/SECURITY_MODEL.md), [source contract](docs/SOURCE_CONTRACT.md), and [release process](docs/RELEASE_PROCESS.md) before using the workflow.

Local verification:

```text
python -B tools/verify_repository.py
python -B tools/secret_scan.py
python -B -m unittest discover -s tests -p "test_*.py" -v
```

Current GitHub and Android behavior is linked only to official documentation in [Official references](docs/OFFICIAL_REFERENCES.md).
