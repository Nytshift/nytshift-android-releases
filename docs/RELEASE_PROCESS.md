# PAPER preview release process

## Before dispatch

1. Confirm owner setup is complete and independently reviewed.
2. In the private source repository, confirm `61f837f304b3942f65cb3d99f1a4236bcd420e41` has completed/successful `android-ci` **push** run `33493181731` on `main`. Do not use a pull-request run, another SHA, or a manually assembled artifact. The run must have exactly two green jobs, exactly three nonexpired artifact metadata records, and prove 338 JVM tests, 39 Android tests, and 46 reviewed screenshot references. The public boundary must download only the unsigned release and device evidence artifacts, never the test-only debug-signed artifact.
3. Review the source commit, evidence/artifact availability, public release-repository commit, tool pins, and certificate fingerprint.
4. Start `android-paper-preview-release` from public `main` with the exact source commit/run and confirmation `PAPER xyz.nytshift.app.staging`.
5. The required environment reviewer compares the inputs and source run before approving the `sign` job. Approval is not evidence that the rest of the run passed.

## Automated acceptance

The workflow will fail unless the repository is public and immutable releases are enabled; the source run/jobs/artifacts are exact and green; the evidence/checksum/runtime authority/package/toolchain contracts match; signing and independent verification agree; the derived release tag does not already exist; and the final public bundle is exactly:

```text
SHA256SUMS
android-paper-preview.json
nytshift-staging-release.apk
provenance.json
release-notes.md
```

The tag is `android-paper-preview-v<VERSION>-staging`. Metadata records the stable public URL:

```text
https://github.com/Nytshift/nytshift-android-releases/releases/download/<TAG>/nytshift-staging-release.apk
```

Publishing creates a draft containing all five assets and then publishes it as a prerelease, allowing immutable-release validation to occur on the complete draft. The postpublish job checks `isImmutable`, tag/target state, local SHA-256 values, metadata URL, `gh release verify`, and `gh release verify-asset` for all five assets.

## Interpreting failures

Do not bypass a gate or substitute a new artifact into the same run. Fix the underlying source/repository/configuration issue and start a new reviewed dispatch. If a draft exists after a partial publisher failure, the owner must inspect it and explicitly decide whether to delete the draft before retrying. Never claim a release succeeded until the fresh postpublish job passes; inspect the immutable release and public APK URL directly as a separate owner check.

This workflow produces a public staging APK for deterministic PAPER behavior only. It does not publish to Google Play, grant live venue/wallet authority, or make a production release.
