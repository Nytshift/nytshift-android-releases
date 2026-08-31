# Security policy

Do not report a signing key, token, password, private artifact, or sensitive log in a public issue. Contact the NYTSHIFT repository owner through an established private security channel. Revoke or rotate an exposed credential before investigating downstream effects.

This repository must never accept:

- Android app or Gradle source;
- an APK, AAB, keystore, private key, certificate file, token, or password;
- private source evidence outside the bounded ephemeral signing handoff;
- a non-PAPER package, a package other than `xyz.nytshift.app.staging`, or enabled execution/mainnet authority;
- an unpinned action, downloaded executable, or executable archive;
- a release workflow change that combines signing secrets with checkout/repository code or with `contents: write`.

Security changes require review of the workflow permissions, environment boundary, executable checksums, certificate fingerprint, source evidence schema, decoded APK manifest allowlist, and immutable postpublication verification. Run all repository tests and the deterministic secret scan before review.
