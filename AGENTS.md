# Repository boundary

This is a public, release-only boundary. Never add Android application source, Gradle files, APKs, signing keys, keystores, credentials, private evidence, or generated release bundles to Git.

Preserve the five fresh-job trust split in `.github/workflows/publish-paper-preview.yml`: read-only preflight; protected-environment signing with no checkout and no GitHub token permissions; secret-free verification/staging; contents-only publication; fresh public postpublication verification. Never let the signing job execute repository code or let the publishing job receive owner-managed secrets.

All action revisions and executable archives/binaries must remain pinned by reviewed SHA-256/full commit. Updating a version label without independently verifying its digest is forbidden. The fixed candidate is `PAPER`, `stagingRelease`, package `xyz.nytshift.app.staging`, with all execution authority disabled.

Before committing, run `python -B tools/verify_repository.py`, `python -B tools/secret_scan.py`, and `python -B -m unittest discover -s tests -p 'test_*.py' -v`. Do not push, publish, create a remote, add a remote, or claim a live approval unless the repository owner explicitly requests and performs that separate operation.
