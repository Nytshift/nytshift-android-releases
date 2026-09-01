# Security model

## Trust boundaries

| Job | Checkout / repository code | Owner-managed secrets | GitHub permission | Security purpose |
| --- | --- | --- | --- | --- |
| `preflight` | Yes | Read-only policy token | `contents: read` | Verify exact public repo/main commit, immutable setting, and a main-only protected environment with one independent accountable reviewer. |
| `sign` | **No** | Source read token + owner-custodied staging key, released by environment reviewer | `{}` | Fetch the fixed private commit/run/artifacts, verify 338/39/46 evidence, sign one fail-closed APK, emit bounded non-secret handoff. |
| `verify-and-stage` | Yes, on a fresh runner | None; certificate fingerprint is a public repository variable | `contents: read` | Independently revalidate everything and create the exact public bundle. |
| `publish` | No | None | `contents: write` only | Publish the already verified five-file bundle via a draft. |
| `postpublish` | No | None | `contents: read` | Verify immutable release state and every published asset. |

Every job uses a fresh GitHub-hosted runner. Artifacts, not a shared workspace, cross boundaries. The signing job receives no GitHub token permission, performs no checkout, and cannot import the repository’s `tools/` directory. Its executable Python is embedded in the workflow, compressed only for transport, and checked against the reviewed public reference SHA-256 before execution.

## Fail-closed candidate

The candidate is accepted only when all layers agree on source commit `61f837f304b3942f65cb3d99f1a4236bcd420e41`, package `xyz.nytshift.app.staging`, variant `stagingRelease`, channel `PAPER`, non-debug status, execution disabled, mainnet disallowed, and authority `none`. Source evidence must report exactly 338 green JVM tests, 39 green API-36 Android tests, and 46 reviewed screenshot references. Source run `33493181731` must expose exactly two green jobs and three exact nonexpired artifact records; the test-only debug-signed record is validated as metadata but never downloaded, handed off, or published. The emulator SDK inventory must match the exact audited components/revisions and source-property hashes, and the BuildConfig constants must repeat the same authority.

The final signed APK is independently checked with pinned `aapt2`, `apkanalyzer`, and `apksigner`. The verifier requires the exact permission and exported-component allowlists, FileProvider authority, min/target SDK bounds, one expected signing certificate, v1 disabled, v2/v3 enabled, `--Werr`, and byte-identical ZIP payload entries between unsigned and signed APKs.

## Supply-chain pins

Action references use full reviewed commit SHAs. Each downloaded JDK, Android tool archive, extracted executable/script/JAR, and GitHub CLI archive/binary has a fixed SHA-256 in the workflow and static tests. Tool version labels are informational; hashes are the authority.

The source-side validator is recorded by exact private-source commit, path, and independently reviewed file SHA-256. The public no-checkout boundary independently enforces the fixed commit and 338/39/46 inventory, corrected signature-return behavior, symlink rejection, warning-as-error verification, audited toolchain checks, decoded final-manifest gate, and source/evidence provenance. Final metadata labels only the owner-key-signed APK as public, rejects unsigned public names/URLs and live authority, and requires immutable postpublication verification.

## Residual limitations

- No GitHub setting, reviewer, secret, variable, key custody control, ruleset, or immutable release setting can be proven from a local scaffold.
- The workflow and tests have not signed a real APK or executed on GitHub-hosted runners.
- GitHub-hosted runner images, API availability, environment availability, and artifact retention are external dependencies; preflight/tool checks fail rather than silently relaxing policy.
- A compromised required reviewer or staging key custodian can authorize misuse of the staging key. The key still must have no live trading, wallet, transfer, or production application authority.
- Immutable releases protect a release only after successful publication. A failed draft requires explicit inspection/remediation.
- Repository variables are intentionally public to workflows. The certificate fingerprint authenticates the expected public key; it is not key material.
