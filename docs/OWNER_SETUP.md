# Owner setup checklist

Status recorded 2026-08-31. Checked items are limited to settings that the owner configured on the public repository and that were read back through GitHub. Unchecked items remain blockers; this status does not claim an environment approval, secret, signing operation, APK, tag, or release.

**Current decision: NO-GO for dispatch.** No independent signing reviewer identity is known, so the protected signing environment must not be created yet.

## 1. Create and harden the public repository

- [x] Create public repository `Nytshift/nytshift-android-releases`, set default branch `main`, and push the reviewed scaffold.
- [x] Enable immutable releases. The repository API reports `enabled: true`; the workflow still rechecks this before every release.
- [x] Set default Actions workflow permissions to read. GitHub Actions cannot approve pull-request reviews, and the workflow declares its one bounded `contents: write` publisher job.
- [x] Require SHA-pinned allowed actions and allow only these exact revisions:
  - `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`
  - `actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53`
  - `actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f`
- [x] Protect `main`: pull requests required; `repository-verify` required in strict mode; linear history, administrator enforcement, stale-review dismissal, and conversation resolution enabled; force pushes and deletion disabled.
- [ ] Identify the owner’s actual CODEOWNER team/handle and add it in a reviewed change. Do not invent an identity. Branch protection currently requires **zero approving reviews** because no independent reviewer identity is known.

## 2. Create the protected signing environment

**Blocked: do not create this environment until one independent, accountable GitHub user reviewer identity is known.** After that identity is confirmed, create environment `android-paper-preview-signing` and configure:

- exactly one independent required user reviewer, different from the dispatcher and signing-key owner;
- “prevent self-review” where available;
- deployment branch/tag restriction admitting only `main` for this workflow;
- no custom deployment app that can silently bypass the human gate.

All environment controls and secrets below remain incomplete:

- [ ] Add exactly one independent required user reviewer and record the identity in the owner’s audit record.
- [ ] Enable “prevent self-review” where available.
- [ ] Restrict deployment to `main` for this workflow.
- [ ] Confirm no custom deployment app can silently bypass the human gate.

Only after those gates exist, add these **environment secrets**, not repository secrets:

| Status | Name | Owner-supplied value |
| --- | --- | --- |
| Blocked / absent | `SOURCE_REPO_READ_TOKEN` | Fine-grained token limited to `Nytshift/nytshift-android`, with Actions: read and only the unavoidable metadata read. No source contents or write permission. Use a short expiry and rotate it. |
| Blocked / absent | `ANDROID_PREVIEW_KEYSTORE_BASE64` | Strict base64 of the dedicated staging/PAPER keystore. |
| Blocked / absent | `ANDROID_PREVIEW_KEYSTORE_PASSWORD` | Keystore password. |
| Blocked / absent | `ANDROID_PREVIEW_KEY_ALIAS` | Dedicated staging key alias. |
| Blocked / absent | `ANDROID_PREVIEW_KEY_PASSWORD` | Key password. |

The source token principal must have access to the private source repository. Confirm its repository selection and permission screen after creation; do not reuse a broad personal token.

## 3. Configure independent public checks

- [ ] Add repository variable `ANDROID_PREVIEW_KEY_OWNER` containing the accountable GitHub login of the staging-key owner/custodian. It must differ from the configured environment reviewer. This remains absent.

- [ ] Add repository variable `ANDROID_PREVIEW_CERTIFICATE_SHA256` containing the normalized SHA-256 fingerprint of the dedicated staging signing certificate. This remains absent. Obtain and cross-check it through the key custodian’s offline process; it must not be derived from an unreviewed workflow output.

- [ ] Add repository secret `RELEASE_POLICY_READ_TOKEN`: a fine-grained, short-lived/rotated token limited to `Nytshift/nytshift-android-releases` with **Administration: read** and metadata read, and no write permission. This remains absent. It exists only because the immutable-release settings endpoint requires repository Administration read. The preflight job is otherwise read-only and never forwards this token.

## 4. Custody and recovery decisions the owner must record

- [ ] Name the independent required reviewer and staging key custodian.
- [ ] Record the offline encrypted backup location, recovery test date, rotation/retirement process, and certificate fingerprint out of band.
- [ ] Confirm this staging key is not a production wallet, venue credential, mainnet authority, Play App Signing production key, or another app’s key.
- [ ] Define incident steps: stop approvals; revoke the source/policy tokens; remove environment secrets; rotate the staging key/certificate variable; investigate all affected run IDs and immutable releases.
- [ ] Define draft recovery: if asset upload succeeds but draft publication fails, inspect the exact draft. Delete it only through an explicit owner decision before a clean retry; published immutable releases are not a retry surface.

## 5. Final dry review before any dispatch

- [ ] Confirm commit `61f837f304b3942f65cb3d99f1a4236bcd420e41` is on source `main` and review completed/successful `android-ci` push run `33493181731`: exactly two green jobs (`verify` `99809214893`, `device` `99814660114`), exactly three nonexpired artifact metadata records, and inventories 338 JVM / 39 AndroidTest / 46 reviewed screenshots. Confirm that only the unsigned release and device evidence artifacts may cross the signing boundary.
- [ ] Review the commit diff, action/tool checksum provenance, environment settings, protection rule, token permission screens, certificate fingerprint, and exact source run.
- [ ] Have the independent environment reviewer reject any dispatch whose commit/run or confirmation differs.
- [ ] Dispatch only after every unchecked blocker above is complete, using an exact successful source `main` commit/run and confirmation `PAPER xyz.nytshift.app.staging`.

No release workflow has been dispatched, and no signing, APK publication, tag, or release has occurred as part of this status update.
