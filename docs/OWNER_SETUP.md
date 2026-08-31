# Owner setup checklist

These are owner actions. This scaffold has not performed or approved any of them.

## 1. Create and harden the public repository

1. Create the **public** repository `Nytshift/nytshift-android-releases` with default branch `main`. Do not initialize it with unrelated files.
2. Push this locally reviewed commit in a separate, deliberate owner operation.
3. Set Actions workflow permissions to read repository contents by default. Do not grant blanket write access; the workflow declares its one `contents: write` publisher job.
4. Enable immutable releases before the first release. The workflow fails closed unless the repository API reports `enabled: true`. GitHub documents that enabling the feature affects future releases, so there must be no earlier production release to rely on.
5. Create a `main` ruleset or branch-protection rule that requires pull requests, the `repository-verify` status check, conversation resolution, blocks force pushes and deletion, and applies to administrators/bypass actors according to the owner’s governance policy. Add the owner’s actual team/handle as CODEOWNER in a later reviewed change; this scaffold does not invent an identity.
6. Limit allowed Actions to the pinned GitHub-authored actions used here, or an equivalent allowlist that admits their exact commit SHAs.

## 2. Create the protected signing environment

Create environment `android-paper-preview-signing` and configure:

- at least one independent required reviewer;
- “prevent self-review” where available;
- deployment branch/tag restriction admitting only `main` for this workflow;
- no custom deployment app that can silently bypass the human gate.

Add these **environment secrets**, not repository secrets:

| Name | Owner-supplied value |
| --- | --- |
| `SOURCE_REPO_READ_TOKEN` | Fine-grained token limited to `Nytshift/nytshift-android`, with Actions: read and only the unavoidable metadata read. No source contents or write permission. Use a short expiry and rotate it. |
| `ANDROID_PREVIEW_KEYSTORE_BASE64` | Strict base64 of the dedicated staging/PAPER keystore. |
| `ANDROID_PREVIEW_KEYSTORE_PASSWORD` | Keystore password. |
| `ANDROID_PREVIEW_KEY_ALIAS` | Dedicated staging key alias. |
| `ANDROID_PREVIEW_KEY_PASSWORD` | Key password. |

The source token principal must have access to the private source repository. Confirm its repository selection and permission screen after creation; do not reuse a broad personal token.

## 3. Configure independent public checks

Add repository variable `ANDROID_PREVIEW_CERTIFICATE_SHA256` containing the normalized SHA-256 fingerprint of the dedicated staging signing certificate. Obtain and cross-check it through the key custodian’s offline process; it must not be derived from an unreviewed workflow output.

Add repository secret `RELEASE_POLICY_READ_TOKEN`: a fine-grained, short-lived/rotated token limited to `Nytshift/nytshift-android-releases` with **Administration: read** and metadata read, and no write permission. It exists only because the immutable-release settings endpoint requires repository Administration read. The preflight job is otherwise read-only and never forwards this token.

## 4. Custody and recovery decisions the owner must record

- Name the staging key custodian and required reviewer(s).
- Record the offline encrypted backup location, recovery test date, rotation/retirement process, and certificate fingerprint out of band.
- Confirm this staging key is not a production wallet, venue credential, mainnet authority, Play App Signing production key, or another app’s key.
- Define incident steps: stop approvals; revoke the source/policy tokens; remove environment secrets; rotate the staging key/certificate variable; investigate all affected run IDs and immutable releases.
- Define draft recovery: if asset upload succeeds but draft publication fails, inspect the exact draft. Delete it only through an explicit owner decision before a clean retry; published immutable releases are not a retry surface.

## 5. Final dry review before any dispatch

Review the commit diff, action/tool checksum provenance, environment settings, ruleset, token permission screens, certificate fingerprint, and source run. A required reviewer should reject a dispatch whose commit/run or confirmation differs. This scaffold contains no evidence that these controls have been configured.
