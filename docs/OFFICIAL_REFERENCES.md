# Official references

Changing platform behavior in this design was checked against official documentation:

- [GitHub deployment environments, secrets, and required reviewers](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [Managing environments for deployment](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
- [Prevent release changes with immutable releases](https://docs.github.com/en/enterprise-cloud@latest/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes)
- [Immutable releases security model](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
- [Verify release integrity](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/verify-release-integrity)
- [`gh release verify` manual](https://cli.github.com/manual/gh_release_verify)
- [`gh release verify-asset` manual](https://cli.github.com/manual/gh_release_verify-asset)
- [GitHub repository REST endpoints, including immutable-release configuration](https://docs.github.com/en/enterprise-cloud@latest/rest/repos/repos?apiVersion=2026-03-10)
- [GitHub Actions artifact REST API and fine-grained token permissions](https://docs.github.com/en/rest/actions/artifacts?apiVersion=2022-11-28)
- [GitHub repository rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [Managing branch-protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule)
- [Android `apksigner`](https://developer.android.com/tools/apksigner)
- [Microsoft Build of OpenJDK downloads](https://learn.microsoft.com/en-us/java/openjdk/download)

These links do not prove that the future public repository has been configured. The owner must re-check plan availability, permissions, API versions, and immutable-release behavior when setting it up.
