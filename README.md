# NYTSHIFT Android releases

This public repository is the release home for the NYTSHIFT Android app. It holds the release workflow, the policy it follows and the checks that go with them.

No public build has been published yet. There are no releases, tags or APK files here, and the workflow has never been run.

To use NYTSHIFT on a phone today, open [nytshift.xyz/terminal](https://nytshift.xyz/terminal) in your phone's browser.

If someone offers you a NYTSHIFT APK, it didn't come from this repository. Please don't install it.

## What's here

This repository holds no app source code, Gradle project, signing key, keystore or APK, and the checks refuse them. The workflow is locked to one fixed test package that has live trading switched off, and it isn't set up to publish anything else. Nothing in this repository can place an order.

## Checking this repository

These are the same checks the repository runs on every change:

```text
python -B tools/verify_repository.py
python -B tools/secret_scan.py
python -B -m unittest discover -s tests -p "test_*.py" -v
```

## More detail

- [Security model](docs/SECURITY_MODEL.md)
- [Release process](docs/RELEASE_PROCESS.md)
- [Owner setup](docs/OWNER_SETUP.md), which lists what's still needed before a first release
- [Security policy](SECURITY.md)
