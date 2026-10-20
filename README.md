# Hello World iOS (isolated test project)

Minimal SwiftUI Hello World app for Mission 02 (unsigned cloud build through
ios-builder v0.11.0 / GitHub Actions).

## Project

- `HelloWorld.xcodeproj` — native Xcode project (objectVersion 56).
- `HelloWorld.xcodeproj/xcshareddata/xcschemes/HelloWorld.xcscheme` — shared scheme.
- `HelloWorldApp.swift` — SwiftUI `@main` entry point.
- `ContentView.swift` — single "Hello, World!" view.
- `builder.json` — ios-builder config: GitHub, scheme `HelloWorld`,
  bundle id `com.example.helloworld`, Debug, unsigned.
- `.github/workflows/ios-build.yml` — workflow_dispatch only, macOS standard
  runner, 30-minute timeout, 3-day artifact retention, `contents: read`.
- `scripts/secret-protection-gate.sh` — fail-closed GitHub Secret Protection Gate.
- `scripts/verify-artifact.py` — unsigned IPA structural validator (no Xcode needed).

No Apple certificates, provisioning profiles, App Store Connect keys, or
repository secrets are required.

## Build

```
builder ios build --unsigned --output dist
```

The CLI snapshots the working tree (tracked + untracked, excluding `.gitignore`),
pushes it to `refs/ios-builder/jobs/<id>`, dispatches the workflow, then downloads
the `ipa` artifact to `dist/`.

## Security gate (mandatory before commit/push/dispatch)

```
scripts/secret-protection-gate.sh
```

Scans the exact snapshot payload, the working tree (including ignored files),
all git history and workflow YAML with gitleaks. Any finding, incomplete scan or
uncertain result exits non-zero. Evidence is written outside the repository with
redacted findings only.

## Artifact validation

```
scripts/verify-artifact.py dist/HelloWorld-<build-id>.ipa
```

## Status

See `/home/msyah/ios-builder-lab/mission-02-report.md` for the current verified
state. An unsigned IPA is a compilation artifact, not an installable/signed app.
