# LabRecorder component

The LabRecorder recording application with security-status support, vendored
into this monorepo as a component.

## Licensing

This component retains its upstream license (MIT, Copyright (c) 2012 Christian
Kothe); see `LICENSE` in this directory. The security integration added here is
contributed under that same MIT license. It reads stream security status through
the public LSL API and contains no cryptographic implementation, so the
proprietary Secure LSL terms do not apply to it. See COMPONENT LICENSING POLICY
in the repository-root `LICENSE`.

## Upstream tracking

- Upstream: https://github.com/labstreaminglayer/App-LabRecorder
- Based on upstream commit: `684df66`
- Security integration: security-status display for encrypted streams, version
  API information in the About dialog, and security-mismatch detection with
  actionable error dialogs

## Behavior against a stock liblsl

The security queries are optional. Linked against a stock `liblsl` that does not
export them, the application builds and runs as upstream does, without the
security indicators.
