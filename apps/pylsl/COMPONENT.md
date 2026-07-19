# pylsl component

Security-enabled Python binding for Lab Streaming Layer, vendored into this
monorepo as a component.

## Licensing

This component retains its upstream license (MIT, Copyright (c) 2012-2018
Christian A. Kothe); see `LICENSE` in this directory. The security integration
added here is contributed under that same MIT license. It consists of `ctypes`
interface declarations and two stream properties that call the public liblsl C
API, and contains no cryptographic implementation, so the proprietary Secure LSL
terms do not apply to it. See COMPONENT LICENSING POLICY in the repository-root
`LICENSE`.

## Upstream tracking

- Upstream: https://github.com/labstreaminglayer/pylsl
- Based on upstream commit: `c90f623`
- Security integration: interface declarations plus `StreamInfo.security_enabled`
  and `StreamInfo.security_fingerprint`

## Graceful degradation

The security symbols are resolved inside `try`/`except AttributeError` and
recorded in `_security_api_available` / `_stream_security_api_available`. Linked
against a stock `liblsl` that does not export them, the binding imports and
behaves exactly as upstream; the security properties simply report unavailable.
