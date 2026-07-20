# SigVisualizer component

The SigVisualizer signal-display application with security-status support,
vendored into this monorepo as a component.

## Licensing (GPLv3, unlike the MIT components)

Upstream SigVisualizer is licensed under the GNU General Public License v3.0.
This component therefore remains GPLv3; see `LICENSE` in this directory. Because
GPLv3 is copyleft, the security integration added here is also GPLv3, and it
could not be relicensed under proprietary terms even though it contains no
cryptography (it reads stream security status through the public LSL API).

This is a deliberate departure from the pylsl and LabRecorder components, whose
upstreams are MIT. The component sits in this repository as an aggregate under
GPLv3 section 5; the proprietary Secure LSL license does not extend to it. See
COMPONENT LICENSING POLICY in the repository-root `LICENSE`.

## Note for review

SigVisualizer imports the in-repo `pylsl` component and, at the user's runtime,
loads `liblsl-secure` (proprietary) through `ctypes`. Whether distributing a
GPLv3 application alongside a proprietary library it loads at runtime creates
any obligation is a question for UCSD OIC rather than one resolved here; it is
the same question that already applies to the drop-in library-replacement route.
Co-location itself is mere aggregation under GPLv3 section 5.

## Upstream tracking

- Upstream: https://github.com/labstreaminglayer/App-SigVisualizer
- Based on upstream commit: `aa754e6`
- Security integration: `lsl_security_helper.py` (a pylsl compatibility shim),
  security-status display in `paintwidget.py`, and mismatch detection

## Behavior against a stock liblsl

The security queries are optional. Against a stock `liblsl` that does not export
them, the helper reports security unavailable and the application runs as
upstream does.
