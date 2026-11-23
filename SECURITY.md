# Security Policy

## Reporting a vulnerability

Email **security@0xkey.io**. Do not open a public issue, pull request or discussion for a suspected
vulnerability. Once this repository's GitHub private vulnerability reporting is available ("Report a
vulnerability" on the Security tab), you can use it instead.

Please include:

- the SDK and version (for example `0.1.0`), platform and OS version, and device model if relevant;
- what an attacker can do and what they need (network position, a compromised app process, physical
  access, and so on);
- steps or a minimal project that reproduces it.

Do not include real credentials, private keys, session JWTs or user data. Use a test organization.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 2 business days |
| Initial assessment (confirmed or not, severity) | within 5 business days |
| Fix for critical and high severity | released within 30 days of confirmation |
| Fix for medium and low severity | in a scheduled release |

We keep you informed until the issue is resolved and agree the disclosure date with you. We publish a
GitHub security advisory and a CHANGELOG entry when the fix is released, and credit you unless you ask
us not to. Please give us 90 days, or until a fix is released if that is sooner, before disclosing
publicly. We do not take legal action against good-faith research that follows this policy.

## Scope

In scope: the code in this repository and the artifacts built from it, including session key handling,
request stamping, signature and bundle verification, transport security, and session storage.

Out of scope here (report to the same address, but they are not issues in this SDK): the 0xkey API,
Auth Proxy and Dashboard; vulnerabilities in the operating system or third-party dependencies (report to
their maintainers; tell us if the SDK needs a change); attacks that need a rooted or jailbroken device or
a debugger attached to the app, unless the SDK claims to defend against them; denial of service by
volume; findings from automated scanners without a demonstrated impact.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

Security fixes go into the latest release. While the major version is 0, older minor versions do not
receive fixes; upgrade to the latest release.

## Security defaults

The SDK accepts only `https` endpoints by default, and verifies OTP
encryption target bundles and session JWTs against built-in 0xkey production keys. Relaxing either is
an explicit, `dangerously`-named configuration option. Details: README, "Configure", and the
"Security" section of the 0.1.0 entry in CHANGELOG.md.
