# Daily Brief — 2026-06-02 — Demo stack

## Top priorities

1. **urllib3 1.24.0** has two HIGH severity issues affecting streaming API and decompression handling, both fixed in 2.6.0:
   - Improper handling of highly compressed data ([CVE-2025-66471](https://nvd.nist.gov/vuln/detail/CVE-2025-66471))
   - Unbounded decompression chain allowing DoS ([CVE-2025-66418](https://nvd.nist.gov/vuln/detail/CVE-2025-66418))

2. **cryptography 2.5** contains a HIGH severity subgroup validation flaw for SECT curves that could impact ECDSA/ECDH operations ([CVE-2026-26007](https://nvd.nist.gov/vuln/detail/CVE-2026-26007)). Fixed in 46.0.5.

## Other notable

- Pillow 6.0.0 has an integer overflow in font processing ([CVE-2026-42308](https://nvd.nist.gov/vuln/detail/CVE-2026-42308)), fixed in 12.2.0. Severity unspecified.

## Notes

- Severity ratings lack CVSS scores and EPSS data, reducing confidence in precise risk ranking
- Pillow finding appears twice in source data but represents same issue

## What I'd do today

1. urllib3: Upgrade to 2.6.0+ immediately if processing compressed content from untrusted sources
2. cryptography: Plan upgrade to 46.0.5+ if using SECT curves for ECDSA/ECDH operations