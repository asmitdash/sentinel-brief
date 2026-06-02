# DRY RUN

Watchlist: Demo stack
Date: 2026-06-02

The following findings were matched against the watchlist over the last 7 days, sorted by score. Each finding lists: component, advisory, severity, score breakdown, and references.

---
[1] pkg:pypi/urllib3@1.24.0  (score 0.370, matched_via version_in_range)
  Advisory: urllib3 streaming API improperly handles highly compressed data  (CVE-2025-66471 / GHSA-2xpw-w6gg-jr37)
  Severity: HIGH  CVSS: ?  KEV: no  EPSS: -
  Score breakdown: severity=0.22, match=0.15, kev=0.0, epss=0.0, recency=0.0
  Affected: PyPI/urllib3 fixed in 2.6.0
  Summary: ### Impact

urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.5.0/advanced-usage.html#streaming-and-i-o) is designed for the efficient handling of large HTTP responses by reading the content in chunks, rather than loading the entire response body into memory at once.

When streaming a compressed response, urllib3 can perform decoding or decompression based on the HTTP `Content-Encoding` header (e.g., `gzip`, `deflate`, `br`, or `zstd`). The library must read compressed data from the network and decompress it until the requested chunk size is met. Any resulting decompressed data tha
  References:
  - https://github.com/urllib3/urllib3/security/advisories/GHSA-2xpw-w6gg-jr37 (WEB)
  - https://nvd.nist.gov/vuln/detail/CVE-2025-66471 (ADVISORY)
  - https://github.com/urllib3/urllib3/commit/c19571de34c47de3a766541b041637ba5f716ed7 (WEB)
  - https://github.com/urllib3/urllib3 (PACKAGE)

---
[2] pkg:pypi/urllib3@1.24.0  (score 0.370, matched_via version_in_range)
  Advisory: urllib3 allows an unbounded number of links in the decompression chain  (CVE-2025-66418 / GHSA-gm62-xv2j-4w53)
  Severity: HIGH  CVSS: ?  KEV: no  EPSS: -
  Score breakdown: severity=0.22, match=0.15, kev=0.0, epss=0.0, recency=0.0
  Affected: PyPI/urllib3 fixed in 2.6.0
  Summary: ## Impact

urllib3 supports chained HTTP encoding algorithms for response content according to RFC 9110 (e.g., `Content-Encoding: gzip, zstd`).

However, the number of links in the decompression chain was unbounded allowing a malicious server to insert a virtually unlimited number of compression steps leading to high CPU usage and massive memory allocation for the decompressed data.


## Affected usages

Applications and libraries using urllib3 version 2.5.0 and earlier for HTTP requests to untrusted sources unless they disable content decoding explicitly.


## Remediation

Upgrade to at least
  References:
  - https://github.com/urllib3/urllib3/security/advisories/GHSA-gm62-xv2j-4w53 (WEB)
  - https://nvd.nist.gov/vuln/detail/CVE-2025-66418 (ADVISORY)
  - https://github.com/urllib3/urllib3/commit/24d7b67eac89f94e11003424bcf0d8f7b72222a8 (WEB)
  - https://github.com/urllib3/urllib3 (PACKAGE)

---
[3] pkg:pypi/cryptography@2.5  (score 0.370, matched_via version_in_range)
  Advisory: cryptography Vulnerable to a Subgroup Attack Due to Missing Subgroup Validation for SECT Curves  (CVE-2026-26007 / GHSA-r6ph-v2qm-q3c2)
  Severity: HIGH  CVSS: ?  KEV: no  EPSS: -
  Score breakdown: severity=0.22, match=0.15, kev=0.0, epss=0.0, recency=0.0
  Affected: PyPI/cryptography fixed in 46.0.5
  Summary: ## Vulnerability Summary

The `public_key_from_numbers` (or `EllipticCurvePublicNumbers.public_key()`), `EllipticCurvePublicNumbers.public_key()`, `load_der_public_key()` and `load_pem_public_key()` functions do not verify that the point belongs to the expected prime-order subgroup of the curve.

This missing validation allows an attacker to provide a public key point `P` from a small-order subgroup.  This can lead to security issues in various situations, such as the most commonly used signature verification (ECDSA) and shared key negotiation (ECDH). When the victim computes the shared secret
  References:
  - https://github.com/pyca/cryptography/security/advisories/GHSA-r6ph-v2qm-q3c2 (WEB)
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26007 (ADVISORY)
  - https://github.com/pyca/cryptography/commit/0eebb9dbb6343d9bc1d91e5a2482ed4e054a6d8c (WEB)
  - https://github.com/pyca/cryptography (PACKAGE)
  - https://github.com/pyca/cryptography/releases/tag/46.0.5 (WEB)
  - http://www.openwall.com/lists/oss-security/2026/02/10/4 (WEB)

---
[4] pkg:pypi/pillow@6.0.0  (score 0.259, matched_via version_in_range)
  Advisory: Pillow has an integer overflow when processing fonts  (CVE-2026-42308 / GHSA-wjx4-4jcj-g98j)
  Severity: ?  CVSS: ?  KEV: no  EPSS: -
  Score breakdown: severity=0.0, match=0.15, kev=0.0, epss=0.0, recency=0.1093
  Affected: PyPI/pillow fixed in 12.2.0
  Summary: If a font advances for each glyph by an exceeding large amount, when Pillow keeps track of the current position, it may lead to an integer overflow. This has been fixed.
  References:
  - https://github.com/python-pillow/Pillow/security/advisories/GHSA-wjx4-4jcj-g98j (WEB)
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42308 (ADVISORY)
  - https://github.com/python-pillow/Pillow (PACKAGE)
  - https://github.com/python-pillow/Pillow/releases/tag/12.2.0 (WEB)

---
[5] pkg:pypi/pillow@6.0.0  (score 0.259, matched_via version_in_range)
  Advisory: PYSEC-2026-165  (CVE-2026-42308 / GHSA-wjx4-4jcj-g98j / PYSEC-2026-165)
  Severity: ?  CVSS: ?  KEV: no  EPSS: -
  Score breakdown: severity=0.0, match=0.15, kev=0.0, epss=0.0, recency=0.1093
  Affected: PyPI/pillow fixed in 12.2.0
  Summary: Pillow is a Python imaging library. Prior to version 12.2.0, if a font advances for each glyph by an exceeding large amount, when Pillow keeps track of the current position, it may lead to an integer overflow. This issue has been patched in version 12.2.0.
  References:
  - https://github.com/python-pillow/Pillow/releases/tag/12.2.0 (ADVISORY)
  - https://github.com/python-pillow/Pillow/security/advisories/GHSA-wjx4-4jcj-g98j (ADVISORY)

---
[6] pkg:pypi/flask@1.0.0  (score 0.200, matched_via version_in_range)
  Advisory: Flask session does not add `Vary: Cookie` header when accessed in some ways  (CVE-2026-27205 / GHSA-68rp-wp8r-4726)
  Severity: LOW  CVSS: ?  KEV: no  EPSS: -
  Score breakdown: severity=0.05, match=0.15, kev=0.0, epss=0.0, recency=0.0
  Affected: PyPI/flask fixed in 3.1.3
  Summary: When the `session` object is accessed, Flask should set the `Vary: Cookie` header. This instructs caches not to cache the response, as it may contain information specific to a logged in user. This is handled in most cases, but some forms of access such as the Python `in` operator were overlooked.

The severity depends on the application's use of the session, and the cache's behavior regarding cookies. The risk depends on all these conditions being met.

1. The application must be hosted behind a caching proxy that does not ignore responses with cookies.
2. The application does not set a `Cache
  References:
  - https://github.com/pallets/flask/security/advisories/GHSA-68rp-wp8r-4726 (WEB)
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27205 (ADVISORY)
  - https://github.com/pallets/flask/commit/089cb86dd22bff589a4eafb7ab8e42dc357623b4 (WEB)
  - https://github.com/pallets/flask (PACKAGE)
  - https://github.com/pallets/flask/releases/tag/3.1.3 (WEB)


Write the brief now per the system instructions. Cite inline. Do not list findings I did not give you.
