# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :---: |
| `1.x` (current `main`) | Yes |

## Reporting a Vulnerability

NOSIH is designed as a zero-trust orchestration kernel where cryptographic canonicalization (RFC 8785 JCS), signed tool manifests, Macaroon capability attenuation, atomic SQLite WAL replay protection, algebraic provenance semirings, and RFC 6962/9162 Merkle transparency logs serve as primary security boundaries.

If you discover a security vulnerability—such as a JCS parser differential, capability replay bypass, taint-lattice escape, linear monetary budget race, or semantic cache poisoning vector—please report it responsibly:

- **Contact:** G Praveenraj (`gpraveenraj03@gmail.com`)
- **Subject Line:** `[NOSIH Security] <Brief description>`
- **Please Include:**
  - A concise description of the vulnerability and affected component (Plane I, Plane II, or Plane III).
  - A minimal reproducible proof-of-concept or failing test case.
  - Suggested remediation or mitigation, if available.

### Response Timeline

- **Acknowledgment:** Within 48 hours of receipt.
- **Triage & Assessment:** Within 5 business days.
- **Fix & Disclosure:** Coordinated disclosure once a verified patch and regression test are merged.

Please do **not** open public GitHub issues for undisclosed security vulnerabilities.
