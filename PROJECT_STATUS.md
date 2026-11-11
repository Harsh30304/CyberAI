# Project status

## Implemented in the current prototype

- SSH connection to the Ubuntu lab scanner VM
- Remote Nmap service/version scan and XML parsing
- NVD API lookups and CVE/CPE candidate extraction
- Product identity mapping for a limited set of software products
- Conservative version-boundary and applicability-condition handling
- Potential / uncertain / non-match classifications
- Optional local Ollama explanation
- Concise terminal summary
- HTML report and optional detailed text report
- Offline unit tests for core matching behaviour

## Not implemented yet

- CVSS-based risk score or priority engine
- Arbitrary IP/domain scanning or configurable target profiles
- Web application scanning
- WAF assessment
- Dashboard or multi-user interface
- Production-grade vulnerability validation

This status file intentionally distinguishes working code from planned features.
