# Changelog

## v3.0 — Advanced Toolkit Upgrade

### Fixed
- **Critical bug**: `self.SVERITY_LOW` typo in `_check_referrer_policy` raised
  an uncaught `AttributeError`. Because the whole `scan()` method was wrapped
  in a single try/except, this silently aborted the entire scan and reset the
  report to its default placeholder values — which is why a real scan could
  show a contradictory **"Risk Score: 0/100, Grade: F"** at the same time.

### Added
- **Fault-isolated scan stages**: header analysis, SSL/TLS, DNS/network, and
  content checks now each run in their own try/except. A failure in one stage
  (e.g. a DNS timeout) no longer erases findings from the others or resets
  the risk score to zero.
- **New checks**:
  - `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`,
    `Cross-Origin-Resource-Policy` (modern cross-origin isolation headers)
  - RFC 9116 `security.txt` discovery (`/.well-known/security.txt`)
- **Real HTML report**: the previous HTML output was a placeholder stub.
  It's now a fully styled, severity-color-coded report with a grade badge,
  grouped findings, remediation text, and a headers table.
- **Reference links** on findings that have an authoritative source
  (MDN, RFCs) so reviewers/users can verify recommendations.
- **Test suite** (`tests/test_scanner.py`, 12 tests) covering header checks,
  risk scoring, report generation, and a regression test for the
  scan-isolation bug fix — runs offline via mocked HTTP/DNS.

### Unchanged
- CLI interface, JSON/CSV/text report formats, concurrent multi-URL scanning.
