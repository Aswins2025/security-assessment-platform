# Scope and Authorization Record

This document exists to formally record that security testing performed with
the Automated Security Assessment and Vulnerability Analysis Platform was
carried out **only** against systems for which explicit authorization was
obtained, and within a controlled, agreed-upon scope. Fill in one copy of
this template per engagement/project and keep it alongside your assessment
reports.

Unauthorized scanning or testing of systems you do not own or do not have
written permission to test may be illegal in your jurisdiction (e.g. under
the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, or
equivalent local laws) even when using only "passive" or low-impact checks.
This platform does not perform this legal check for you — it is the
responsibility of the analyst to obtain and record authorization before
running any scan, and the `is_authorized` flag on a Project in this system
is a workflow control, not a substitute for actual legal authorization.

---

## 1. Engagement Details

| Field | Value |
|---|---|
| Project name | |
| Target application(s) / URL(s) | |
| Target environment | ☐ Production &nbsp; ☐ Staging &nbsp; ☐ Local/dev &nbsp; ☐ Dedicated test instance |
| Assessment start date | |
| Assessment end date | |
| Analyst(s) performing the assessment | |

## 2. Authorization

| Field | Value |
|---|---|
| Authorizing party (name, title, organization) | |
| Date authorization granted | |
| Form of authorization (e.g. signed engagement letter, email approval, internal ticket #) | |
| Scope explicitly included | |
| Scope explicitly excluded (out of bounds) | |
| Testing window / blackout periods (if any) | |
| Emergency contact during testing | |

## 3. Rules of Engagement

- [ ] Testing is limited to the categories implemented by this platform:
      authentication & session management, authorization & access control,
      input validation (passive indicators only), API security, client-side
      security headers, secure communication (TLS/HSTS), and data storage
      exposure (publicly reachable files only).
- [ ] No destructive, exploit-based, or denial-of-service testing will be
      performed. All checks are passive or benign active checks (e.g.
      requesting a well-known path, inspecting response headers).
- [ ] No real user accounts, personal data, or production data will be
      accessed, modified, or exfiltrated during testing.
- [ ] Any authenticated testing (e.g. authorization/access-control checks)
      will use dedicated test accounts created specifically for this
      assessment, not real user credentials.
- [ ] Findings and evidence will be stored and shared only with the
      authorizing party and other explicitly approved stakeholders.
- [ ] If a finding indicates a severe, actively exploitable issue, the
      analyst will pause automated scanning and notify the authorizing party
      immediately rather than continuing further testing.

## 4. Sign-off

| Role | Name | Signature / Approval Reference | Date |
|---|---|---|---|
| Authorizing party | | | |
| Lead analyst | | | |

---

*Keep this record on file for the duration of the engagement and for your
organization's standard audit-retention period. Attach or link it to the
corresponding project in the platform's dashboard.*
