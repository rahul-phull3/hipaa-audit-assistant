# Example policies

Both are fictional, contain no real data and are safe to send to a model. They are for trying the tool, not for measuring it.

| File | What it is |
| --- | --- |
| `sample_policy.md` | A short policy of about 460 words. Quick to read. The browser test and `make demo` use it |
| `clinic_security_policy.pdf` | A four-page PDF with numbered sections and a table, for trying the PDF path and the Claude reviewer |
| `clinic_security_policy.md` | The same text as the PDF, so you can edit it. The PDF was printed from it with Chromium |

## Trying the clinic policy

```sh
# Offline keyword matcher, no key. It is not an AI model and it under-reports
hipaa-audit audit examples/clinic_security_policy.pdf --backend heuristic -o review.md

# Claude, with ANTHROPIC_API_KEY set. This makes one model call for each of the 48 controls
hipaa-audit audit examples/clinic_security_policy.pdf -o review.md

# A cheaper first run: three controls, one well covered, one partly and one missing
hipaa-audit audit examples/clinic_security_policy.pdf --controls risk-analysis,data-backup-plan,periodic-evaluation -o review.md
```

Or choose the file in the browser interface (`hipaa-audit serve`).

## What the clinic policy was written to show

It is written so that a reader finds a mix. Below is the author's reading of the text against the catalog, as a sanity check
for a first run. **It is not a test result and not an accuracy measure**: the same person wrote the policy and this list, and a
model can reasonably disagree on the borderline items. The control ids are the ones `hipaa-audit controls` prints.

**Written to address the control (15):** `risk-analysis`, `risk-management`, `information-system-activity-review`,
`assigned-security-responsibility`, `termination-procedures`, `access-authorization`, `security-awareness-training`,
`data-backup-plan`, `access-control-validation`, `unique-user-identification`, `automatic-logoff`, `audit-controls`,
`transmission-encryption`, `policies-and-procedures`, `documentation-retention`.

**Written to address part of it (19):** `sanction-policy` (no word on making staff aware of sanctions),
`workforce-authorization-supervision`, `access-establishment-modification` (no periodic access review), `malicious-software-protection`
(no reporting of suspected malware), `password-management` (no change or storage rules), `incident-response-and-reporting` (no
containment or mitigation), `disaster-recovery-plan` (a plan is mentioned and nothing more), `contingency-testing-revision`,
`business-associate-arrangements` (no list of vendors), `facility-security-plan`, `workstation-use`, `workstation-security`,
`device-media-disposal` (no record of disposal), `encryption-at-rest` (no word on keys), `person-entity-authentication` (no
stronger sign-in for remote access), `transmission-integrity-controls`, `business-associate-contract-terms` (nothing about
subcontractors), `documentation-availability`, `documentation-updates`.

**Left out on purpose (14):** `workforce-clearance`, `security-reminders`, `login-monitoring`, `emergency-mode-operation-plan`,
`criticality-analysis`, `periodic-evaluation`, `facility-contingency-operations`, `maintenance-records`, `media-reuse`,
`device-media-accountability`, `data-backup-before-movement`, `emergency-access-procedure`, `integrity-protection`,
`ephi-authentication-mechanism`.

Borderline, where a careful reader could go either way: `access-control-validation`, `documentation-availability`,
`transmission-integrity-controls`, `disaster-recovery-plan` and `workforce-clearance`.
