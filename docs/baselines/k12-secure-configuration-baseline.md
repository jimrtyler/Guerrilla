# K12 Secure Configuration Baseline

**Baseline ID prefix:** `K12`
**Version:** 0.1.0
**Status:** Candidate
**Authored by:** Guerrilla (Jim Tyler)
**Published:** 2026-07-12
**Comment period:** Open

## What this document is, and what it is not

This is a candidate community baseline for K12 school districts, authored and
maintained by the Guerrilla project. It is expert opinion, openly published,
versioned, and open for comment.

It is **not a consensus standard**. CISA SCuBA, CIS Benchmarks, NIST guidance,
and EIDSCA are produced by institutions through consensus processes. This
document is not a peer of those publications and should never be cited as one.
Guerrilla checks that assess these controls carry a `guerrillaBaseline` field,
which is deliberately separate from the `compliance` field used for external
framework mappings, so the two kinds of authority are never conflated.

Districts are invited to review these controls, comment, and co-sign the ones
that match their experience. No PowerShell required: reading a control and
saying "this matches what we need" or "this is wrong for districts like mine"
is a contribution. See CONTRIBUTING.md in the repository root.

## Why a K12 baseline exists

Consensus baselines assess a tenant as a single population. A school district
is not a single population: it is adults and minors sharing one tenant, with
legally distinct duties toward each (FERPA, COPPA, and state student-privacy
laws in the US). Settings that are reasonable defaults for staff are not
reasonable for students, and the boundary between the two is usually an
organizational unit subtree, not the tenant. No consensus baseline currently
assesses that boundary. This document proposes controls that do.

Several controls therefore require the assessing tool to be told which
organizational units contain student accounts. Guerrilla accepts this as an
explicit input; when it is not provided, OU-scoped controls report
Not Assessed rather than guessing.

## Versioning and lifecycle

The baseline is versioned as a whole (semver). Every control carries a
lifecycle status:

- `candidate`: proposed, open for comment, may change or be withdrawn.
- `adopted`: stable after community review; changes require a version bump
  and changelog entry. (Reserved; no control holds this status yet.)
- `deprecated`: retained for reference, no longer recommended. (Reserved.)

Checks reference this document by `baselineId` and `baselineVersion`. A check
claiming a control that does not exist in this document fails the build, and a
control listed here with no covering check must say so in its Checks field.
That consistency is enforced by an automated guard.

## Field key

Each control below carries these fields:

- **Scope:** `OU-scoped` (assessed against the student OU subtree, requires
  the student OU input) or `Tenant-wide`.
- **Assessment:** `Machine-assessable` (a collected setting decides the
  verdict), `Machine-assisted + policy review` (settings are collected but a
  district policy decision is part of the verdict), or `Policy review`
  (no API surface; human review).
- **Verdict posture:** `Standard` (normal PASS/FAIL semantics) or
  `Context-dependent` (no single right answer across districts; findings are
  reported as review items against the district's own policy, not hard FAIL).
- **Checks:** the Guerrilla check IDs that assess this control, or
  `Not yet covered`.
- **Status:** lifecycle status per above.

---

## Domain: Data protection and sharing (K12-DATA)

### K12-DATA-001: Student OUs do not inherit staff external-sharing defaults

- **Scope:** OU-scoped
- **Assessment:** Machine-assessable
- **Verdict posture:** Standard
- **Checks:** GWS-K12-001
- **Status:** candidate

**Rationale.** Districts commonly configure Drive external sharing for the
needs of staff (vendors, parents, other districts) and let student OUs inherit
that configuration. Inheritance is invisible in day-to-day administration: the
student OU shows a value, but nobody chose it for students. This control
requires that external-sharing configuration on student OUs be an explicit,
local decision rather than an inherited staff default.

**Threat addressed.** Student documents shared outside the district without
any deliberate decision that students should be able to do that. Exposure of
student work, names, and metadata to arbitrary external accounts.

**Settings assessed.** Drive and Docs sharing settings on each student OU
(Admin console: Apps > Google Workspace > Drive and Docs > Sharing settings),
specifically whether the external-sharing configuration on the student OU is
locally applied or inherited from a parent OU whose population is staff.

### K12-DATA-002: Student external Drive sharing is disabled or restricted

- **Scope:** OU-scoped
- **Assessment:** Machine-assessable
- **Verdict posture:** Standard
- **Checks:** GWS-K12-002
- **Status:** candidate

**Rationale.** Whatever the staff posture, student OUs should not permit
unrestricted sharing outside the organization. Reasonable district positions
range from fully disabled to allowlisted-domains to warn-on-external for older
students; unrestricted silent external sharing is not a defensible student
default at any age band.

**Threat addressed.** Deliberate or accidental exfiltration of student
documents to external accounts; students sharing personal information with
unknown external parties through Drive.

**Settings assessed.** Drive and Docs external-sharing mode on each student OU
(off, allowlisted domains, or on), and whether the warn-on-external-sharing
prompt is enabled when sharing is not fully disabled.

### K12-DATA-003: Student data is not excluded from retention

- **Scope:** Tenant-wide
- **Assessment:** Machine-assisted + policy review
- **Verdict posture:** Context-dependent
- **Checks:** Not yet covered
- **Status:** candidate

**Rationale.** Student mail and Drive content is frequently the record of an
incident: bullying, threats, grooming attempts, self-harm signals. Districts
that exclude student OUs from retention (or never license or configure Vault
for students) discover this during an investigation, when it is too late.
Retention duration is a district policy decision; having student data covered
by some deliberate retention decision is the control.

**Threat addressed.** Inability to reconstruct communications during a
safeguarding, legal, or disciplinary investigation because student data was
never retained.

**Settings assessed.** Vault licensing and default retention rules as they
apply to student OUs; whether student mail and Drive are excluded from
retention coverage.

---

## Domain: Identity and third-party access (K12-IDENT)

### K12-IDENT-001: Students cannot authorize third-party OAuth applications

- **Scope:** OU-scoped
- **Assessment:** Machine-assessable
- **Verdict posture:** Standard
- **Checks:** GWS-K12-003
- **Status:** candidate

**Rationale.** A student clicking "Sign in with Google" on an arbitrary
website can grant that site access to their school account data unless the
district restricts third-party API access. Staff may need broad OAuth access;
students need either no third-party access or a district-curated allowlist.
This is one of the highest-leverage single settings in a school tenant.

**Threat addressed.** Data harvesting from student accounts by non-vetted
applications; phishing-style consent grants against minors; ed-tech apps
acquiring student data without district review, contrary to COPPA/FERPA
obligations.

**Settings assessed.** Google Workspace API access controls for the student
OUs (Admin console: Security > API controls > App access control): whether
third-party app access is unrestricted for students, or restricted/blocked
with a configured allowlist.

### K12-IDENT-002: Vendor delegated access is scoped, current, and reviewed

- **Scope:** Tenant-wide
- **Assessment:** Machine-assisted + policy review
- **Verdict posture:** Context-dependent
- **Checks:** GWS-K12-004
- **Status:** candidate

**Rationale.** SIS platforms, rostering tools, and EdTech vendors accumulate
domain-wide delegation grants and OAuth authorizations over years. Vendors get
replaced; their grants rarely do. Each stale grant is standing access to
student data held by a party with no current contract or duty of care.

**Threat addressed.** Standing access to student data by former vendors;
breach of a defunct vendor cascading into the district tenant; domain-wide
delegation grants with scopes far beyond the vendor's function.

**Settings assessed.** Domain-wide delegation client list and granted scopes;
tenant OAuth token grants aggregated by application; age and last-use where
available. Which vendors are legitimate is a district determination, so
findings are review items rather than hard failures.

### K12-IDENT-003: Non-IT staff admin roles are least-privilege

- **Scope:** Tenant-wide
- **Assessment:** Machine-assisted + policy review
- **Verdict posture:** Context-dependent
- **Checks:** GWS-K12-005
- **Status:** candidate

**Rationale.** Districts routinely give counselors, secretaries, and building
administrators delegated admin roles for legitimate tasks (password resets,
class group changes) using roles far broader than the task: user-management
over the whole domain, or Super Admin because it was easiest. Every
over-privileged non-IT account is an account whose compromise reaches all
student data.

**Threat addressed.** Compromise of a non-technical staff account escalating
to bulk student-data access or security-setting changes; well-meaning staff
making tenant-wide changes they did not intend.

**Settings assessed.** Admin role assignments: which accounts hold which
delegated admin roles, the privileges in each role, and whether custom roles
scope user-management privileges to specific OUs rather than the whole
domain. Whether a given secretary should hold a given role is a district
determination; the machine-assessable part is surfacing scope-of-privilege
versus scope-of-duty mismatches for review.

---

## Domain: Child safety (K12-SAFE)

Wording note: controls in this domain describe configuration posture, not
incidents. A FAIL here means a setting permits a class of contact or access
that the district has not affirmatively decided to permit. It does not mean
such contact has occurred.

### K12-SAFE-001: Student communication boundaries are configured

- **Scope:** OU-scoped
- **Assessment:** Machine-assessable
- **Verdict posture:** Standard
- **Checks:** GWS-K12-006
- **Status:** candidate

**Rationale.** Google Chat, Meet, and Gmail each have independent settings
governing whether accounts can communicate with people outside the
organization. For staff these are productivity settings. For student OUs they
are a safety boundary: they determine whether an external adult can initiate
contact with a student through district-provided tools. The district should
make this boundary an explicit decision per service, per student OU.

**Threat addressed.** Unsolicited contact with students by external parties
through district-managed communication channels; students initiating contact
with unknown external accounts from school identities.

**Settings assessed.** Per student OU: Chat external-chat settings (whether
students can send or receive external direct messages and spaces), Meet
settings for who can join meetings and whether external participants can
interact with students, and Gmail external mail restrictions if the district
uses them for student OUs.

### K12-SAFE-002: Guardian access is configured with integrity

- **Scope:** OU-scoped
- **Assessment:** Machine-assisted + policy review
- **Verdict posture:** Context-dependent
- **Checks:** GWS-K12-007
- **Status:** candidate

**Rationale.** Guardian email summaries and guardian access exist so parents
see their own student's activity. The integrity properties that matter: the
district, not the student, controls who is registered as a guardian; a
student cannot approve or self-manage guardian invitations; and a guardian
relationship never exposes another student's data. Districts should also know
whether guardian features are in use at all, since an unused-but-enabled
feature is unowned surface.

**Threat addressed.** A non-guardian adult obtaining guardian-level visibility
into a student's activity; guardian relationships created without district
verification; cross-student data exposure through mis-scoped guardian access.

**Settings assessed.** Classroom guardian-summary settings per student OU
(whether guardian management is admin-controlled or teacher/student-
controlled), and, where collectable, the guardian invitation flow
configuration. Verifying the district's guardian-verification procedure is a
policy review item.

---

## Domain: Device and endpoint (K12-DEVICE)

### K12-DEVICE-001: Student Chromebook posture is managed

- **Scope:** OU-scoped
- **Assessment:** Machine-assessable
- **Verdict posture:** Standard
- **Checks:** GWS-K12-008
- **Status:** candidate

**Rationale.** Student Chromebooks are the district's largest fleet and its
most hostile-user environment, in the affectionate sense: students probe
boundaries as a hobby. The posture that keeps the fleet assessable: devices
must be enrolled (forced re-enrollment on wipe), student OUs carry an
extension allow/blocklist policy, and force-installed extensions on student
OUs are a reviewed list rather than an accumulation.

**Threat addressed.** Students unenrolling devices to escape management;
malicious or data-harvesting browser extensions on student devices;
force-installed extensions with broad permissions that nobody has reviewed.

**Settings assessed.** Per student OU: forced re-enrollment setting, extension
allow/blocklist configuration mode, sideloading and developer-mode controls,
and the force-install extension list for review.

---

## Domain: Lifecycle (K12-LIFE)

### K12-LIFE-001: Departed students are offboarded

- **Scope:** OU-scoped
- **Assessment:** Machine-assisted + policy review
- **Verdict posture:** Context-dependent
- **Checks:** GWS-K12-009
- **Status:** candidate

**Rationale.** Graduation and withdrawal produce accounts nobody owns. An
active account belonging to a departed student is an unwatched identity with
access to whatever the student OU permits, often still receiving mail and
still holding Drive data the district may be obligated to retain or return.
Districts need a disposition pipeline: suspend or archive on departure, and a
deliberate answer for Drive ownership before deletion.

**Threat addressed.** Credential compromise of unmonitored departed-student
accounts; departed students retaining access to current-student spaces; data
loss when accounts are eventually bulk-deleted without ownership transfer.

**Settings assessed.** Within student OUs (or a designated departed/alumni
OU): accounts with no sign-in activity beyond a threshold that remain active
rather than suspended, and suspended accounts holding Drive data with no
ownership transfer, surfaced as a review list. The departure roster itself
lives in the SIS, so verdicts are posture heuristics plus review items rather
than a roster reconciliation.

---

## Domain: Audit and recoverability (K12-AUDIT)

### K12-AUDIT-001: Audit-log durability supports investigations

- **Scope:** Tenant-wide
- **Assessment:** Machine-assisted + policy review
- **Verdict posture:** Context-dependent
- **Checks:** Not yet covered
- **Status:** candidate

**Rationale.** When a student account incident is suspected, the questions are
always the same: who signed in, from where, what was shared, what was deleted.
Workspace audit logs answer them only within their retention window (six
months for most Workspace editions, and not configurable upward without
export). A district that needs longer reconstruction capability must export
logs (BigQuery, SIEM, or scheduled Reports API pulls). The control: the
district knows its reconstruction window and has made a deliberate decision
that it is sufficient.

**Threat addressed.** Inability to reconstruct account activity during a
safeguarding or legal investigation because logs aged out; discovering the
retention window during the incident.

**Settings assessed.** Workspace edition and applicable log retention window;
whether a log-export pipeline (BigQuery export or equivalent) is configured.
Whether the resulting window satisfies the district's legal and safeguarding
obligations is a policy determination.

---

## Domain: Account hygiene (K12-ACCT)

### K12-ACCT-001: Student account security floor matches the age band

- **Scope:** OU-scoped
- **Assessment:** Machine-assisted + policy review
- **Verdict posture:** Context-dependent
- **Checks:** GWS-K12-010
- **Status:** candidate

**Rationale.** Consensus baselines demand 2SV enforcement for all users. For a
third grader with no phone, that demand is not just impractical; enforcing it
produces workarounds worse than the absence. An honest student security floor
is age-banded: strong password policy and admin-controlled recovery
everywhere; sign-in challenges where supported; 2SV enforcement for OUs
serving students old enough to hold a second factor. The control is that each
student OU has a deliberate floor matched to its age band, not that every OU
meets the staff bar.

**Threat addressed.** Bulk student-account compromise through weak or shared
passwords; account takeover via student-controlled recovery channels; the
false-comfort failure where a tool reports students FAIL 2SV forever and the
district learns to ignore the finding.

**Settings assessed.** Per student OU: password length and strength policy,
recovery options configuration (whether student-controlled recovery is
disabled), sign-in challenge posture, and 2SV enforcement state, evaluated
against the age band the district declares for that OU rather than against a
single tenant-wide bar.

---

## Future work

Entra ID twins of K12-IDENT-001 (student app-consent restrictions),
K12-IDENT-002 (vendor service principals), and K12-IDENT-003 (delegated admin
scoping) are planned as future candidate controls. This version assesses
Google Workspace first because it is the dominant K12 platform.

## Changelog

- 0.1.0 (2026-07-12): initial candidate publication, 12 controls.
