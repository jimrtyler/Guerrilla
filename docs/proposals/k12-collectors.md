# Proposal: collectors for the uncovered K12 baseline controls

Status: proposal. The K12 candidate baseline (docs/baselines/
k12-secure-configuration-baseline.md, v0.1.0) has twelve controls; ten are
assessed by GWS-K12-001..010. The two remaining controls, and one
strengthening item, need collection work recorded here so the gap is a
decision, not an accident.

## K12-DATA-003: student data retention (Vault)

Control: student mail and Drive are covered by a deliberate retention
decision. Not machine-assessable today: Guerrilla collects nothing from
Google Vault.

Proposed collector:
- API: `vault.googleapis.com/v1/matters` is not needed; retention rules are
  `vault.googleapis.com/v1/retentionRules`? No: default retention rules live
  under `v1/matters`-independent admin retention (`holds` are per-matter).
  The correct surface is the Vault API `retentionRules` custom rules plus
  default rule state, read with scope
  `https://www.googleapis.com/auth/ediscovery.readonly`.
- License visibility: Vault requires an edition or add-on license; the
  Enterprise License Manager API (`licensing.googleapis.com`) says which
  users hold one. Collect per student OU membership.
- Verdict shape: Context-dependent. Machine part: student OUs excluded from
  every retention rule, or students unlicensed for Vault, surfaces as WARN
  review items. Duration adequacy stays policy review.
- Isolation: own token, same self-isolating pattern as the Cloud Identity
  Policy scope (tenants that have not delegated ediscovery.readonly get
  Not Assessed, not a broken scan).

## K12-AUDIT-001: audit-log durability

Control: the district knows its log-reconstruction window and decided it is
sufficient. Mostly policy review; two machine-assessable fragments exist:

- Workspace edition (bounds the retention window): the Enterprise License
  Manager API or the Admin SDK `customers` subscription surface
  (`cloudchannel` is partner-only; `siteVerification` irrelevant). Needs a
  spike: the cleanest read appears to be the Licensing API per-SKU
  assignments.
- BigQuery export configured: no public read API. The setting's presence is
  inferable from the audit log itself (Reports API admin events record the
  export being enabled) which is the same audit-log-inference pattern
  recorded in docs/proposals/effective-state-and-audit-log-inference.md.

Until then the control stays Not yet covered in the baseline document, which
the completeness gate enforces as an explicit statement.

## Strengthening GWS-K12-004: token-activity collector

The domain-wide delegation surface exposes no grant age or last use, so
staleness is currently a review question. A per-user
`admin.directory.user.security` `tokens.list` sweep (sampled like the Gmail
crawl, `-Quick`-gated) would show which delegated clients actually
authenticate, turning "confirm each vendor is current" into "these three
grants have no observed authentication in the sample window."

## Entra twins (future baseline versions)

K12-IDENT-001/002/003 have Entra analogues (user consent policy,
service-principal credentials and permissions, delegated admin scoping by
administrative unit). Most of the required data is already collected by
Invoke-EntraAudit; the work is check logic plus an administrative-unit
analogue of the student-OU designation (the -StudentOU parameter already
exists on Invoke-EntraAudit, reserved). Planned as baseline 0.2.0 material.
