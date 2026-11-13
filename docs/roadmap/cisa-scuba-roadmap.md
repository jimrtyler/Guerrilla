# CISA / SCuBA Coverage Roadmap

> Generated daily by `.github/workflows/cisa-roadmap.yml` (`scripts/roadmap/cisa-scan.py`). Do not edit by hand: changes are overwritten on the next scan. This is a deterministic diff of upstream CISA SCuBA baselines against the checks Guerrilla ships. No AI is involved.

Last scan: **2026-11-13 18:54 UTC**

## Upstream state

| Source | Latest | Notes |
|---|---|---|
| ScubaGear (M365 / Entra) | [v2.0.0](https://github.com/cisagov/ScubaGear/releases/tag/v2.0.0) (2026-10-22) | MS.* Secure Configuration Baselines |
| ScubaGoggles (Google Workspace) | [v1.1.0](https://github.com/cisagov/ScubaGoggles/releases/tag/v1.1.0) (2026-10-22) | GWS.* Secure Configuration Baselines |
| CISA KEV catalog | 2026.11.13 (2026-11-13) | 1781 known-exploited CVEs |
| CISA BOD 25-01 | [SCuBA mandate](https://www.cisa.gov/news-events/directives/binding-operational-directive-25-01) | Secure cloud baselines for FCEB M365 |

## SCuBA coverage summary

Coverage compares the base policy ID (version tag stripped) so a version bump does not read as a lost mapping; version drift is tracked separately.

| Baseline | Upstream policies | Covered by Guerrilla | Gap |
|---|---|---|---|
| ScubaGear MS.* | 222 | 79 | **143** |
| ScubaGoggles GWS.* | 139 | 110 | **29** |

Guerrilla references 80 MS.* and 110 GWS.* policy IDs today.

## ScubaGear (M365 / Entra) gaps

143 upstream policies have no Guerrilla check yet (candidate roadmap items):

- [ ] `MS.AAD.3.9`
- [ ] `MS.AAD.5.4`
- [ ] `MS.AAD.9.1`
- [ ] `MS.DEFENDER.1.4`
- [ ] `MS.DEFENDER.1.5`
- [ ] `MS.DEFENDER.2.3`
- [ ] `MS.DEFENDER.4.2`
- [ ] `MS.DEFENDER.4.3`
- [ ] `MS.DEFENDER.4.4`
- [ ] `MS.DEFENDER.4.5`
- [ ] `MS.DEFENDER.4.6`
- [ ] `MS.DEFENDER.6.2`
- [ ] `MS.EXO.10.1`
- [ ] `MS.EXO.10.2`
- [ ] `MS.EXO.10.3`
- [ ] `MS.EXO.11.1`
- [ ] `MS.EXO.11.2`
- [ ] `MS.EXO.11.3`
- [ ] `MS.EXO.12.1`
- [ ] `MS.EXO.12.2`
- [ ] `MS.EXO.14.1`
- [ ] `MS.EXO.14.2`
- [ ] `MS.EXO.14.3`
- [ ] `MS.EXO.15.1`
- [ ] `MS.EXO.15.2`
- [ ] `MS.EXO.15.3`
- [ ] `MS.EXO.16.1`
- [ ] `MS.EXO.16.2`
- [ ] `MS.EXO.17.1`
- [ ] `MS.EXO.17.2`
- [ ] `MS.EXO.17.3`
- [ ] `MS.EXO.2.1`
- [ ] `MS.EXO.8.1`
- [ ] `MS.EXO.8.2`
- [ ] `MS.EXO.8.3`
- [ ] `MS.EXO.8.4`
- [ ] `MS.EXO.9.1`
- [ ] `MS.EXO.9.2`
- [ ] `MS.EXO.9.3`
- [ ] `MS.EXO.9.4`
- [ ] `MS.EXO.9.5`
- [ ] `MS.POWERBI.1.1`
- [ ] `MS.POWERBI.2.1`
- [ ] `MS.POWERBI.3.1`
- [ ] `MS.POWERBI.4.1`
- [ ] `MS.POWERBI.4.2`
- [ ] `MS.POWERBI.5.1`
- [ ] `MS.POWERBI.6.1`
- [ ] `MS.POWERBI.7.1`
- [ ] `MS.POWERPLATFORM.4.1`
- [ ] `MS.POWERPLATFORM.5.1`
- [ ] `MS.POWERPLATFORM.6.1`
- [ ] `MS.SECURITYSUITE.1.1`
- [ ] `MS.SECURITYSUITE.1.2`
- [ ] `MS.SECURITYSUITE.1.3`
- [ ] `MS.SECURITYSUITE.1.4`
- [ ] `MS.SECURITYSUITE.2.1`
- [ ] `MS.SECURITYSUITE.2.2`
- [ ] `MS.SECURITYSUITE.2.3`
- [ ] `MS.SECURITYSUITE.2.4`
- [ ] `MS.SECURITYSUITE.3.1`
- [ ] `MS.SECURITYSUITE.3.2`
- [ ] `MS.SECURITYSUITE.3.3`
- [ ] `MS.SECURITYSUITE.3.4`
- [ ] `MS.SECURITYSUITE.3.5`
- [ ] `MS.SECURITYSUITE.4.1`
- [ ] `MS.SECURITYSUITE.4.2`
- [ ] `MS.SECURITYSUITE.5.1`
- [ ] `MS.SECURITYSUITE.5.2`
- [ ] `MS.SECURITYSUITE.6.1`
- [ ] `MS.SECURITYSUITE.6.2`
- [ ] `MS.SECURITYSUITE.7.1`
- [ ] `MS.SECURITYSUITE.7.2`
- [ ] `MS.SECURITYSUITE.7.3`
- [ ] `MS.SECURITYSUITE.8.1`
- [ ] `MS.SECURITYSUITE.8.2`
- [ ] `MS.SHAREPOINT.1.4`
- [ ] `MS.SHAREPOINT.3.3`
- [ ] `MS.SHAREPOINT.4.1`
- [ ] `MS.SHAREPOINT.4.2`
- [ ] `MS.SI.1.1`
- [ ] `MS.SI.1.2`
- [ ] `MS.SI.1.3`
- [ ] `MS.SI.10.1`
- [ ] `MS.SI.10.2`
- [ ] `MS.SI.10.3`
- [ ] `MS.SI.10.4`
- [ ] `MS.SI.10.5`
- [ ] `MS.SI.10.6`
- [ ] `MS.SI.10.7`
- [ ] `MS.SI.11.1`
- [ ] `MS.SI.11.2`
- [ ] `MS.SI.11.3`
- [ ] `MS.SI.11.4`
- [ ] `MS.SI.11.5`
- [ ] `MS.SI.11.6`
- [ ] `MS.SI.12.1`
- [ ] `MS.SI.12.2`
- [ ] `MS.SI.12.3`
- [ ] `MS.SI.12.4`
- [ ] `MS.SI.13.1`
- [ ] `MS.SI.13.2`
- [ ] `MS.SI.13.3`
- [ ] `MS.SI.13.4`
- [ ] `MS.SI.13.5`
- [ ] `MS.SI.13.6`
- [ ] `MS.SI.2.1`
- [ ] `MS.SI.2.2`
- [ ] `MS.SI.2.3`
- [ ] `MS.SI.3.1`
- [ ] `MS.SI.3.2`
- [ ] `MS.SI.3.3`
- [ ] `MS.SI.3.4`
- [ ] `MS.SI.4.1`
- [ ] `MS.SI.4.2`
- [ ] `MS.SI.4.3`
- [ ] `MS.SI.5.1`
- [ ] `MS.SI.6.1`
- [ ] `MS.SI.6.2`
- [ ] `MS.SI.6.3`
- [ ] `MS.SI.6.4`
- [ ] `MS.SI.7.1`
- [ ] `MS.SI.7.2`
- [ ] `MS.SI.7.3`
- [ ] `MS.SI.7.4`
- [ ] `MS.SI.8.1`
- [ ] `MS.SI.8.2`
- [ ] `MS.SI.8.3`
- [ ] `MS.SI.8.4`
- [ ] `MS.SI.8.5`
- [ ] `MS.SI.9.1`
- [ ] `MS.SI.9.2`
- [ ] `MS.SI.9.3`
- [ ] `MS.TEAMS.1.4`
- [ ] `MS.TEAMS.1.5`
- [ ] `MS.TEAMS.3.1`
- [ ] `MS.TEAMS.4.1`
- [ ] `MS.TEAMS.6.1`
- [ ] `MS.TEAMS.6.2`
- [ ] `MS.TEAMS.7.1`
- [ ] `MS.TEAMS.7.2`
- [ ] `MS.TEAMS.8.1`
- [ ] `MS.TEAMS.8.2`

Version drift (Guerrilla references an older policy version than upstream):

- `MS.DEFENDER.4.1v1 -> MS.DEFENDER.4.1v2`

## ScubaGoggles (Google Workspace) gaps

29 upstream policies have no Guerrilla check yet (candidate roadmap items):

- [ ] `GWS.CALENDAR.3.2`
- [ ] `GWS.CHAT.5.1`
- [ ] `GWS.CHAT.5.2`
- [ ] `GWS.COMMONCONTROLS.10.1`
- [ ] `GWS.COMMONCONTROLS.10.2`
- [ ] `GWS.COMMONCONTROLS.12.1`
- [ ] `GWS.COMMONCONTROLS.14.1`
- [ ] `GWS.COMMONCONTROLS.14.2`
- [ ] `GWS.COMMONCONTROLS.16.3`
- [ ] `GWS.COMMONCONTROLS.16.4`
- [ ] `GWS.COMMONCONTROLS.18.1`
- [ ] `GWS.COMMONCONTROLS.18.2`
- [ ] `GWS.COMMONCONTROLS.2.1`
- [ ] `GWS.COMMONCONTROLS.3.1`
- [ ] `GWS.COMMONCONTROLS.3.2`
- [ ] `GWS.COMMONCONTROLS.6.1`
- [ ] `GWS.COMMONCONTROLS.8.3`
- [ ] `GWS.COMMONCONTROLS.9.1`
- [ ] `GWS.COMMONCONTROLS.9.2`
- [ ] `GWS.DRIVEDOCS.1.10`
- [ ] `GWS.DRIVEDOCS.1.11`
- [ ] `GWS.DRIVEDOCS.5.2`
- [ ] `GWS.GEMINI.5.1`
- [ ] `GWS.GMAIL.13.1`
- [ ] `GWS.GMAIL.4.3`
- [ ] `GWS.GMAIL.4.4`
- [ ] `GWS.MEET.6.1`
- [ ] `GWS.MEET.6.2`
- [ ] `GWS.MEET.6.3`

Version drift (Guerrilla references an older policy version than upstream):

- `GWS.GMAIL.7.5v1 -> GWS.GMAIL.7.5v2`

## Newest CISA KEV entries

Broader CISA context (CVE-level, not directly a config baseline):

- `CVE-2026-114713` UnrealIRCd Improper Neutralization of Delimiters Vulnerability (added 2026-11-13)
- `CVE-2026-123039` Check Point Multiple Products Incorrect Permission Assignment for Critical Resource Vulnerability (added 2026-11-13)
- `CVE-2026-124194` Microsoft Office Outlook Missing User Interaction for Potentially Unsafe Action Vulnerability (added 2026-11-10)
- `CVE-2026-111793` Openwave Messaging Limited Webtop Media Transcoder Incorrect Resource Transfer Between Spheres Vulnerability (added 2026-11-10)
- `CVE-2026-20320` Cisco BroadWorks Improper Restriction of XML External Entity Reference Vulnerability (added 2026-11-10)

## Scan log

Most recent first. One entry per day the scanner ran.

### 2026-11-13
- KEV catalog 2026.11.10 -> 2026.11.13 (+2 entries, now 1781)

### 2026-11-12
- No upstream changes detected.

### 2026-11-11
- KEV catalog 2026.11.09 -> 2026.11.10 (+6 entries, now 1779)

### 2026-11-10
- No upstream changes detected.

### 2026-11-09
- ScubaGoggles new policies: GWS.COMMONCONTROLS.16.3v2, GWS.GEMINI.5.1v1
- ScubaGoggles removed policies: GWS.COMMONCONTROLS.16.3v1
- KEV catalog 2026.11.06 -> 2026.11.09 (+4 entries, now 1773)

### 2026-11-08
- No upstream changes detected.

### 2026-11-07
- KEV catalog 2026.11.04 -> 2026.11.06 (+1 entries, now 1769)

### 2026-11-06
- No upstream changes detected.

### 2026-11-05
- KEV catalog 2026.11.03 -> 2026.11.04 (+1 entries, now 1768)

### 2026-11-04
- ScubaGear new policies: MS.SI.1.1v1, MS.SI.1.2v1, MS.SI.1.3v1, MS.SI.10.1v1, MS.SI.10.2v1, MS.SI.10.3v1, MS.SI.10.4v1, MS.SI.10.5v1, MS.SI.10.6v1, MS.SI.10.7v1, MS.SI.11.1v1, MS.SI.11.2v1, MS.SI.11.3v1, MS.SI.11.4v1, MS.SI.11.5v1, MS.SI.11.6v1, MS.SI.12.1v1, MS.SI.12.2v1, MS.SI.12.3v1, MS.SI.12.4v1, MS.SI.13.1v1, MS.SI.13.2v1, MS.SI.13.3v1, MS.SI.13.4v1, MS.SI.13.5v1, MS.SI.13.6v1, MS.SI.2.1v1, MS.SI.2.2v1, MS.SI.2.3v1, MS.SI.3.1v1, MS.SI.3.2v1, MS.SI.3.3v1, MS.SI.3.4v1, MS.SI.4.1v1, MS.SI.4.2v1, MS.SI.4.3v1, MS.SI.5.1v1, MS.SI.6.1v1, MS.SI.6.2v1, MS.SI.6.3v1, MS.SI.6.4v1, MS.SI.7.1v1, MS.SI.7.2v1, MS.SI.7.3v1, MS.SI.7.4v1, MS.SI.8.1v1, MS.SI.8.2v1, MS.SI.8.3v1, MS.SI.8.4v1, MS.SI.8.5v1, MS.SI.9.1v1, MS.SI.9.2v1, MS.SI.9.3v1
- KEV catalog 2026.10.30 -> 2026.11.03 (+1 entries, now 1767)

### 2026-11-03
- No upstream changes detected.

### 2026-11-02
- ScubaGoggles new policies: GWS.GMAIL.7.5v2
- ScubaGoggles removed policies: GWS.GMAIL.7.5v1

### 2026-11-01
- No upstream changes detected.

### 2026-10-31
- KEV catalog 2026.10.29 -> 2026.10.30 (+2 entries, now 1766)

### 2026-10-30
- KEV catalog 2026.10.28 -> 2026.10.29 (+2 entries, now 1764)

### 2026-10-29
- KEV catalog 2026.10.27 -> 2026.10.28 (+2 entries, now 1762)

### 2026-10-28
- KEV catalog 2026.10.26 -> 2026.10.27 (+2 entries, now 1760)

### 2026-10-27
- KEV catalog 2026.10.23 -> 2026.10.26 (+2 entries, now 1758)

### 2026-10-26
- No upstream changes detected.

### 2026-10-25
- No upstream changes detected.

### 2026-10-24
- KEV catalog 2026.10.21 -> 2026.10.23 (+2 entries, now 1756)

### 2026-10-23
- ScubaGear release v1.8.0 -> v2.0.0 (2026-10-22)
- ScubaGoggles release v1.0.1 -> v1.1.0 (2026-10-22)

### 2026-10-22
- No upstream changes detected.

### 2026-10-21
- KEV catalog 2026.10.16 -> 2026.10.21 (+6 entries, now 1754)

### 2026-10-20
- No upstream changes detected.

### 2026-10-19
- No upstream changes detected.

### 2026-10-18
- No upstream changes detected.

### 2026-10-17
- KEV catalog 2026.10.15 -> 2026.10.16 (+2 entries, now 1748)

### 2026-10-16
- ScubaGear removed policies: MS.SECURITYSUITE.15.2v1
- KEV catalog 2026.10.14 -> 2026.10.15 (+1 entries, now 1746)

### 2026-10-15
- KEV catalog 2026.10.13 -> 2026.10.14 (+4 entries, now 1745)

### 2026-10-14
- No upstream changes detected.

### 2026-10-13
- KEV catalog 2026.10.08 -> 2026.10.13 (+1 entries, now 1740)

### 2026-10-12
- No upstream changes detected.

### 2026-10-11
- No upstream changes detected.

### 2026-10-10
- No upstream changes detected.

### 2026-10-09
- No upstream changes detected.

### 2026-10-08
- KEV catalog 2026.10.04 -> 2026.10.08 (+5 entries, now 1739)

### 2026-10-07
- No upstream changes detected.

### 2026-10-06
- KEV catalog 2026.10.02 -> 2026.10.04 (+1 entries, now 1734)

### 2026-10-04
- No upstream changes detected.

### 2026-10-03
- No upstream changes detected.

### 2026-10-02
- KEV catalog 2026.09.30 -> 2026.10.02 (+3 entries, now 1733)

### 2026-10-01
- KEV catalog 2026.09.29 -> 2026.09.30 (+1 entries, now 1730)

### 2026-09-30
- No upstream changes detected.

### 2026-09-29
- KEV catalog 2026.09.27 -> 2026.09.29 (+1 entries, now 1729)

### 2026-09-28
- KEV catalog 2026.09.25 -> 2026.09.27 (+2 entries, now 1728)

### 2026-09-27
- No upstream changes detected.

### 2026-09-26
- No upstream changes detected.

### 2026-09-25
- KEV catalog 2026.09.23 -> 2026.09.25 (+4 entries, now 1725)

### 2026-09-24
- No upstream changes detected.

### 2026-09-23
- KEV catalog 2026.09.21 -> 2026.09.23 (+4 entries, now 1721)

### 2026-09-22
- KEV catalog 2026.09.18 -> 2026.09.21 (+1 entries, now 1717)

### 2026-09-21
- No upstream changes detected.

### 2026-09-20
- No upstream changes detected.

### 2026-09-19
- No upstream changes detected.

### 2026-09-18
- KEV catalog 2026.09.16 -> 2026.09.18 (+2 entries, now 1715)

### 2026-09-17
- No upstream changes detected.

### 2026-09-16
- ScubaGear new policies: MS.SHAREPOINT.1.1v1, MS.SHAREPOINT.1.2v1, MS.SHAREPOINT.1.3v1, MS.SHAREPOINT.2.1v1, MS.SHAREPOINT.2.2v1, MS.SHAREPOINT.3.1v1, MS.SHAREPOINT.3.2v1, MS.SHAREPOINT.3.3v2
- ScubaGoggles new policies: GWS.COMMONCONTROLS.1.1v1, GWS.COMMONCONTROLS.1.2v1, GWS.COMMONCONTROLS.1.3v1, GWS.COMMONCONTROLS.1.4v1, GWS.COMMONCONTROLS.1.5v1, GWS.COMMONCONTROLS.10.1v1, GWS.COMMONCONTROLS.10.2v1, GWS.COMMONCONTROLS.10.3v1, GWS.COMMONCONTROLS.10.4v1, GWS.COMMONCONTROLS.10.5v1, GWS.COMMONCONTROLS.11.1v1, GWS.COMMONCONTROLS.12.1v1, GWS.COMMONCONTROLS.13.1v1, GWS.COMMONCONTROLS.14.1v1, GWS.COMMONCONTROLS.14.2v1, GWS.COMMONCONTROLS.15.1v1, GWS.COMMONCONTROLS.15.2v1, GWS.COMMONCONTROLS.16.1v1, GWS.COMMONCONTROLS.16.2v1, GWS.COMMONCONTROLS.16.3v1, GWS.COMMONCONTROLS.16.4v1, GWS.COMMONCONTROLS.17.1v1, GWS.COMMONCONTROLS.18.1v1, GWS.COMMONCONTROLS.18.2v1, GWS.COMMONCONTROLS.2.1v1, GWS.COMMONCONTROLS.3.1v1, GWS.COMMONCONTROLS.3.2v1, GWS.COMMONCONTROLS.4.1v1, GWS.COMMONCONTROLS.5.1v1, GWS.COMMONCONTROLS.5.2v1, GWS.COMMONCONTROLS.5.3v1, GWS.COMMONCONTROLS.5.4v1, GWS.COMMONCONTROLS.5.5v1, GWS.COMMONCONTROLS.5.6v1, GWS.COMMONCONTROLS.6.1v1, GWS.COMMONCONTROLS.6.2v1, GWS.COMMONCONTROLS.7.1v1, GWS.COMMONCONTROLS.8.1v1, GWS.COMMONCONTROLS.8.2v1, GWS.COMMONCONTROLS.8.3v1, GWS.COMMONCONTROLS.9.1v1, GWS.COMMONCONTROLS.9.2v1
- KEV catalog 2026.09.14 -> 2026.09.16 (+1 entries, now 1711)

### 2026-09-15
- ScubaGear removed policies: MS.SHAREPOINT.1.1v1, MS.SHAREPOINT.1.2v1, MS.SHAREPOINT.1.3v1, MS.SHAREPOINT.2.1v1, MS.SHAREPOINT.2.2v1, MS.SHAREPOINT.3.1v1, MS.SHAREPOINT.3.2v1, MS.SHAREPOINT.3.3v2
- ScubaGoggles removed policies: GWS.COMMONCONTROLS.1.1v1, GWS.COMMONCONTROLS.1.2v1, GWS.COMMONCONTROLS.1.3v1, GWS.COMMONCONTROLS.1.4v1, GWS.COMMONCONTROLS.1.5v1, GWS.COMMONCONTROLS.10.1v1, GWS.COMMONCONTROLS.10.2v1, GWS.COMMONCONTROLS.10.3v1, GWS.COMMONCONTROLS.10.4v1, GWS.COMMONCONTROLS.10.5v1, GWS.COMMONCONTROLS.11.1v1, GWS.COMMONCONTROLS.12.1v1, GWS.COMMONCONTROLS.13.1v1, GWS.COMMONCONTROLS.14.1v1, GWS.COMMONCONTROLS.14.2v1, GWS.COMMONCONTROLS.15.1v1, GWS.COMMONCONTROLS.15.2v1, GWS.COMMONCONTROLS.16.1v1, GWS.COMMONCONTROLS.16.2v1, GWS.COMMONCONTROLS.16.3v1, GWS.COMMONCONTROLS.16.4v1, GWS.COMMONCONTROLS.17.1v1, GWS.COMMONCONTROLS.18.1v1, GWS.COMMONCONTROLS.18.2v1, GWS.COMMONCONTROLS.2.1v1, GWS.COMMONCONTROLS.3.1v1, GWS.COMMONCONTROLS.3.2v1, GWS.COMMONCONTROLS.4.1v1, GWS.COMMONCONTROLS.5.1v1, GWS.COMMONCONTROLS.5.2v1, GWS.COMMONCONTROLS.5.3v1, GWS.COMMONCONTROLS.5.4v1, GWS.COMMONCONTROLS.5.5v1, GWS.COMMONCONTROLS.5.6v1, GWS.COMMONCONTROLS.6.1v1, GWS.COMMONCONTROLS.6.2v1, GWS.COMMONCONTROLS.7.1v1, GWS.COMMONCONTROLS.8.1v1, GWS.COMMONCONTROLS.8.2v1, GWS.COMMONCONTROLS.8.3v1, GWS.COMMONCONTROLS.9.1v1, GWS.COMMONCONTROLS.9.2v1
- KEV catalog 2026.09.11 -> 2026.09.14 (+1 entries, now 1710)

### 2026-09-14
- No upstream changes detected.

### 2026-09-13
- No upstream changes detected.

### 2026-09-12
- KEV catalog 2026.09.10 -> 2026.09.11 (+4 entries, now 1709)

### 2026-09-11
- KEV catalog 2026.09.09 -> 2026.09.10 (+2 entries, now 1705)

### 2026-09-10
- No upstream changes detected.

### 2026-09-09
- KEV catalog 2026.09.04 -> 2026.09.09 (+4 entries, now 1699)

### 2026-09-08
- No upstream changes detected.

### 2026-09-07
- No upstream changes detected.

### 2026-09-06
- No upstream changes detected.

### 2026-09-05
- KEV catalog 2026.09.02 -> 2026.09.04 (+1 entries, now 1695)

### 2026-09-04
- No upstream changes detected.

### 2026-09-03
- KEV catalog 2026.09.01 -> 2026.09.02 (+7 entries, now 1694)

### 2026-09-02
- KEV catalog 2026.08.31 -> 2026.09.01 (+0 entries, now 1687)

### 2026-09-01
- No upstream changes detected.

### 2026-08-31
- KEV catalog 2026.08.27 -> 2026.08.31 (+2 entries, now 1687)

### 2026-08-30
- No upstream changes detected.

### 2026-08-29
- No upstream changes detected.

### 2026-08-28
- No upstream changes detected.

### 2026-08-27
- KEV catalog 2026.08.25 -> 2026.08.27 (+9 entries, now 1685)

### 2026-08-26
- KEV catalog 2026.08.24 -> 2026.08.25 (+1 entries, now 1676)

### 2026-08-25
- KEV catalog 2026.08.21 -> 2026.08.24 (+1 entries, now 1675)

### 2026-08-24
- No upstream changes detected.

### 2026-08-23
- No upstream changes detected.

### 2026-08-22
- No upstream changes detected.

### 2026-08-21
- KEV catalog 2026.08.19 -> 2026.08.21 (+2 entries, now 1673)

### 2026-08-20
- KEV catalog 2026.08.18 -> 2026.08.19 (+1 entries, now 1671)

### 2026-08-19
- KEV catalog 2026.08.17 -> 2026.08.18 (+4 entries, now 1670)

### 2026-08-18
- KEV catalog 2026.08.14 -> 2026.08.17 (+1 entries, now 1666)

### 2026-08-17
- No upstream changes detected.

### 2026-08-16
- No upstream changes detected.

### 2026-08-15
- KEV catalog 2026.08.11 -> 2026.08.14 (+0 entries, now 1665)

### 2026-08-14
- No upstream changes detected.

### 2026-08-13
- ScubaGoggles new policies: GWS.MEET.6.3v1

### 2026-08-12
- KEV catalog 2026.08.10 -> 2026.08.11 (+3 entries, now 1665)

### 2026-08-11
- KEV catalog 2026.08.07 -> 2026.08.10 (+0 entries, now 1662)

### 2026-08-10
- No upstream changes detected.

### 2026-08-09
- No upstream changes detected.

### 2026-08-08
- KEV catalog 2026.08.06 -> 2026.08.07 (+1 entries, now 1662)

### 2026-08-07
- No upstream changes detected.

### 2026-08-06
- KEV catalog 2026.08.04 -> 2026.08.06 (+1 entries, now 1661)

### 2026-08-05
- No upstream changes detected.

### 2026-08-04
- KEV catalog 2026.07.29 -> 2026.08.03 (+1 entries, now 1657)

### 2026-08-03
- Initial CISA/SCuBA baseline snapshot captured: ScubaGear 170 MS.* policies, ScubaGoggles 137 GWS.* policies, KEV 1656 CVEs.
