# Reputation evidence and the alert policy (Phase F2 / F2.1)

**Status: the evidence policy is built and tested but NOT active.** The running application uses the `legacy` policy (`SEVERITY_POLICY=legacy`, the default): one malicious VirusTotal
engine is already SUSPICIOUS and raises a MEDIUM alert, three malicious engines are MALICIOUS and raise a HIGH alert. Nothing below changes that until an administrator sets
`SEVERITY_POLICY=evidence` in `.env` and restarts the server.

## What is recorded for every VirusTotal lookup (both policies)
`reputation_evidence.details_json` keeps the engines that flagged the domain (name, category, result text; at most 30; printable ASCII; under 4 KB), the indicator type, the
assessment level and its strength. The five counts (malicious, suspicious, harmless, undetected, timeout) are unchanged. Engines that found nothing are not listed and the raw
response is never stored. Records written before Phase F2 have no details and are read exactly as before.

## Levels of the evidence policy
M = engines that said *malicious*, S = *suspicious*, A = at least one of the malicious engines is on the authoritative list.

| Level | Rule | Display verdict | Alert |
|---|---|---|---|
| UNKNOWN | no engine answered | UNKNOWN | none |
| CLEAN | M = 0 and S = 0 | SAFE (*no engine flagged it - this is not proof of safety*) | none |
| WEAK | at least one flagged engine, none of the rules below | SUSPICIOUS, level WEAK | **none**; shown as "Weak finding" with the engine names |
| CREDIBLE | M >= 3, or M >= 2 and A, or M >= 1 and M+S >= 4, or M+S >= 5 | SUSPICIOUS | MEDIUM |
| CONFIRMED | M >= 4, or M >= 3 and A | MALICIOUS | HIGH |

A WEAK finding is kept for investigation: the visit is stored with `level = WEAK`, it appears in the visit list and the analysis page, but it creates no alert, adds **zero** risk
points, is not counted as a threat, an exposure or an affected computer, and does not make a computer look compromised (analytics reports it separately as `weak_finding_visits`).
A visit stored before Phase F2.1 has `level = NULL` and is treated exactly as it always was.

## The authoritative-engine list - what it is and what it is not
Google Safebrowsing, Kaspersky, BitDefender, ESET, Sophos, Fortinet, Avira, Forcepoint ThreatSeeker, Spamhaus, OpenPhish, Phishtank (in `services/evidence.py`).
* It is a **judgement** about VirusTotal engines that curate their own lists or are long established. It is not a measure of accuracy: every one of them has produced false positives.
* A vendor's name is **never proof**. One authoritative engine alone is still only a WEAK finding. The list lowers a corroboration threshold by exactly one engine (CREDIBLE at
  two engines instead of three, CONFIRMED at three instead of four); confirmation always needs at least three agreeing engines. Only *malicious* verdicts count for authority; a
  *suspicious* verdict from an authoritative engine does not.
* It needs **maintenance**: VirusTotal renames and adds engines, so entries can silently stop matching (the effect is only that the stricter, non-authoritative thresholds apply).
* No domain is treated specially. A popular site is judged by the same numbers as any other.

## Limitations of the thresholds
* Engine counts are **correlated**, not independent: several products share a detection back end, so "3 engines" can be one underlying signal.
* The numbers are a trade-off, not a truth. Three agreeing non-authoritative engines still raise a MEDIUM alert for a legitimate site, and two non-authoritative engines alone do not.
* VirusTotal's counts change over time and are cached for hours (6 hours for SUSPICIOUS/MALICIOUS, 24 hours for SAFE).
* Only VirusTotal exists today. The record format (`services/evidence.py`) is provider-neutral so later providers can report their own classification, strength and detections; a
  provider that only gives context can never reach CREDIBLE on its own.

## Expected impact (isolated fixtures)
| Evidence | legacy | evidence policy |
|---|---|---|
| 1 of 92 engines (the `login.microsoftonline.com` pattern) | SUSPICIOUS, MEDIUM alert | WEAK, no alert |
| 2 non-authoritative engines | SUSPICIOUS, MEDIUM alert | WEAK, no alert |
| 3 non-authoritative engines | MALICIOUS, HIGH alert | CREDIBLE, MEDIUM alert |
| 3 engines including an authoritative one | MALICIOUS, HIGH alert | CONFIRMED, HIGH alert |
| 4 or more engines | MALICIOUS, HIGH alert | CONFIRMED, HIGH alert |

## Counting one real visit once (Phase F2 / F2.1)
The browser extension and the Windows Agent's browser-history collector can both report the same navigation. For the alert exposure count the two reports are ONE visit when they are
from the same device (the device each event was stored with), domain and browser, from different sources, **at most 15 seconds apart by event time**, and (when both carry a page
address) the same address. The match is one-to-one, the nearest wins, and if the runner-up is within 2 seconds of the best candidate nothing is merged. Both reports are always kept
as evidence (the second is linked to the first in `alert_events.corroborates_event_id`); only the count differs. Worse evidence from the second report still escalates the alert, and
is never hidden behind a handled alert.

Why 15 seconds: on the real database 16 of the 20 extension/history pairs on one computer, domain and browser had identical timestamps and 18 of 20 were within 15 seconds; the others
(30 s, 110 s, 10 minutes) are as likely to be separate visits. The dashboard's display rule (120 s) is wider on purpose: showing two records on one row is harmless, counting two visits
as one exposure is not. Existing events and counts are never rewritten.

## Request budget (Phase F2.1)
VirusTotal requests are counted in one thread-safe budget for all sources (`VT_MAX_PER_MINUTE`, default 3, and `VT_MAX_PER_DAY`, default 450; the free key allows 4 and 500). No single
source may take the last slot of the minute or more than three quarters of the day, so neither the extension nor the agent can starve the other. Two simultaneous requests for one new
domain make one provider call. A request over the budget is answered "not checked yet" (never cached, never safe, no alert) and repeated later. A 429 puts the provider in cooldown for
its Retry-After time (1 to 60 minutes; 15 minutes without the header).
