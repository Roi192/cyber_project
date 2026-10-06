# Suricata checksum investigation (A3 / second-vantage 3C) - closure record

Status: CLOSED for the current project phase (2026-09-22). Formal result: Outcome E. Root cause: UNRESOLVED.
Evidence inventory: `docs/SURICATA_CHECKSUM_EVIDENCE_MANIFEST.md` (see section 11). This record is separate from it.

## 1. Scope and purpose

This record closes the A3 / second-vantage 3C investigation of the Suricata TCP invalid-checksum detections
(sid 2200074 TCPv4, sid 2200077 TCPv6) in Phase 14C workstream A. It records the pre-registered result, a separate
descriptive finding, what is and is not known, and how the detections are handled from here.
It does NOT claim that the root cause has been found, and it does NOT attribute the cause to any component.

## 2. Experiment and pre-registration

- Question: is the stored TCP checksum of the affected server-to-client segments already `0x0000` at a second
  vantage point (the Windows host, upstream of the Kali sensor), or first appears on the Kali/Suricata path?
- Traffic: TCP between the SOC host and 46.101.206.53:443, captured passively and simultaneously on Kali
  (`eth1`, emulated e1000 NIC, VirtualBox bridged) and on the Windows host (dumpcap, Wi-Fi adapter).
  Capture counters as recorded: Windows 554 packets, 0 dropped; Kali 577 captured, 593 received by filter,
  0 dropped by kernel. The 16-packet difference between "received by filter" and "captured" was not analysed
  separately; gate 1 is evaluated on the drop counters.
- The earlier non-simultaneous captures were never mixed into the experiment.
- Method rules fixed before the comparison: no timestamp-based matching (the Kali clock is unsynchronised);
  the classifying gate uses strict 1:1 identity only (client port + TCP sequence + payload length + payload
  digest); overlap is determined from TCP sequence / logical byte ranges; Windows coalescing/resegmentation is
  accounted for in a supplementary logical-byte analysis that is kept separate from the classifying gate;
  output is metadata and digests only, never payload; read-only analysis; input files hash-verified before and
  after (all unchanged).
- Pre-registered outcomes:
  - A: Windows copy valid/non-zero while Kali is `0x0000` (a change after the Windows capture point).
  - A': Windows non-zero but invalid, Kali `0x0000` (two alterations at two points).
  - B: both `0x0000` (the zero exists at or before the Windows capture point).
  - C: Windows `0x0000`, Kali differs.
  - D: mixed.
  - E: a validity gate fails. The Windows coalescing case is E with an annotation.
- Stated in advance as out of reach even for a successful second vantage: identifying the responsible
  component (two NDIS filters, Npcap and the VirtualBox bridge, are bound to the same adapter in unknown
  order), the truth on the physical wire, why one specific packet is affected, and any safety verdict.

## 3. Formal experimental result

**Outcome E - formally inconclusive under the pre-registered classification gates.**
The experiment is not relabelled A, A', B, C or D.

| Gate | Result | Requirement / observation |
|---|---|---|
| 1 | PASS | Zero packet drops on both sides |
| 2 | PASS | Full-length captures |
| 3 | **FAIL** | Required >= 10 strictly matched target 606-byte [P.] stored-0x0000 segments; observed 9 |
| 4 | PASS | Strict 1:1 match >= 95% of the Kali overlap population; observed 78/78 = 100.0% |
| 5 | PASS | Positive control: 17 target stored-0x0000 segments and 0 invalid client->server |
| 6 | **FAIL** | Negative control required >= 99% independently-valid non-target server->client traffic on BOTH vantage points. Observed: Kali overlap 69/69 = 100.0%; Windows overlap 69/76 = 90.8%; Kali shared flows 128/128 = 100.0%; Windows shared flows 127/139 = 91.4% |
| 7 | PASS | Identical analysis method |
| 8 | PASS | Windows capture-interface evidence |

ALL GATES PASS: False.

Notes on the table: gates 1 and 7 are recorded constants (capture drop counters and the method hash verified
in steps 3A/3B), not computed by the comparison script. Gate 8 is evidenced by the Step 0 adapter/interface
match and by the shared flows with identical digests (MAC labels were not extracted). The thresholds were
fixed before the run and are not modified here.

## 4. Descriptive cross-vantage finding (separate from the formal classification)

- 78/78 Kali overlap data segments (of 163 Kali server->client data segments; Windows overlap 85 of 175) had an
  exact Windows identity match using client port + TCP sequence + payload length + payload digest.
  0 same-key/different-digest mismatches. Reverse view (informational): 78/85 = 91.8% of Windows overlap segments.
- 69/69 Kali-valid strict pairs were valid at Windows.
- 9/9 comparable Kali stored-0x0000 target segments (nine distinct flows, one segment each) were also
  stored-0x0000 at the Windows capture point. 0 matched cases where Kali stored 0x0000 but Windows had a valid
  checksum.
- Metadata identical across all 78 pairs: TTL, IP ID, DF, TCP window, IP length, frame length, TOS.
- Client->server: Kali 290/290 valid; Windows 266/266 valid.
- Supplementary logical-byte matching (exploratory; not used by any gate): 78 exact 1:1, logical bytes
  identical 78/78; it adds nothing beyond the strict result.
- Kali reproduced 17 stored-0x0000 server->client data segments in total. 9 were in the shared overlap. The
  other 8 belong to flows that are not present in the Windows capture and cannot be compared.

**This descriptive result does NOT convert Outcome E into formal Outcome B.**

## 5. Proven / strongly supported / unknown

**PROVEN (directly measured; inputs hash-verified before and after):**
- The counts, matches and status pairs in section 4.
- Windows and Kali capture counters and full-length capture as recorded in section 2.
- Flow inventory: Kali 27 flows with server data, Windows 25, shared 13, Kali-only 14, Windows-only 12.
- The Windows-side structure in section 6.
- No Kali server->client data segment lies fully inside any of the 21 Windows >MTU frames (0 of 21).
- Gates 3 and 6 failed as registered.

**STRONGLY SUPPORTED:**
- For the nine directly comparable affected packets, the stored zero was already observable in the Windows capture
  representation, so it was not first introduced by the downstream Kali/Suricata observation path. This is a
  statement about where the zero is already present, based on nine packets. It does not identify the component
  that created it.

**UNKNOWN:**
- The exact component or mechanism responsible.
- Whether the zero existed on the physical wire.
- Whether the two Windows zero-checksum classes (section 6) share a cause.
- The behaviour of the eight Kali zero segments whose flows are absent from the Windows capture.
- The exact checksum representation the Windows TCP stack received.
- Whether the bytes carried by the Windows >MTU frames appear in Kali's capture in any form (0 Kali segments are
  fully contained in them; not analysed further).
- Any attack or tampering attribution. None is made and none is excluded.

## 6. Windows >MTU observation

- Windows server->client data segments: 175. Stored 0x0000: 40. 606-byte [P.] stored 0x0000: 19.
  IP length > 1500: 21, and all 21 stored 0x0000. The remaining 135 (IP length <= 1500, other lengths) are valid.
- No Windows 0x0000 frame fell outside those two observed classes (>MTU, and 606-byte [P.]).
- Wording: the >MTU Windows capture frames are evidence of host-side aggregation/resegmentation in or before the
  Windows capture representation, but they do not identify the responsible mechanism or component.
- The 606-byte [P.] zero frames have IP length <= 1500. Nothing in this record shows that the two classes share a
  mechanism.
- No component (RSC, checksum offload, Npcap, VirtualBox, the Wi-Fi driver, Windows TCP/IP, other host software)
  is proven responsible. Some of these were recorded as present on the host; presence is not attribution.

## 7. Interpretation of the gate failures

- Gate 3: a sample-size gate that failed by one target pair (9 against 10). The nine observed pairs remain valid
  observations; the registered threshold was not met and is not reinterpreted.
- Gate 6: the registered assumption that Windows non-target server->client traffic would be >=99% valid did not
  hold. Observed Windows validity was 69/76 = 90.8% in the overlap and 127/139 = 91.4% across shared flows.
  Separately, the Windows-side structure contains a population of 21 >MTU stored-0x0000 data frames. This
  investigation did not perform a packet-by-packet attribution of the gate-6 failures to that population, so no
  stronger claim is made. The threshold is not modified or retrospectively reinterpreted.
- Both failures block formal A-D classification. They do not erase the directly observed strict-pair
  measurements.

## 8. Operational handling rule

For sid 2200074 and sid 2200077:
- They remain stored as detections; no stored row is deleted, changed or hidden.
- They are sensor/engine-quality diagnostics, not independently a threat verdict, and are not labelled benign.
- They are not suppressed, and Suricata checksum validation remains enabled.
- They must not independently increase correlation, risk, severity or automated response.
- A display-only "Suricata engine event" annotation is approved in principle (presentation only; no schema or
  stored-event change; no severity/risk/decision change; no correlation weighting; no alert-generation change; no
  suppression; no change to raw evidence or Suricata configuration). It is NOT implemented by this record.

Inspection limitation (conservative): checksum-invalid traffic may affect downstream stream inspection or coverage
depending on the effective Suricata configuration and processing behaviour. The actual coverage impact on this
sensor was not measured in this investigation, so it remains an operational limitation rather than a measured
result.

## 9. Re-open triggers

Re-open the checksum/root-cause investigation only if:
- these engine/checksum sids begin affecting correlation, severity, risk or automated response;
- affected-flow inspection coverage becomes material to system correctness;
- the sensor or network topology changes in a way that invalidates this evidence;
- new evidence contradicts the recorded cross-vantage observation.

## 10. Closure decision

- The A3/3C root-cause investigation is CLOSED for the current project phase.
- The formal classification remains Outcome E.
- The root cause remains unresolved.
- No A4 or additional capture is required to continue Phase 14C.

## 11. Evidence reference

- Evidence inventory: `docs/SURICATA_CHECKSUM_EVIDENCE_MANIFEST.md`, checkpoint SHA-256
  `1C47EE813ECE1ED32392A074C3A24D2E652F306282F294BCC3E6381CE21B0CD3`.
- The manifest is the evidence inventory; hashes are not repeated here.
- `3C3_compare_output.txt` (the source of the figures in sections 3-7) is UTF-16LE with a byte-order mark, as
  written by PowerShell `Tee-Object`. This is file-encoding metadata only and does not affect interpretation.
