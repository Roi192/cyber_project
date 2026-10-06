# Suricata checksum investigation (A3 / second-vantage 3C) - evidence manifest

Status: MANIFEST ONLY. This file records the identity of the evidence. It contains no findings, no
classification and no conclusions; those belong in the separate closure record.
Prepared in checkpoint 14C-A-CLOSE-2 from the read-only Windows-side inventory of 14C-A-CLOSE-1 (2026-09-22).
Nothing listed here has been altered, moved, renamed or deleted. No evidence cleanup has been performed.

## 1. Conventions

- **Raw SHA-256** is the hash of the file bytes exactly as stored on that machine.
- **Normalised SHA-256** (scripts only) is the hash after converting CRLF to LF and stripping trailing
  newlines. It identifies the method independently of line endings. The Windows copies of the scripts were
  written with `Set-Content`, which changes line endings, so raw hashes differ between copies while the
  normalised hash is identical. The normalised hash is the method identity; the raw hash is the file identity.
- **Verification status** is one of:
  - `verified 14C-A-CLOSE-1` : hashed on the Windows host during 14C-A-CLOSE-1 and, where a value had been
    recorded earlier, equal to it.
  - `first recorded` : first hash on record for this file; no earlier value existed to compare with.
  - `as previously recorded` : Kali-resident; value comes from an earlier step and was NOT re-verified during
    14C-A-CLOSE (Kali was deliberately not touched).
- "not recorded" means the value was never captured. It is not estimated and was not filled in by touching Kali.
- Timestamps are never used as packet identity anywhere in this investigation (the Kali clock is
  unsynchronised). File modification times are deliberately omitted from this manifest.
- Packet captures were filtered to the SOC host and one external server (46.101.206.53:443) and contain
  TLS ciphertext plus header metadata. No payload was printed, logged or stored outside the pcaps.

## 2. Evidence classes

| Class | Meaning |
|---|---|
| A. Experimental evidence | Packet captures taken for the experiment |
| B. Derived metadata | Per-packet metadata tables extracted from A |
| C. Analysis output | Recorded output of the comparison |
| D. Scripts / method artifacts | Code that produced B and C |
| E. Excluded evidence | Preserved but not used in the pre-registered comparison |

## 3. Manifest

### A. Experimental evidence (packet captures)

| File | Location | Role | Bytes | SHA-256 (raw) | Verification status |
|---|---|---|---|---|---|
| win2.pcap | Windows: %USERPROFILE%\a3b_win\ | Windows-side capture, second-vantage experiment (dumpcap, interface 4 = Wi-Fi) | 294,344 | 4FD374CD3D7CC6C2EEF70D9113A47FF606BD7386EF238EA7BB3D26C8DECA5977 | verified 14C-A-CLOSE-1 (equals value recorded in 3A) |
| kali2.pcap | Kali: /tmp/a3b.hYKLeC/ | Kali-side capture, second-vantage experiment (eth1) | not recorded | 18f5546b8a97762b1450b0649935954a6e09d13379881471b8c6d6528378d3df | Kali-resident; hash as previously recorded; not re-verified during 14C-A-CLOSE |
| a3.pcap | Kali: /tmp/a3.hWsmUx/ | A3 offline-analysis capture (preserved; original A3 evidence) | not recorded | c048b7ef6a1265843305cd4814d66d02efe90bc6682abf563d697f470478cca9 | Kali-resident; hash as previously recorded; not re-verified during 14C-A-CLOSE |

### B. Derived metadata (per-packet tables; metadata and payload digests only, no payload)

| File | Location | Role | Bytes | SHA-256 (raw) | Verification status |
|---|---|---|---|---|---|
| win2_records.tsv | Windows: %USERPROFILE%\a3b_win\ | Extract of win2.pcap | 60,239 | 599AEDB077C05323B3FEEB9DEA03F3ED4681F68A3EB0F1F0D45277267F84A5D5 | verified 14C-A-CLOSE-1 (equals value recorded in 3A) |
| kali2_records.tsv (Windows copy) | Windows: %USERPROFILE%\a3b_win\ | Extract of kali2.pcap, pulled to Windows in 3C-2 | 61,698 | DE49E1974C6D1BA8C846C6696BD23EDDB2DE495A68F6569BF2FDDFD83CE69422 | verified 14C-A-CLOSE-1; hash-equal to the Kali original as verified in 3C-2 |
| kali2_records.tsv (Kali original) | Kali: /tmp/a3b.hYKLeC/ (mode 0600, root) | Original of the row above | equal to the Windows copy (hash-equal) | same as the Windows copy | Kali-resident; hash as previously recorded; not re-verified during 14C-A-CLOSE |
| kali2_records.tsv (Kali-home duplicate) | Kali: home directory of the operator account | Transfer copy created during 3C-1/3C-2; not independently retained as experimental input | not recorded | no separate hash recorded in this manifest | not re-verified during 14C-A-CLOSE |

### C. Analysis output

| File | Location | Role | Bytes | SHA-256 (raw) | Verification status |
|---|---|---|---|---|---|
| 3C3_compare_output.txt | Windows: %USERPROFILE%\a3b_win\ | Saved terminal output of the STEP 3C-3 comparison (metadata and truncated digests only) | 13,986 | E58F843D84B72A982E1DC4A58C369B124CAFCD5D983EF41B6B7E7B208E779975 | first recorded (14C-A-CLOSE-1) |

### D. Scripts / method artifacts

The normalised SHA-256 is the method identity. Copies in the session scratchpad are labelled
"non-retained authoring copy / session-temporary artifact": their continued physical availability is NOT part
of any evidence-retention guarantee. The copies in a3b_win are the locally preserved script artifacts where
applicable (as of 14C-A-CLOSE-1); final retention is decided at the later evidence-retention checkpoint.

| Script | Location | Role | Bytes | SHA-256 raw | SHA-256 normalised (method identity) | Verification status |
|---|---|---|---|---|---|---|
| xv_extract.py | Windows: %USERPROFILE%\a3b_win\ | Extractor, run on both machines (3A, 3B); locally preserved copy | 6,164 | 74E5BF122C3B7F2ACF5C160AAD01769186BA74043B387BE64E9F76713F888829 | 3e69f55df338e616904ef210875048ebca756daa99fa2fc754ffee48f494e39f | verified 14C-A-CLOSE-1 |
| xv_extract.py | session scratchpad | Same script; non-retained authoring copy / session-temporary artifact | not recorded | EE40E88778CBC6FB2AC31FA0F79846CE0CB06013F9B0747C0EAB67FAFA3DC76C | 3e69f55df338e616904ef210875048ebca756daa99fa2fc754ffee48f494e39f | verified 14C-A-CLOSE-1 |
| xv_compare.py | Windows: %USERPROFILE%\a3b_win\ | Comparison script, STEP 3C-3; locally preserved copy | 16,144 | DAC6B5F03BAF16593BD84F9A60071706A7D290A7F1E4DFAE94C14DB75686BAEA | 6bfd18f6817050a8e82180c1e31e01c62e7025c46c75ff84de0dfd773c25ea65 | verified 14C-A-CLOSE-1 |
| xv_compare.py | session scratchpad | Same script; non-retained authoring copy / session-temporary artifact | not recorded | 019F6CE8A2A39FB8A53A60EBA908128E5B81DF13943C4E6084BD0A9EA4A6A40A | 6bfd18f6817050a8e82180c1e31e01c62e7025c46c75ff84de0dfd773c25ea65 | verified 14C-A-CLOSE-1 |
| a3_step3.py | session scratchpad (outside a3b_win) | Existing-pcap analysis of the A3 capture (Step 3); non-retained authoring copy / session-temporary artifact | not recorded | DA8661198149C0C50CEF34B9741FA6AC1608ECD1B3BA9D84D510751A9863971E | 3431db771d82ebcbeaf610ba8f47bf7a27be46cd2f222d6b2682fddc8a84ec1a | first recorded (14C-A-CLOSE-1) |

a3_step3.py: it is currently ONLY a session-temporary method artifact. Its normalised method hash is recorded
above. Physical preservation has NOT yet been decided; that decision belongs to the later evidence-retention
checkpoint. It has not been copied anywhere.

### E. Excluded evidence

| File | Location | Role | Bytes | SHA-256 (raw) | Status |
|---|---|---|---|---|---|
| win.pcap | Windows: %USERPROFILE%\a3b_win\ | Earlier non-simultaneous Windows capture | 256,687 | 618021FAA9B686E16BF1759F825FD140242F72DD630E701E7E29C62268CC8968 | excluded from 3C-3, preserved; first verified 2026-09-22 |
| kali.pcap | Kali: /tmp/a3b.hYKLeC/ | Earlier non-simultaneous Kali capture | not recorded | not recorded in the retained checkpoint record | excluded from 3C-3; preserved as previously recorded; not re-verified during 14C-A-CLOSE |

## 4. Known gaps

1. Sizes of kali2.pcap, a3.pcap and kali.pcap were never recorded and are not invented here. A read-only
   size check on Kali would need separate operator approval.
2. Kali-resident items are not re-verified in 14C-A-CLOSE (Kali was deliberately not touched).
3. The scratchpad copies of the scripts and a3_step3.py are non-retained, session-temporary artifacts,
   outside the repository and outside a3b_win. Physical preservation of a3_step3.py is undecided.
4. The SHA-256 of kali.pcap is not recorded in the retained checkpoint record.
5. No hash is recorded for the Kali-home duplicate of kali2_records.tsv.

## 5. Handling

- All items above are preserved unchanged. This manifest authorises no deletion, move or rename.
- Evidence retention and cleanup (including the pcaps, which hold TLS ciphertext) require a separate,
  explicit approval after the closure record is written.
- Nothing in this manifest is a finding. Interpretation, the formal outcome and limits are in the
  closure record.
