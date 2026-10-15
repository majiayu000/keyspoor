# Independent synthetic evaluation, 2026-10-15

The first run detected 28 of 48 positive samples, missed 20, and flagged 4 of
40 negative samples: precision **87.5%**, recall **58.33%**. All 88 files were
scanned, with no skipped files or acquisition errors. These are sample-level
counts, not production accuracy or provider credential validation.

An independent agent wrote the synthetic corpus without reading Keyspoor's
implementation, rules, or earlier benchmarks. Labels describe secret semantics,
not only currently supported provider formats. No credentials were issued by a
provider. This is an agent-authored holdout, not a human or production study.
The first run used `3dbb94c9335a603fbaa3d0a66dcd2a7e50e8899f`; the corpus was
frozen before running the scanner. Now that the samples have been inspected,
future runs are **regressions**, not new blind tests.

Corpus SHA-256:
`b300e94e5d9caf1ab15c5fc90a66587139df78fb7d1c7852a793d77841d00dd6`.

| Positive category | Detected | Missed |
|---|---:|---:|
| Password | 7 | 5 |
| Connection string | 5 | 3 |
| Authentication token | 8 | 4 |
| Signing or encryption key | 5 | 3 |
| Session cookie | 1 | 3 |
| Credential pair | 2 | 2 |

Three false positives were placeholders or references; one was a checksum.
The exposed-corpus rerun after the Rust declaration correction below has the
same counts. Do not infer a general safety guarantee from this small corpus.

## Reproduce

From the repository root, using Rust 1.96 or newer:

```sh
cargo build --release --locked
python3 bench/independent/evaluate.py target/release/keyspoor
```

The script materializes only each sample's content into a temporary directory.
Labels and rationales remain outside the scanned scope. It requires complete
88-file coverage before reporting counts and prints only classifications and
sample IDs, never matched values. This complements the existing benchmarks;
it does not replace their workloads or change thresholds to fit these labels.

## Initial review cost and daily baseline workflow

A frozen public `litellm-rs/src` subtree had 1,336 files / 15,210,726 bytes.
The original scanner reported 295 locations with 214 distinct fingerprints.
Conservative source inspection confirmed at least 30 public Rust field type
declarations among those findings; the rest were not all labeled. A minimal
example is `pub access_token: String,`, where `String` was reported as a secret.
The correction excludes this unquoted public-field syntax in `.rs` files;
it does not globally allowlist `String` or suppress other assignments on the
same line. The engine configuration digest changes, so an old baseline must
not silently suppress findings under the revised detection policy.
An independent rescan of the same frozen source content reduced 295 findings
to 261: all 30 originally confirmed declarations and four additional public
field declarations disappeared, with no newly reported locations. This is a
targeted correction, not a precision estimate for the remaining 261 findings.

With the original scanner, a baseline workflow over that complete source
subtree produced **295 → 0 → 1 → 0** findings: initial scan, unchanged scan,
one newly added synthetic credential, then its removal. Each scan took
0.187–0.211 seconds on one macOS arm64 machine, including process startup and
JSON output. These single runs are observations, not isolated performance
benchmarks. Adding every existing finding to a baseline here tested the
mechanism; it was not a security approval of those findings.

Full-repository scans of palim and litellm-rs encountered archive expansion
budgets and were incomplete. They were not used as complete quality scores or
to create baselines. An rui snapshot scan was complete with zero findings;
without labels this does not establish recall or absence of secrets.

The initial review queue still costs human attention. No human review duration,
weekly retention, or production benefit was measured; those require actual
users and repeated observations.
