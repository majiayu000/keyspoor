# v6: share finding paths and explanations

Baseline: v5 / `3b28f5c`, SHA-256 `aca1a038f1faaf485e054dc7e208ce49027624fd63542019afe8b29e8a3412e5`. Candidate SHA-256 `94e3b936287ec45e44f37e596e67553d7a4762f5f287e78fa2a0a04391d7938a`. [Manifest and commands](manifest.json).

## Implementation and API impact

Only Finding.path and Finding.explanation change from String to Arc<str>. Allocate a shared path at the first finding in a scan; later raw/Base64 views reuse it. Each compiled rule lazily caches four explanation variants covering plain, Base64, UTF-16 and both. The cache contains rule metadata and encoding annotations, not raw secrets or input buffers. Empty-result scans do not allocate a new path. All other Finding fields remain unchanged.

**Breaking Rust API change:** assign owned strings with `.into()`, read `&str` with `.as_ref()`, and replace the field instead of using String mutation methods. JSON still contains the same strings, and scan context/fingerprint/configuration identity are unchanged. v5 JSON baselines remain comparable under the same scope. Deserialization does not intern duplicate strings. Git history projection still constructs each commit-prefixed display path; this patch does not introduce a Git path cache.

## Allocation evidence

[Probe source](allocation_probe.rs), [build/run driver](allocation_probe.py), [before](allocation-before.json), [after](allocation-after.json). A standalone single-thread GlobalAlloc wrapper delegates unchanged pointer/layout operations to System. Warm one exact-workload scan before measuring; exclude Engine/input construction, warmed caches, output serialization and validation. Counters perturb timing and are never used for latency claims. Values below are requested allocation-layout bytes, not RSS or allocator usable size; realloc internals are not observable. All four cases return to their pre-scan live-byte baseline after results are dropped.

| Case | Allocation calls before → after | Reallocation calls before → after | Live bytes at return before → after | Peak incremental live bytes before → after |
|---|---:|---:|---:|---:|
| utf8, 1 findings | 18 → 17 | 4 → 2 | 1,387 → 1,008 | 1,663 → 1,284 |
| utf8, 10,000 findings | 120,007 → 100,008 | 20,014 → 14 | 8,391,088 → 4,578,984 | 10,711,107 → 6,739,003 |
| utf8, 100,000 findings | 1,200,007 → 1,000,008 | 200,017 → 17 | 76,308,704 → 38,711,592 | 87,908,723 → 49,511,611 |
| utf16le, 10,000 findings | 120,008 → 100,009 | 20,030 → 30 | 8,391,088 → 4,578,984 | 11,235,395 → 7,263,291 |

Finding inline size is 232 → 216 bytes on this target. At 100,000 results, return-time live bytes fall 49.27%, allocation calls fall 16.67%, and repeated formatting growth is eliminated (200,017 → 17 reallocations). The complete serialized Finding output hashes and lengths are identical in every before/after probe case. Cache storage is retained by Engine and excluded from the warmed scan delta; this is not a cold-process memory measurement.

## Process measurements

All CLI measurements below use the ordinary release binaries without allocator instrumentation, after builds stopped. Each case has 20 alternating before/after pairs on Apple M2 Max/macOS with uncontrolled warm filesystem cache. RSS is the scanner process wait4 peak, not aggregate process-tree memory. Shared-machine scheduling remains a source of variance; no universal speedup claim.

| Stress case | Wall median ms before → after | CPU user+system median ms before → after | First finding ms before → after | RSS median MiB before → after |
|---|---:|---:|---:|---:|
| densefindings_10000 | 172.87 → 169.93 | 57.68 → 55.02 | 53.22 → 51.07 | 28.80 → 24.77 |
| densefindings_100000 | 1428.91 → 1400.20 | 287.37 → 262.26 | 229.28 → 209.81 | 99.86 → 59.59 |
| newline_dense_16mib | 73.58 → 73.67 | 70.57 → 70.67 | 71.66 → 71.80 | 37.09 → 37.25 |
| manyfiles_10000 | 159.39 → 158.25 | 565.64 → 560.50 | 34.33 → 34.14 | 20.13 → 20.32 |
| git_fixedblobs_1commits | 90.39 → 90.35 | 79.22 → 79.18 | 88.23 → 88.20 | 18.52 → 18.80 |
| git_fixedblobs_200commits | 90.45 → 89.78 | 78.82 → 78.73 | 87.94 → 87.29 | 18.69 → 18.97 |

The 100,000-result JSONL workload reduces RSS 40.33%, scanner CPU 8.74% (19/20 paired reductions), and first-result median 8.49%. Consumer-inclusive wall time falls only 2.01%; the 51,235,415-byte output payload is unchanged. Other stress cases are broadly flat; sparse/Git RSS medians are slightly higher, so this is not a reduction in every workload. File-level buffering remains. [Dense raw runs](stress-dense.json), [files/Git raw runs](stress-files-git.json).

**Parallel dense check:** [16 files × 6,250 findings, four workers](parallel-dense.json), [reproduction driver](parallel-dense.py). JSON goes to temporary files and parsing/complete-Finding verification occurs after timing. Wall median 368.22 → 341.22 ms (-7.33%, 19/20 pairs lower), CPU 641.69 → 586.83 ms (-8.55%, 20/20 lower), RSS 118.85 → 76.38 MiB (-35.74%, 20/20 lower). No shared-reference contention regression was observed in this fixture; this does not prove all parallel workloads improve.

| Regular CLI dataset | Wall median ms before → after | CPU user+system median ms before → after |
|---|---:|---:|
| throughput-16mib | 58.52 → 57.85 | 124.33 → 124.03 |
| throughput-128mib | 219.51 → 218.54 | 758.24 → 758.02 |
| real-regex | 75.93 → 76.38 | 201.18 → 203.37 |

Regular throughput/real-source workloads are essentially unchanged. [20-pair raw evidence](paired-throughput.json), [driver](paired-throughput.py). Do not substitute historical timings for these contemporaneous baselines.

## Quality and checks

- Both previously observed synthetic regression corpora retain 600 TP / 25 FP / 0 FN. Original regression remains 34 / 0 / 0; capability labels remain 6 / 0 / 0. The 25 ambiguous description alerts remain; this iteration changes storage, not detection coverage.
- [Complete contract comparison](contract-parity.json) verifies every Finding field and ScanContext on all four corpora, beyond location-only scoring. Parallel dense and allocation probes also compare full serialized findings. All matched, including fingerprints and explanations.
- Six stress cases × 20 pairs = 240 measured runs with exact source-coordinate/rule parity. Stress raw metadata inherits a historical reason for excluding fingerprints; that reason does not apply to v5/v6. The separate full-contract comparisons verify unchanged fingerprints explicitly.
- 117 Rust tests and 59 Python tests passed; fmt, Clippy with denied warnings, release, Rust 1.96.1 and final .crate independent-consumer checks passed. Doc tests completed with zero examples. New tests cover actual Arc sharing, all four annotation variants, different paths/fingerprints and JSON roundtrip.
- Independent code/allocator review found no blocking defects. Linux/Windows CI was not run; nothing published or pushed. Competitors were not rerun for this storage-only change; [v4 comparator results](../v4/quality-comparison.md) retain their own provenance.

[v3 regression](quality-regression.json), [v2 regression](previous-quality.json), [original/capability regression](original-regression.json). These are observed synthetic regression sets, not new holdouts or real-world precision estimates.

## Reproduce

Preserve the old binary, fixed corpora and original artifacts; use new output paths. Allocation comparison requires compiling the probe against each corresponding release library, or rerunning its frozen executable/provenance with --run-only. The driver resolves exact dependency artifacts from Cargo JSON, including fresh cached builds.

The current allocation driver builds the renamed `keyspoor` crate. Its output
measures the current checkout and does not reproduce the historical v6 binary
by itself. To rebuild the historical `secret_scan` probe, use the source and
driver from that recorded revision; to rerun a preserved probe, use `--run-only`
with its original executable and provenance. The paired CLI drivers below still
use the preserved `secret-scan` binaries whose hashes are recorded in
`manifest.json`; `cargo build --release` now produces `target/release/keyspoor`
and does not rebuild or replace those historical executables.

```sh
python3 bench/results/v6/allocation_probe.py --label reproduced --binary /tmp/v6-probe-new --output /tmp/v6-alloc-new.json
python3 bench/results/v6/paired-throughput.py /tmp/v6-throughput-new.json
python3 bench/results/v6/parallel-dense.py /tmp/v6-parallel-new.json
python3 scripts/stress_benchmark.py --before bench/tools/secret-scan-v5-aca1a038 --after target/release/secret-scan --repeats 20 --cases dense --output /tmp/v6-dense-new.json
python3 scripts/stress_benchmark.py --before bench/tools/secret-scan-v5-aca1a038 --after target/release/secret-scan --repeats 20 --cases newline manyfiles git --output /tmp/v6-files-new.json
```
