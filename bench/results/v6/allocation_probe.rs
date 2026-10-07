//! Single-thread, warmed scan allocation probe. Build with allocation_probe.py.
//! Counters track requested allocator layouts, not RSS or allocator usable size.
use keyspoor::{Engine, EngineConfig, Finding};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

struct CountingAllocator;

static ENABLED: AtomicBool = AtomicBool::new(false);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_BYTES: AtomicUsize = AtomicUsize::new(0);
static REALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static REALLOCATION_REQUEST_BYTES: AtomicUsize = AtomicUsize::new(0);
static DEALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

fn add_live(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
    if ENABLED.load(Relaxed) {
        PEAK.fetch_max(live, Relaxed);
    }
}

// SAFETY: all pointer operations are delegated to System with unchanged layouts.
// Counter operations use atomics only and cannot reenter the allocator. LIVE is
// maintained even outside measurement so freeing an older allocation is valid.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            add_live(layout.size());
            if ENABLED.load(Relaxed) {
                ALLOCATIONS.fetch_add(1, Relaxed);
                ALLOCATION_BYTES.fetch_add(layout.size(), Relaxed);
            }
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            add_live(layout.size());
            if ENABLED.load(Relaxed) {
                ALLOCATIONS.fetch_add(1, Relaxed);
                ALLOCATION_BYTES.fetch_add(layout.size(), Relaxed);
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
        if ENABLED.load(Relaxed) {
            DEALLOCATIONS.fetch_add(1, Relaxed);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !ptr.is_null() {
            if new_size >= layout.size() {
                add_live(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
            if ENABLED.load(Relaxed) {
                REALLOCATIONS.fetch_add(1, Relaxed);
                REALLOCATION_REQUEST_BYTES.fetch_add(new_size, Relaxed);
            }
        }
        ptr
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let count: usize = args
        .get(1)
        .ok_or("usage: allocation_probe COUNT utf8|utf16le")?
        .parse()?;
    let encoding = args.get(2).ok_or("missing encoding")?;
    if !matches!(encoding.as_str(), "utf8" | "utf16le") {
        return Err("encoding must be utf8 or utf16le".into());
    }
    // Intentionally generated, non-live test token, never printed by this probe.
    let mut token = String::from("ghp_");
    let mut state = 0x192a_531f_u32;
    for _ in 0..36 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        token.push(b"0123456789abcdef"[(state >> 16 & 15) as usize] as char);
    }
    let line = format!("{token}\n");
    let input = line.repeat(count);
    let bytes: Vec<u8> = if encoding == "utf16le" {
        [0xff, 0xfe]
            .into_iter()
            .chain(input.encode_utf16().flat_map(u16::to_le_bytes))
            .collect()
    } else {
        input.into_bytes()
    };
    let engine = Engine::new(EngineConfig::default())?;
    // Warm lazy regex caches with the exact workload, excluding engine/input
    // construction and cache initialization from this result-allocation probe.
    let warmup = engine.scan_bytes("synthetic/dense.txt", &bytes)?;
    assert_eq!(warmup.len(), count);
    drop(warmup);

    let baseline = LIVE.load(Relaxed);
    PEAK.store(baseline, Relaxed);
    ENABLED.store(true, Relaxed);
    let scan = engine.scan_bytes("synthetic/dense.txt", &bytes);
    ENABLED.store(false, Relaxed);
    let findings = scan?;
    let scan_live = LIVE.load(Relaxed);
    let peak = PEAK.load(Relaxed);
    let allocations = ALLOCATIONS.load(Relaxed);
    let allocation_bytes = ALLOCATION_BYTES.load(Relaxed);
    let reallocations = REALLOCATIONS.load(Relaxed);
    let reallocation_request_bytes = REALLOCATION_REQUEST_BYTES.load(Relaxed);
    let deallocations = DEALLOCATIONS.load(Relaxed);

    assert_eq!(findings.len(), count);
    assert!(
        findings
            .iter()
            .all(|finding| finding.redacted == "[REDACTED]" && finding.rule_id == "github-pat")
    );
    // Validation/serialization are outside the counted scan, and dropped before
    // the final live snapshot. The output hash compares full public semantics.
    let serialized = serde_json::to_vec(&findings)?;
    assert!(
        !serialized
            .windows(token.len())
            .any(|window| window == token.as_bytes())
    );
    let output_digest = blake3::hash(&serialized);
    let output_bytes = serialized.len();
    drop(serialized);
    let capacity = findings.capacity();
    drop(findings);
    let after_drop = LIVE.load(Relaxed);

    println!(
        "{}",
        serde_json::json!({
            "count": count,
            "encoding": encoding,
            "input_bytes": bytes.len(),
            "finding_size_bytes": std::mem::size_of::<Finding>(),
            "finding_capacity": capacity,
            "allocation_calls": allocations,
            "allocation_requested_bytes": allocation_bytes,
            "reallocation_calls": reallocations,
            "reallocation_requested_bytes": reallocation_request_bytes,
            "deallocation_calls_during_scan": deallocations,
            "live_baseline_bytes": baseline,
            "live_at_scan_return_delta_bytes": scan_live as i128 - baseline as i128,
            "peak_scan_live_delta_bytes": peak as i128 - baseline as i128,
            "live_after_drop_delta_bytes": after_drop as i128 - baseline as i128,
            "serialized_output_bytes": output_bytes,
            "serialized_output_blake3": output_digest.to_hex().to_string(),
            "redaction_verified": true,
        })
    );
    Ok(())
}
