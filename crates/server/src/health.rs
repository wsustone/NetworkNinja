//! Monitor health (spec "Web UI: monitor health"): the server's own CPU and
//! memory, read from the operating system with no extra dependencies, for
//! `/api/health`.
//!
//! - Linux and macOS: `getrusage` (CPU time, peak memory); Linux also reads
//!   the current resident size from `/proc/self/status`.
//! - Windows: `GetProcessTimes` and `K32GetProcessMemoryInfo` (kernel32).

/// What the process has used so far.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Usage {
    /// User + system CPU time, seconds since the process started.
    pub cpu_secs: f64,
    /// Resident memory now, bytes, where the OS says.
    pub rss: Option<u64>,
    /// Peak resident memory, bytes.
    pub peak_rss: Option<u64>,
}

#[cfg(unix)]
pub fn usage() -> Option<Usage> {
    // struct rusage: two timevals, then fourteen longs (ru_maxrss first).
    // Read as 64-bit words: on macOS tv_usec is 32 bits plus padding.
    #[allow(non_camel_case_types)]
    type c_int = i32;
    extern "C" {
        fn getrusage(who: c_int, usage: *mut [u64; 18]) -> c_int;
    }
    let mut r = [0u64; 18];
    // SAFETY: getrusage fills a struct rusage, 144 bytes on 64-bit Linux
    // and macOS; the buffer is that size and outlives the call.
    if unsafe { getrusage(0, &mut r) } != 0 {
        return None;
    }
    let usec = |w: u64| (if cfg!(target_os = "macos") { w & 0xffff_ffff } else { w }) as f64 / 1e6;
    let cpu_secs = r[0] as f64 + usec(r[1]) + r[2] as f64 + usec(r[3]);
    // ru_maxrss: bytes on macOS, kilobytes on Linux.
    let peak_rss = Some(if cfg!(target_os = "macos") { r[4] } else { r[4] * 1024 });
    Some(Usage {
        cpu_secs,
        rss: resident_now(),
        peak_rss,
    })
}

#[cfg(target_os = "linux")]
fn resident_now() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb = s
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?;
    Some(kb.parse::<u64>().ok()? * 1024)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn resident_now() -> Option<u64> {
    None
}

#[cfg(windows)]
pub fn usage() -> Option<Usage> {
    type Handle = isize;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn GetProcessTimes(p: Handle, created: *mut u64, exited: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
        fn K32GetProcessMemoryInfo(p: Handle, counters: *mut [usize; 9], cb: u32) -> i32;
    }
    // SAFETY: the current-process pseudo-handle needs no closing; the out
    // parameters are FILETIMEs (u64) and a PROCESS_MEMORY_COUNTERS (a u32
    // pair, then eight SIZE_Ts: nine words on 64-bit), sized as declared.
    unsafe {
        let p = GetCurrentProcess();
        let (mut c, mut e, mut k, mut u) = (0u64, 0u64, 0u64, 0u64);
        if GetProcessTimes(p, &mut c, &mut e, &mut k, &mut u) == 0 {
            return None;
        }
        let mut m = [0usize; 9];
        m[0] = std::mem::size_of::<[usize; 9]>(); // cb in the low 32 bits
        let mem = K32GetProcessMemoryInfo(p, &mut m, std::mem::size_of::<[usize; 9]>() as u32) != 0;
        Some(Usage {
            // FILETIME: 100 ns units.
            cpu_secs: (k + u) as f64 / 1e7,
            rss: mem.then_some(m[2] as u64),
            peak_rss: mem.then_some(m[1] as u64),
        })
    }
}

#[cfg(not(any(unix, windows)))]
pub fn usage() -> Option<Usage> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_reports_cpu_and_memory() {
        let a = usage().expect("usage on this OS");
        // Burn a little CPU and memory.
        let v: Vec<u64> = (0..2_000_000).map(|i| i * i).collect();
        let b = usage().unwrap();
        assert!(v.iter().sum::<u64>() > 0);
        assert!(b.cpu_secs >= a.cpu_secs && b.cpu_secs > 0.0, "{a:?} {b:?}");
        let peak = b.peak_rss.expect("peak memory");
        assert!(peak > 1 << 20 && peak < 1 << 40, "{peak} bytes");
        if let Some(rss) = b.rss {
            assert!(rss > 1 << 20 && rss <= peak.max(rss), "{rss}");
        }
    }
}
