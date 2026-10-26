// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the benchmark reads about the machine and the measured process, from outside it.
//!
//! The server is measured as a separate process, so nothing here needs the server's cooperation —
//! and the product gains neither unsafe code nor a dependency to report on itself. On Linux the
//! numbers are the kernel's own: `/proc/<pid>/stat` for CPU time and `VmHWM` for the peak resident
//! set, reset before each step through `clear_refs`. Elsewhere `ps` is sampled while the step runs
//! and the highest sample is the peak; the report names which method produced its numbers.

use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::report::{FsyncProbe, Platform};

/// The machine the run is on.
pub fn platform() -> Platform {
    let linux = cfg!(target_os = "linux");
    Platform {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        kernel: output("uname", &["-r"]),
        cpu_model: if linux {
            std::fs::read_to_string("/proc/cpuinfo")
                .ok()
                .and_then(|text| field(&text, "model name"))
                .or_else(|| output("lscpu", &[]).and_then(|text| field(&text, "Model name")))
        } else {
            output("sysctl", &["-n", "machdep.cpu.brand_string"])
        },
        logical_cores: std::thread::available_parallelism().map_or(1, usize::from),
        memory_bytes: if linux {
            std::fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|text| field(&text, "MemTotal"))
                .and_then(|kib| kib.trim_end_matches(" kB").trim().parse::<u64>().ok())
                .map(|kib| kib * 1024)
        } else {
            output("sysctl", &["-n", "hw.memsize"]).and_then(|bytes| bytes.parse().ok())
        },
    }
}

/// What a 4 KiB write and its data flush cost in `directory`, `samples` times.
pub fn fsync(directory: &Path, samples: usize) -> std::io::Result<FsyncProbe> {
    let path = directory.join(".permguard-bench-fsync-probe");
    let mut file = std::fs::File::create(&path)?;
    let block = [0x5a_u8; 4096];
    let mut micros = Vec::with_capacity(samples);
    for _ in 0..samples.max(1) {
        let started = Instant::now();
        file.write_all(&block)?;
        file.sync_data()?;
        micros.push(started.elapsed().as_secs_f64() * 1_000_000.0);
    }
    drop(file);
    std::fs::remove_file(&path)?;
    let p = super::report::percentiles(&mut micros).unwrap_or(super::report::Percentiles {
        p50: 0.0,
        p95: 0.0,
        p99: 0.0,
        max: 0.0,
    });
    Ok(FsyncProbe {
        samples: micros.len(),
        p50_us: p.p50.round() as u64,
        p99_us: p.p99.round() as u64,
    })
}

/// How [`Process`] reads its numbers, as the report names it.
pub fn method() -> &'static str {
    if cfg!(target_os = "linux") {
        "procfs"
    } else {
        "ps-sampled"
    }
}

/// The measured process, one step at a time.
pub struct Process {
    pid: u32,
    ticks_per_second: f64,
}

/// A step in progress.
pub struct Measuring {
    cpu_before: Option<f64>,
    peak: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    sampler: Option<std::thread::JoinHandle<()>>,
}

impl Process {
    pub fn new(pid: u32) -> Self {
        let ticks_per_second = output("getconf", &["CLK_TCK"])
            .and_then(|ticks| ticks.parse().ok())
            .unwrap_or(100.0);
        Self {
            pid,
            ticks_per_second,
        }
    }

    /// Starts measuring a step: the CPU time so far, and a fresh peak.
    pub fn begin(&self) -> Measuring {
        let peak = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let sampler = if cfg!(target_os = "linux") {
            // `5` resets the peak resident set to the current one (Linux 4.0 and later). When the
            // write is refused the peak is the process's since it started, which is never lower
            // than the step's: the report then overstates, never understates.
            let _ = std::fs::write(format!("/proc/{}/clear_refs", self.pid), "5");
            None
        } else {
            let (pid, peak, stop) = (self.pid, Arc::clone(&peak), Arc::clone(&stop));
            Some(std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    if let Some((rss, _)) = ps(pid) {
                        peak.fetch_max(rss, Ordering::AcqRel);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }))
        };
        Measuring {
            cpu_before: self.cpu_seconds(),
            peak,
            stop,
            sampler,
        }
    }

    /// Ends a step: the CPU seconds it used, and its peak resident set.
    pub fn end(&self, mut measuring: Measuring) -> (Option<f64>, Option<u64>) {
        measuring.stop.store(true, Ordering::Release);
        if let Some(sampler) = measuring.sampler.take() {
            let _ = sampler.join();
        }
        let cpu = match (measuring.cpu_before, self.cpu_seconds()) {
            (Some(before), Some(after)) => Some((after - before).max(0.0)),
            _ => None,
        };
        let peak = if cfg!(target_os = "linux") {
            std::fs::read_to_string(format!("/proc/{}/status", self.pid))
                .ok()
                .and_then(|text| field(&text, "VmHWM"))
                .and_then(|kib| kib.trim_end_matches(" kB").trim().parse::<u64>().ok())
                .map(|kib| kib * 1024)
        } else {
            Some(measuring.peak.load(Ordering::Acquire)).filter(|peak| *peak > 0)
        };
        (cpu, peak)
    }

    /// The process's user and system CPU time so far.
    fn cpu_seconds(&self) -> Option<f64> {
        if cfg!(target_os = "linux") {
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid)).ok()?;
            // The command name is parenthesised and may hold spaces: count fields after it.
            let (_, rest) = stat.rsplit_once(')')?;
            let fields: Vec<&str> = rest.split_whitespace().collect();
            // `utime` and `stime` are fields 14 and 15 of the line, 12 and 13 after the name.
            let utime: f64 = fields.get(11)?.parse().ok()?;
            let stime: f64 = fields.get(12)?.parse().ok()?;
            Some((utime + stime) / self.ticks_per_second)
        } else {
            ps(self.pid).map(|(_, cpu)| cpu)
        }
    }
}

/// `ps`'s resident set (bytes) and cumulative CPU time (seconds) of `pid`.
fn ps(pid: u32) -> Option<(u64, f64)> {
    let text = output("ps", &["-o", "rss=", "-o", "time=", "-p", &pid.to_string()])?;
    let mut parts = text.split_whitespace();
    let rss_kib: u64 = parts.next()?.parse().ok()?;
    Some((rss_kib * 1024, cpu_time(parts.next()?)?))
}

/// `ps`'s `[[dd-]hh:]mm:ss[.ss]`, in seconds.
fn cpu_time(text: &str) -> Option<f64> {
    let (days, clock) = match text.split_once('-') {
        Some((days, clock)) => (days.parse::<f64>().ok()?, clock),
        None => (0.0, text),
    };
    let mut seconds = 0.0;
    for part in clock.split(':') {
        seconds = seconds * 60.0 + part.parse::<f64>().ok()?;
    }
    Some(days * 86_400.0 + seconds)
}

/// A `Name: value` line's value.
fn field(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == name).then(|| value.trim().to_owned())
    })
}

/// A command's trimmed standard output, when it ran and succeeded.
fn output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_ps_cpu_time_reads_every_shape_ps_prints() {
        assert_eq!(cpu_time("0:01.50"), Some(1.5));
        assert_eq!(cpu_time("12:03.25"), Some(723.25));
        assert_eq!(cpu_time("01:00:00"), Some(3600.0));
        assert_eq!(cpu_time("2-00:00:01"), Some(172_801.0));
        assert_eq!(cpu_time("abc"), None);
    }

    #[test]
    fn test_a_named_field_is_read_whatever_its_padding() {
        let text = "MemTotal:       16384 kB\nVmHWM:\t  2048 kB\n";
        assert_eq!(field(text, "MemTotal").as_deref(), Some("16384 kB"));
        assert_eq!(field(text, "VmHWM").as_deref(), Some("2048 kB"));
        assert_eq!(field(text, "Missing"), None);
    }

    #[test]
    fn test_this_process_measures_cpu_and_a_peak() {
        let process = Process::new(std::process::id());
        let measuring = process.begin();
        // Work the step can see: a little CPU and a little memory.
        let mut keep = Vec::new();
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(200) {
            keep.push(vec![1_u8; 64 * 1024]);
            if keep.len() > 64 {
                keep.clear();
            }
        }
        let (cpu, peak) = process.end(measuring);
        assert!(cpu.expect("CPU time") > 0.0, "{cpu:?}");
        assert!(peak.expect("a peak") > 1024 * 1024, "{peak:?}");
    }

    #[test]
    fn test_the_platform_names_at_least_what_every_platform_has() {
        let platform = platform();
        assert!(!platform.os.is_empty() && !platform.arch.is_empty());
        assert!(platform.logical_cores >= 1);
    }

    #[test]
    fn test_the_fsync_probe_measures_and_leaves_nothing_behind() {
        let dir =
            std::env::temp_dir().join(format!("permguard-bench-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a directory");
        let probe = fsync(&dir, 8).expect("the probe runs");
        assert_eq!(probe.samples, 8);
        assert!(probe.p99_us >= probe.p50_us);
        assert_eq!(std::fs::read_dir(&dir).expect("readable").count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
