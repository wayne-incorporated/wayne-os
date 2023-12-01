// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use libchromeos::sys::error;
use once_cell::sync::Lazy;

use crate::common;

const GAME_MODE_OFFSET_KB: u64 = 300 * 1024;

/// calculate_reserved_free_kb() calculates the reserved free memory in KiB from
/// /proc/zoneinfo.  Reserved pages are free pages reserved for emergent kernel
/// allocation and are not available to the user space.  It's the sum of high
/// watermarks and max protection pages of memory zones.  It implements the same
/// reserved pages calculation in linux kernel calculate_totalreserve_pages().
///
/// /proc/zoneinfo example:
/// ...
/// Node 0, zone    DMA32
///   pages free     422432
///         min      16270
///         low      20337
///         high     24404
///         ...
///         protection: (0, 0, 1953, 1953)
///
/// The high field is the high watermark for this zone.  The protection field is
/// the protected pages for lower zones.  See the lowmem_reserve_ratio section
/// in https://www.kernel.org/doc/Documentation/sysctl/vm.txt.
fn calculate_reserved_free_kb<R: BufRead>(reader: R) -> Result<u64> {
    let page_size_kb = 4;
    let mut num_reserved_pages: u64 = 0;

    for line in reader.lines() {
        let line = line?;
        let mut tokens = line.split_whitespace();
        let key = if let Some(k) = tokens.next() {
            k
        } else {
            continue;
        };
        if key == "high" {
            num_reserved_pages += if let Some(v) = tokens.next() {
                v.parse::<u64>()
                    .with_context(|| format!("Couldn't parse the high field: {}", line))?
            } else {
                0
            };
        } else if key == "protection:" {
            num_reserved_pages += tokens.try_fold(0u64, |maximal, token| -> Result<u64> {
                let pattern = &['(', ')', ','][..];
                let num = token
                    .trim_matches(pattern)
                    .parse::<u64>()
                    .with_context(|| format!("Couldn't parse protection field: {}", line))?;
                Ok(std::cmp::max(maximal, num))
            })?;
        }
    }
    Ok(num_reserved_pages * page_size_kb)
}

fn get_reserved_memory_kb() -> Result<u64> {
    // Reserve free pages is high watermark + lowmem_reserve. extra_free_kbytes
    // raises the high watermark.  Nullify the effect of extra_free_kbytes by
    // excluding it from the reserved pages.  The default extra_free_kbytes
    // value is 0 if the file couldn't be accessed.
    let reader = File::open(Path::new("/proc/zoneinfo"))
        .map(BufReader::new)
        .context("Couldn't read /proc/zoneinfo")?;
    Ok(calculate_reserved_free_kb(reader)?
        - common::read_file_to_u64("/proc/sys/vm/extra_free_kbytes").unwrap_or(0))
}

/// Returns the percentage of the recent 10 seconds that some process is blocked
/// by memory.
/// Example input:
///   some avg10=0.00 avg60=0.00 avg300=0.00 total=0
///   full avg10=0.00 avg60=0.00 avg300=0.00 total=0
fn parse_psi_memory<R: BufRead>(reader: R) -> Result<f64> {
    for line in reader.lines() {
        let line = line?;
        let mut tokens = line.split_whitespace();
        if tokens.next() != Some("some") {
            continue;
        }
        if let Some(pair) = tokens.next() {
            let mut elements = pair.split('=');
            if elements.next() != Some("avg10") {
                continue;
            }
            if let Some(value) = elements.next() {
                return value.parse().context("Couldn't parse the avg10 value");
            }
        }
        bail!("Couldn't parse /proc/pressure/memory, line: {}", line);
    }
    bail!("Couldn't parse /proc/pressure/memory");
}

#[allow(dead_code)]
fn get_psi_memory_pressure_10_seconds() -> Result<f64> {
    let reader = File::open(Path::new("/proc/pressure/memory"))
        .map(BufReader::new)
        .context("Couldn't read /proc/pressure/memory")?;
    parse_psi_memory(reader)
}

/// Struct to hold parsed /proc/meminfo data, only contains used fields.
#[derive(Default)]
struct MemInfo {
    total: u64,
    free: u64,
    active_anon: u64,
    inactive_anon: u64,
    active_file: u64,
    inactive_file: u64,
    dirty: u64,
    swap_free: u64,
}

/// Parsing /proc/meminfo.
fn parse_meminfo<R: BufRead>(reader: R) -> Result<MemInfo> {
    let mut result = MemInfo::default();
    for line in reader.lines() {
        let line = line?;
        let mut tokens = line.split_whitespace();
        let key = if let Some(k) = tokens.next() {
            k
        } else {
            continue;
        };
        let value = if let Some(v) = tokens.next() {
            v.parse()?
        } else {
            continue;
        };
        if key == "MemTotal:" {
            result.total = value;
        } else if key == "MemFree:" {
            result.free = value;
        } else if key == "Active(anon):" {
            result.active_anon = value;
        } else if key == "Inactive(anon):" {
            result.inactive_anon = value;
        } else if key == "Active(file):" {
            result.active_file = value;
        } else if key == "Inactive(file):" {
            result.inactive_file = value;
        } else if key == "Dirty:" {
            result.dirty = value;
        } else if key == "SwapFree:" {
            result.swap_free = value;
        }
    }
    Ok(result)
}

/// Return MemInfo object containing /proc/meminfo data.
fn get_meminfo() -> Result<MemInfo> {
    let reader = File::open(Path::new("/proc/meminfo"))
        .map(BufReader::new)
        .context("Couldn't read /proc/meminfo")?;
    parse_meminfo(reader)
}

/// calculate_available_memory_kb implements similar available memory
/// calculation as kernel function get_available_mem_adj().  The available memory
/// consists of 3 parts: the free memory, the file cache, and the swappable
/// memory.  The available free memory is free memory minus reserved free memory.
/// The available file cache is the total file cache minus reserved file cache
/// (min_filelist).  Because swapping is prohibited if there is no anonymous
/// memory or no swap free, the swappable memory is the minimal of anonymous
/// memory and swap free.  As swapping memory is more costly than dropping file
/// cache, only a fraction (1 / ram_swap_weight) of the swappable memory
/// contributes to the available memory.
fn calculate_available_memory_kb(
    info: &MemInfo,
    reserved_free: u64,
    min_filelist: u64,
    ram_swap_weight: u64,
) -> u64 {
    let free = info.free;
    let anon = info.active_anon.saturating_add(info.inactive_anon);
    let file = info.active_file.saturating_add(info.inactive_file);
    let dirty = info.dirty;
    let free_component = free.saturating_sub(reserved_free);
    let cache_component = file.saturating_sub(dirty).saturating_sub(min_filelist);
    let swappable = std::cmp::min(anon, info.swap_free);
    let swap_component = if ram_swap_weight != 0 {
        swappable / ram_swap_weight
    } else {
        0
    };
    free_component
        .saturating_add(cache_component)
        .saturating_add(swap_component)
}

struct MemoryParameters {
    reserved_free: u64,
    min_filelist: u64,
    ram_swap_weight: u64,
}

fn get_memory_parameters() -> MemoryParameters {
    static RESERVED_FREE: Lazy<u64> = Lazy::new(|| match get_reserved_memory_kb() {
        Ok(reserved) => reserved,
        Err(e) => {
            error!("get_reserved_memory_kb failed: {}", e);
            0
        }
    });
    let min_filelist: u64 =
        common::read_file_to_u64("/proc/sys/vm/min_filelist_kbytes").unwrap_or(0);
    // TODO(vovoy): Use a regular config file instead of sysfs file.
    static RAM_SWAP_WEIGHT: Lazy<u64> = Lazy::new(|| {
        common::read_file_to_u64("/sys/kernel/mm/chromeos-low_mem/ram_vs_swap_weight").unwrap_or(0)
    });
    MemoryParameters {
        reserved_free: *RESERVED_FREE,
        min_filelist,
        ram_swap_weight: *RAM_SWAP_WEIGHT,
    }
}

fn get_available_memory_kb() -> Result<u64> {
    let meminfo = get_meminfo()?;
    let p = get_memory_parameters();
    Ok(calculate_available_memory_kb(
        &meminfo,
        p.reserved_free,
        p.min_filelist,
        p.ram_swap_weight,
    ))
}

pub fn get_foreground_available_memory_kb() -> Result<u64> {
    get_available_memory_kb()
}

// |game_mode| is passed rather than implicitly queried. This saves us a query
// (hence a lock) in the case where the caller needs the game mode state for a
// separate purpose (see |get_memory_pressure_status|).
pub fn get_background_available_memory_kb(game_mode: common::GameMode) -> Result<u64> {
    let available = get_available_memory_kb()?;
    if game_mode != common::GameMode::Off {
        if available > GAME_MODE_OFFSET_KB {
            Ok(available - GAME_MODE_OFFSET_KB)
        } else {
            Ok(0)
        }
    } else {
        Ok(available)
    }
}

fn parse_margins<R: BufRead>(reader: R) -> Result<Vec<u64>> {
    let first_line = reader
        .lines()
        .next()
        .context("No content in margin buffer")??;
    let margins = first_line
        .split_whitespace()
        .map(|x| x.parse().context("Couldn't parse an element in margins"))
        .collect::<Result<Vec<u64>>>()?;
    if margins.len() < 2 {
        bail!("Less than 2 numbers in margin content.");
    } else {
        Ok(margins)
    }
}

struct MemoryMarginsKb {
    critical: u64,
    moderate: u64,
}

static MEMORY_MARGINS: Lazy<Mutex<MemoryMarginsKb>> =
    Lazy::new(|| Mutex::new(get_default_memory_margins_kb_impl()));

// Given the total system memory in KB and the basis points for critical and moderate margins
// calculate the absolute values in KBs.
fn total_mem_to_margins_bps(total_mem_kb: u64, critical_bps: u64, moderate_bps: u64) -> (u64, u64) {
    // A basis point is 1/100th of a percent, so we need to convert to whole digit percent and then
    // convert into a fraction of 1, so we divide by 100 twice, ie. 4000bps -> 40% -> .4.
    let total_mem_kb = total_mem_kb as f64;
    let critical_bps = critical_bps as f64;
    let moderate_bps = moderate_bps as f64;
    (
        (total_mem_kb * (critical_bps / 100.0) / 100.0) as u64,
        (total_mem_kb * (moderate_bps / 100.0) / 100.0) as u64,
    )
}

fn get_memory_margins_kb_from_bps(critical_bps: u64, moderate_bps: u64) -> MemoryMarginsKb {
    let total_memory_kb = match get_meminfo() {
        Ok(meminfo) => meminfo.total,
        Err(e) => {
            error!("Assume 2 GiB total memory if get_meminfo failed: {}", e);
            2 * 1024
        }
    };

    let (critical, moderate) =
        total_mem_to_margins_bps(total_memory_kb, critical_bps, moderate_bps);
    MemoryMarginsKb { critical, moderate }
}

fn get_default_memory_margins_kb_impl() -> MemoryMarginsKb {
    // TODO(vovoy): Use a regular config file instead of sysfs file.
    let margin_path = "/sys/kernel/mm/chromeos-low_mem/margin";
    match File::open(Path::new(margin_path)).map(BufReader::new) {
        Ok(reader) => match parse_margins(reader) {
            Ok(margins) => {
                return MemoryMarginsKb {
                    critical: margins[0] * 1024,
                    moderate: margins[1] * 1024,
                }
            }
            Err(e) => error!("Couldn't parse {}: {}", margin_path, e),
        },
        Err(e) => error!("Couldn't read {}: {}", margin_path, e),
    }

    // Critical margin is 5.2% of total memory, moderate margin is 40% of total
    // memory. See also /usr/share/cros/init/swap.sh on DUT.
    get_memory_margins_kb_from_bps(520, 4000)
}

pub fn get_memory_margins_kb() -> (u64, u64) {
    match MEMORY_MARGINS.lock() {
        Ok(data) => (data.critical, data.moderate),
        Err(poisoned) => {
            let data = poisoned.into_inner();
            (data.critical, data.moderate)
        }
    }
}

pub fn set_memory_margins_bps(critical: u32, moderate: u32) -> Result<()> {
    match MEMORY_MARGINS.lock() {
        Ok(mut data) => {
            let margins = get_memory_margins_kb_from_bps(critical.into(), moderate.into());
            *data = margins;
            Ok(())
        }
        Err(_) => bail!("Failed to set memory margins"),
    }
}

pub struct ComponentMarginsKb {
    pub chrome_critical: u64,
    pub chrome_moderate: u64,
    pub arcvm_foreground: u64,
    pub arcvm_perceptible: u64,
    pub arcvm_cached: u64,
}

pub fn get_component_margins_kb() -> ComponentMarginsKb {
    let (critical, moderate) = get_memory_margins_kb();
    ComponentMarginsKb {
        chrome_critical: critical,
        chrome_moderate: moderate,
        arcvm_foreground: critical * 3 / 4,  // 75 % of critical
        arcvm_perceptible: critical * 3 / 2, // 150 % of critical
        arcvm_cached: moderate,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PressureLevelChrome {
    // There is enough memory to use.
    None = 0,
    // Chrome is advised to free buffers that are cheap to re-allocate and not
    // immediately needed.
    Moderate = 1,
    // Chrome is advised to free all possible memory.
    Critical = 2,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum PressureLevelArcvm {
    // There is enough memory to use.
    None = 0,
    // ARCVM is advised to kill cached processes to free memory.
    Cached = 1,
    // ARCVM is advised to kill perceptible processes to free memory.
    Perceptible = 2,
    // ARCVM is advised to kill foreground processes to free memory.
    Foreground = 3,
}

pub struct PressureStatus {
    pub chrome_level: PressureLevelChrome,
    pub chrome_reclaim_target_kb: u64,
    pub arcvm_level: PressureLevelArcvm,
    pub arcvm_reclaim_target_kb: u64,
}

pub fn get_memory_pressure_status() -> Result<PressureStatus> {
    let game_mode = common::get_game_mode()?;
    let available = get_background_available_memory_kb(game_mode)?;
    let margins = get_component_margins_kb();

    let (chrome_level, chrome_reclaim_target_kb) = if available < margins.chrome_critical {
        (
            PressureLevelChrome::Critical,
            margins.chrome_critical - available,
        )
    } else if available < margins.chrome_moderate {
        (
            PressureLevelChrome::Moderate,
            margins.chrome_moderate - available,
        )
    } else {
        (PressureLevelChrome::None, 0)
    };

    let (raw_arcvm_level, arcvm_reclaim_target_kb) = if available < margins.arcvm_foreground {
        (
            PressureLevelArcvm::Foreground,
            margins.arcvm_foreground - available,
        )
    } else if available < margins.arcvm_perceptible {
        (
            PressureLevelArcvm::Perceptible,
            margins.arcvm_perceptible - available,
        )
    } else if available < margins.arcvm_cached {
        (PressureLevelArcvm::Cached, margins.arcvm_cached - available)
    } else {
        (PressureLevelArcvm::None, 0)
    };

    let arcvm_level =
        if game_mode == common::GameMode::Arc && raw_arcvm_level > PressureLevelArcvm::Cached {
            // Do not kill Android apps that are perceptible or foreground, only
            // those that are cached. Otherwise, the fullscreen Android app or a
            // service it needs may be killed.
            PressureLevelArcvm::Cached
        } else {
            raw_arcvm_level
        };

    Ok(PressureStatus {
        chrome_level,
        chrome_reclaim_target_kb,
        arcvm_level,
        arcvm_reclaim_target_kb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_reserved_free_kb() {
        let mock_partial_zoneinfo = r#"
Node 0, zone      DMA
  pages free     3968
        min      137
        low      171
        high     205
        spanned  4095
        present  3999
        managed  3976
        protection: (0, 1832, 3000, 3786)
Node 0, zone    DMA32
  pages free     422432
        min      16270
        low      20337
        high     24404
        spanned  1044480
        present  485541
        managed  469149
        protection: (0, 0, 1953, 1500)
Node 0, zone   Normal
  pages free     21708
        min      17383
        low      21728
        high     26073
        spanned  524288
        present  524288
        managed  501235
        protection: (0, 0, 0, 0)"#;
        let page_size_kb = 4;
        let high_watermarks = 205 + 24404 + 26073;
        let lowmem_reserves = 3786 + 1953;
        let reserved = calculate_reserved_free_kb(mock_partial_zoneinfo.as_bytes()).unwrap();
        assert_eq!(reserved, (high_watermarks + lowmem_reserves) * page_size_kb);
    }

    #[test]
    fn test_parse_meminfo() {
        let mock_meminfo = r#"
MemTotal:        8025656 kB
MemFree:         4586928 kB
MemAvailable:    6704404 kB
Buffers:          659640 kB
Cached:          1949056 kB
SwapCached:            0 kB
Active:          1430416 kB
Inactive:        1556968 kB
Active(anon):     489640 kB
Inactive(anon):    29188 kB
Active(file):     940776 kB
Inactive(file):  1527780 kB
Unevictable:      151128 kB
Mlocked:           41008 kB
SwapTotal:      11756332 kB
SwapFree:       11756332 kB
Dirty:              5712 kB
Writeback:             0 kB
AnonPages:        529800 kB
Mapped:           321468 kB
Shmem:            140156 kB
Slab:             169252 kB
SReclaimable:     115540 kB
SUnreclaim:        53712 kB
KernelStack:        7072 kB
PageTables:        13340 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:    15769160 kB
Committed_AS:    2483600 kB
VmallocTotal:   34359738367 kB
VmallocUsed:           0 kB
VmallocChunk:          0 kB
Percpu:             2464 kB
AnonHugePages:     40960 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
DirectMap4k:      170216 kB
DirectMap2M:     5992448 kB
DirectMap1G:     3145728 kB"#;
        let meminfo = parse_meminfo(mock_meminfo.as_bytes()).unwrap();
        assert_eq!(meminfo.free, 4586928);
        assert_eq!(meminfo.active_anon, 489640);
        assert_eq!(meminfo.inactive_anon, 29188);
        assert_eq!(meminfo.active_file, 940776);
        assert_eq!(meminfo.inactive_file, 1527780);
        assert_eq!(meminfo.dirty, 5712);
        assert_eq!(meminfo.swap_free, 11756332);
    }

    #[test]
    fn test_parse_psi_memory() {
        let mock_psi_memory = r#"
some avg10=57.25 avg60=35.97 avg300=10.18 total=32748793
full avg10=29.29 avg60=19.01 avg300=5.44 total=17589167"#;
        let pressure = parse_psi_memory(mock_psi_memory.as_bytes()).unwrap();
        assert!((pressure - 57.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_calculate_available_memory_kb() {
        let mut info = MemInfo::default();
        let min_filelist = 400 * 1024;
        let reserved_free = 0;
        let ram_swap_weight = 4;

        // Available determined by file cache.
        info.active_file = 500 * 1024;
        info.inactive_file = 500 * 1024;
        info.dirty = 10 * 1024;
        let file = info.active_file + info.inactive_file;
        let available =
            calculate_available_memory_kb(&info, reserved_free, min_filelist, ram_swap_weight);
        assert_eq!(available, file - min_filelist - info.dirty);

        // Available determined by swap free.
        info.swap_free = 1200 * 1024;
        info.active_anon = 1000 * 1024;
        info.inactive_anon = 1000 * 1024;
        info.active_file = 0;
        info.inactive_file = 0;
        info.dirty = 0;
        let available =
            calculate_available_memory_kb(&info, reserved_free, min_filelist, ram_swap_weight);
        assert_eq!(available, info.swap_free / ram_swap_weight);

        // Available determined by anonymous.
        info.swap_free = 6000 * 1024;
        info.active_anon = 500 * 1024;
        info.inactive_anon = 500 * 1024;
        let anon = info.active_anon + info.inactive_anon;
        let available =
            calculate_available_memory_kb(&info, reserved_free, min_filelist, ram_swap_weight);
        assert_eq!(available, anon / ram_swap_weight);

        // When ram_swap_weight is 0, swap is ignored in available.
        info.swap_free = 1200 * 1024;
        info.active_anon = 1000 * 1024;
        info.inactive_anon = 1000 * 1024;
        info.active_file = 500 * 1024;
        info.inactive_file = 500 * 1024;
        let file = info.active_file + info.inactive_file;
        let ram_swap_weight = 0;
        let available =
            calculate_available_memory_kb(&info, reserved_free, min_filelist, ram_swap_weight);
        assert_eq!(available, file - min_filelist);
    }

    #[test]
    fn test_parse_margins() {
        assert!(parse_margins("".to_string().as_bytes()).is_err());
        assert!(parse_margins("123 4a6".to_string().as_bytes()).is_err());
        assert!(parse_margins("123.2 412.3".to_string().as_bytes()).is_err());
        assert!(parse_margins("123".to_string().as_bytes()).is_err());

        let margins = parse_margins("123 456".to_string().as_bytes()).unwrap();
        assert_eq!(margins.len(), 2);
        assert_eq!(margins[0], 123);
        assert_eq!(margins[1], 456);
    }

    #[test]
    fn test_bps_to_margins_bps() {
        let (critical, moderate) = total_mem_to_margins_bps(
            100000, /* 100mb */
            1200,   /* 12% */
            3600,   /* 36% */
        );
        assert_eq!(critical, 12000 /* 12mb */);
        assert_eq!(moderate, 36000 /* 36mb */);

        let (critical, moderate) = total_mem_to_margins_bps(
            1000000, /* 1000mb */
            1250,    /* 12.50% */
            7340,    /* 73.4% */
        );
        assert_eq!(critical, 125000 /* 125mb */);
        assert_eq!(moderate, 734000 /* 734mb */);
    }
}
