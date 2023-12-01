// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Creates the emulated pstore and copies it back to RAMOOPS memory on reboot.

use std::cmp;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use data_model::volatile_memory::VolatileMemory;
use data_model::DataInit;
use libchromeos::sys::MappedRegion;
use libchromeos::sys::MemoryMapping;
use libchromeos::sys::MemoryMappingBuilder;
use libchromeos::sys_deps::zerocopy;
use libchromeos::sys_deps::zerocopy::FromBytes;
use libsirenia::linux::kmsg;
use libsirenia::sys::get_cbmem_toc;
use log::error;
use log::info;

const RAMOOPS_UNBIND: &str = "/sys/devices/platform/ramoops.0/driver/unbind";
const RAMOOPS_BUS_ID: &[u8] = b"ramoops.0";

const RAMOOPS_REGION_HEADER_SIZE: usize = 12;
const RAMOOPS_DEFAULT_REGION_SIZE: usize = 0x20000;
const PSTORE_CONSOLE_FILENAME: &str = "console-ramoops-0";
const PSTORE_PMSG_FILENAME: &str = "pmsg-ramoops-0";

const HYPERVISOR_DMESG_TAIL_BYTES: usize = 10 * 1024;

/// Copy contents of emulated pstore to RAMOOPS memory.
pub fn save_pstore(pstore_path: &str, append_dmesg: bool) -> Result<()> {
    // Unbind the hypervisor ramoops driver so that it doesn't clobber our
    // writes. If this fails, we continue anyway since the dmesg buffer will
    // still be preserved as long as the hypervisor does not crash.
    if let Err(e) = unbind_ramoops() {
        error!("Error (ignored): {:?}", e);
    }

    let pstore_fd = File::open(pstore_path)
        .with_context(|| format!("Failed to open pstore file: {}", pstore_path))?;
    let ramoops = mmap_ramoops()?;
    ramoops
        .read_to_memory(0, &pstore_fd, ramoops.size())
        .context("Failed to copy emulated pstore to ramoops memory")?;

    if append_dmesg {
        append_hypervisor_dmesg(&ramoops).context("Failed to append dmesg to ramoops")?;
    }
    Ok(())
}

fn unbind_ramoops() -> Result<()> {
    fs::write(RAMOOPS_UNBIND, RAMOOPS_BUS_ID).context("Failed to unbind ramoops driver")
}

fn get_ramoops_location() -> Result<(u64, usize)> {
    match get_cbmem_toc()?.iter().find(|&x| x.name == "RAMOOPS") {
        None => bail!("RAMOOPS cbmem entry not found"),
        Some(e) => {
            info!("pstore: using ramoops {:#x}@{:#x}", e.size, e.start);
            Ok((e.start, e.size))
        }
    }
}

fn mmap_ramoops() -> Result<MemoryMapping> {
    let (ramoops_addr, ramoops_len) = get_ramoops_location()?;
    let devmem = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_SYNC)
        .open("/dev/mem")
        .context("Failed to open /dev/mem")?;
    MemoryMappingBuilder::new(ramoops_len)
        .from_file(&devmem)
        .offset(ramoops_addr)
        .build()
        .context("Failed to mmap /dev/mem")
}

fn get_ramoops_region_size(name: &str) -> usize {
    // Chrome OS sets all regions except dmesg to the same size, so we
    // use that as the default size here in case of failures.
    let path = format!("/sys/module/ramoops/parameters/{}_size", name);
    match fs::read_to_string(&path) {
        Err(e) => {
            error!("Error reading {}: {}", path, e);
            RAMOOPS_DEFAULT_REGION_SIZE
        }
        Ok(v) => usize::from_str(v.trim())
            .with_context(|| format!("Could not parse {}: {:?}", path, v))
            .unwrap_or_else(|e| {
                error!("Error: {}", e);
                RAMOOPS_DEFAULT_REGION_SIZE
            }),
    }
}

#[allow(dead_code)]
struct RamoopsOffsets {
    dmesg_size: usize,
    console_size: usize,
    console_offset: usize,
    ftrace_size: usize,
    ftrace_offset: usize,
    pmsg_size: usize,
    pmsg_offset: usize,
}

impl RamoopsOffsets {
    fn new(ramoops_size: usize) -> RamoopsOffsets {
        let console_size = get_ramoops_region_size("console");
        let ftrace_size = get_ramoops_region_size("ftrace");
        let pmsg_size = get_ramoops_region_size("pmsg");
        let dmesg_size = ramoops_size - console_size - ftrace_size - pmsg_size;
        let console_offset = dmesg_size;
        let ftrace_offset = console_offset + console_size;
        let pmsg_offset = ftrace_offset + ftrace_size;
        info!(
            "pstore offsets: console={:#x} ftrace={:#x} pmsg={:#x}",
            console_offset, ftrace_offset, pmsg_offset
        );
        RamoopsOffsets {
            dmesg_size,
            console_size,
            console_offset,
            ftrace_size,
            ftrace_offset,
            pmsg_size,
            pmsg_offset,
        }
    }
}

// See fs/pstore/ram_core.c in the kernel for the header definition.
#[derive(Copy, Clone, FromBytes)]
#[repr(C)]
struct RamoopsRegionHeader {
    sig: [u8; 4], // signature, eg. b"DBGC"
    start: u32,   // offset to write next
    size: u32,    // bytes stored
}

// Safe because PstoreRegionHeader is plain data.
// TODO: Remove this once crosvm has finished its migration to zerocopy::FromBytes.
unsafe impl DataInit for RamoopsRegionHeader {}

/// Copy data from the specified /sys/fs/pstore file to the emulated pstore.
fn restore_pstore_region(
    emulated_pstore: &MemoryMapping,
    offset: usize,
    region_size: usize,
    fname: &str,
) -> Result<()> {
    // If there is no data in this ramoops region, the file will not exist.
    let path: PathBuf = ["/sys/fs/pstore", fname].iter().collect();
    if !path.is_file() {
        return Ok(());
    }

    // Write header
    let flen = path.metadata()?.len() as usize;
    let data_size: u32 = cmp::min(flen, region_size - RAMOOPS_REGION_HEADER_SIZE) as u32;
    let header = RamoopsRegionHeader {
        sig: *b"DBGC",
        start: data_size,
        size: data_size,
    };
    emulated_pstore.write_obj(header, offset)?;

    // Write data
    let dataf =
        File::open(&path).with_context(|| format!("Failed to open: {}", path.to_string_lossy()))?;
    emulated_pstore
        .read_to_memory(
            offset + RAMOOPS_REGION_HEADER_SIZE,
            &dataf,
            data_size as usize,
        )
        .with_context(|| format!("Failed to write {} to pstore file", fname))?;
    info!(
        "pstore: wrote {} bytes to region at {:#x} from {}",
        data_size,
        offset,
        path.to_string_lossy()
    );
    Ok(())
}

/// Set up emulated pstore by copying from RAMOOPS memory and /sys/fs/pstore.
pub fn restore_pstore(pstore_path: &str) -> Result<()> {
    // We never read from this file, but mmap requires read permissions.
    let outputf = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(pstore_path)
        .with_context(|| format!("Failed to open pstore file: {}", pstore_path))?;

    // Use identical size and settings for physical and emulated ramoops.
    let ramoops = mmap_ramoops()?;
    outputf
        .set_len(ramoops.size() as u64)
        .context("Failed to resize pstore file")?;
    outputf
        .sync_all()
        .context("Failed to sync pstore file after resize")?;
    let emulated_pstore = MemoryMappingBuilder::new(ramoops.size())
        .from_file(&outputf)
        .build()
        .context("Failed to mmap pstore file")?;

    let offsets = RamoopsOffsets::new(ramoops.size());

    // Copy the dmesg regions as-is from hardware ramoops to pstore file since
    // they are not being written to. For the rest of the regions, copy from
    // files in /sys/fs/pstore.
    ramoops
        .get_slice(0, offsets.dmesg_size)?
        .copy_to_volatile_slice(emulated_pstore.get_slice(0, offsets.dmesg_size)?);

    // For everything except dmesg, use the files in /sys/fs/pstore.
    // TODO(b/221453622): Handle ftrace buffers.
    restore_pstore_region(
        &emulated_pstore,
        offsets.console_offset,
        offsets.console_size,
        PSTORE_CONSOLE_FILENAME,
    )?;
    restore_pstore_region(
        &emulated_pstore,
        offsets.pmsg_offset,
        offsets.pmsg_size,
        PSTORE_PMSG_FILENAME,
    )?;
    emulated_pstore
        .msync()
        .context("Unable to sync pstore file")
}

// Append data to the given ramoops region.
//
// region_offset and region_size must correspond to either the console of the
// pmsg ramoops regions. If the data is too large, it will be truncated to fit.
// Returns the number of bytes copied.
fn append_to_ramoops_region(
    ramoops: &MemoryMapping,
    region_offset: usize,
    region_size: usize,
    data: &[u8],
) -> Result<usize> {
    let mut header: RamoopsRegionHeader = ramoops.read_obj(region_offset)?;
    let data_offset = region_offset + RAMOOPS_REGION_HEADER_SIZE;
    let max_data_size = region_size - RAMOOPS_REGION_HEADER_SIZE;
    let mut copied: usize;
    if data.len() >= max_data_size {
        copied = ramoops.write_slice(&data[..max_data_size], data_offset)?;
        if copied != max_data_size {
            bail!("internal error");
        }
        header.start = 0;
        header.size = copied as u32;
    } else {
        let before_wrap = cmp::min(data.len(), max_data_size - (header.start as usize));
        copied =
            ramoops.write_slice(&data[..before_wrap], data_offset + (header.start as usize))?;
        if copied != before_wrap {
            bail!("internal error");
        };
        if before_wrap == data.len() {
            header.start += copied as u32;
        } else {
            // wraparound at the end of the buffer
            let remaining = ramoops.write_slice(&data[before_wrap..], data_offset)?;
            header.start = remaining as u32;
            copied += remaining;
            if copied != data.len() {
                bail!("internal error");
            };
        }
        header.size = cmp::min(max_data_size, (header.size as usize) + data.len()) as u32;
    }
    ramoops.write_obj(header, region_offset)?;
    Ok(copied)
}

/// Copy the tail of dmesg into the ramoops console buffer.
///
/// This causes hypervisor logs to be included in kernel crash reports.
fn append_hypervisor_dmesg(ramoops: &MemoryMapping) -> Result<()> {
    let dmesg = kmsg::kmsg_tail(HYPERVISOR_DMESG_TAIL_BYTES)?;
    // Make the string longer to account for newlines and escaped chars.
    let mut output = String::with_capacity(HYPERVISOR_DMESG_TAIL_BYTES + 512);
    output.push_str("\n--------[ hypervisor log ]--------\n");
    for line in dmesg {
        output.push_str(line.as_str());
        output.push('\n');
    }

    let data = output.as_bytes();
    let offsets = RamoopsOffsets::new(ramoops.size());
    let copied =
        append_to_ramoops_region(ramoops, offsets.console_offset, offsets.console_size, data)?;
    info!("Appended {} bytes to ramoops console log", copied);
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_ramoops_region_header_size() {
        assert_eq!(
            std::mem::size_of::<RamoopsRegionHeader>(),
            RAMOOPS_REGION_HEADER_SIZE
        )
    }

    fn create_ramoops(sz: usize, data: &[u8]) -> MemoryMapping {
        let m = MemoryMappingBuilder::new(sz).build().unwrap();
        let h = RamoopsRegionHeader {
            sig: *b"DBGC",
            start: data.len() as u32,
            size: data.len() as u32,
        };
        m.write_obj(h, 0).unwrap();
        m.write_slice(data, RAMOOPS_REGION_HEADER_SIZE).unwrap();
        m
    }

    // The ramoops_append_* tests create a mmap mapping of 40 bytes, and then
    // call append_to_ramoops_region() with half that size to simulate the fact
    // that the ramoops memory mapping contains multiple regions.

    #[test]
    fn ramoops_append_nowrap() {
        let d1: [u8; 4] = [1, 2, 3, 4];
        let m = create_ramoops(40, &d1);

        let d2: [u8; 3] = [5, 6, 7];
        append_to_ramoops_region(&m, 0, 20, &d2).unwrap();

        let mut d3: [u8; 7] = [0; 7];
        m.read_slice(&mut d3, RAMOOPS_REGION_HEADER_SIZE).unwrap();
        assert_eq!(&d3, &[1, 2, 3, 4, 5, 6, 7]);
        let hh: RamoopsRegionHeader = m.read_obj(0).unwrap();
        assert_eq!(&hh.sig, b"DBGC");
        assert_eq!(hh.start, 7);
        assert_eq!(hh.size, 7);
    }

    #[test]
    fn ramoops_append_wrap() {
        let d1: [u8; 4] = [1, 2, 3, 4];
        let m = create_ramoops(40, &d1);

        let d2: [u8; 5] = [5, 6, 7, 8, 9];
        append_to_ramoops_region(&m, 0, 20, &d2).unwrap();

        let mut d3: [u8; 8] = [0; 8];
        m.read_slice(&mut d3, RAMOOPS_REGION_HEADER_SIZE).unwrap();
        assert_eq!(&d3, &[9, 2, 3, 4, 5, 6, 7, 8]);
        let hh: RamoopsRegionHeader = m.read_obj(0).unwrap();
        assert_eq!(&hh.sig, b"DBGC");
        assert_eq!(hh.start, 1);
        assert_eq!(hh.size, 8);
    }

    #[test]
    fn ramoops_append_trunc() {
        let d1: [u8; 4] = [1, 2, 3, 4];
        let m = create_ramoops(40, &d1);

        let d2: [u8; 10] = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
        append_to_ramoops_region(&m, 0, 20, &d2).unwrap();

        let mut d3: [u8; 8] = [0; 8];
        m.read_slice(&mut d3, RAMOOPS_REGION_HEADER_SIZE).unwrap();
        assert_eq!(&d3, &[10, 11, 12, 13, 14, 15, 16, 17]);
        let hh: RamoopsRegionHeader = m.read_obj(0).unwrap();
        assert_eq!(&hh.sig, b"DBGC");
        assert_eq!(hh.start, 0);
        assert_eq!(hh.size, 8);
    }
}
