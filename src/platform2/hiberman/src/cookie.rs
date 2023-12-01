// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages the "valid resume image" cookie.

use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;

use crate::hiberutil::path_to_stateful_block;
use crate::hiberutil::HibernateError;
use crate::mmapbuf::MmapBuffer;

/// The hibernate cookie is a flag stored at a known location on disk. The early
/// init scripts use this flag to determine whether or not to mount the stateful
/// partition in snapshot mode for resume, or normal read/write mode for a
/// traditional fresh boot. Normally this sort of cookie would be stored as a
/// regular file in the stateful partition itself. But we can't exactly do that
/// because this is the indicator used to determine _how_ to mount the RW
/// file systems.
///
/// This implementation currently stores the flag as a well-known string inside
/// the leftover space at the end of the sector containing the GUID Partition
/// Table (GPT) header. This space is ideal because its location is fixed, it's
/// not manipulated in normal circumstances, and the GPT header format is
/// unlikely to change and start using this space.
struct HibernateCookie {
    blockdev: File,
    buffer: MmapBuffer,
}

/// Define the size of the region we update.
const COOKIE_READ_SIZE: usize = 0x400;
const COOKIE_WRITE_SIZE: usize = 0x400;

/// Define the magic value the GPT stamps down, which we will use to verify
/// we're writing to an area that we expect. If somehow the world shifted out
/// from under us, this could prevent us from silently corrupting data.
const GPT_MAGIC_OFFSET: usize = 0x200;
const GPT_MAGIC: u64 = 0x5452415020494645; // 'EFI PART'

/// The beginning of the disk starts with a protective MBR, followed by a sector
/// just for the GPT header. The GPT header is quite small and doesn't use its
/// whole sector. Define the offset towards the end of the region where the
/// cookie will be written.
const COOKIE_MAGIC_OFFSET: usize = 0x3E0;

/// Define the magic token values we write to indicate a valid hibernate
/// partition. This is both big (as in bigger than a single bit), and points the
/// finger at an obvious culprit, in the case this does end up unintentionally
/// writing over important data. This is made arbitrarily, but intentionally, to
/// be 16 bytes. If this is seen on a booting system, we initialize and prepare
/// dm-snapshots for stateful systems in preparation for resuming from
/// hibernate.
const COOKIE_RESUME_READY_VALUE: &[u8] = b"HibernateCookie!";

/// Define a known "not valid" value as well. This is treated identically to
/// anything else that is invalid, but again could serve as a more useful
/// breadcrumb to someone debugging than 16 vanilla zeroes. If this is seen on
/// boot, a normal boot continues with no preparations for resume from
/// hibernate.
const COOKIE_NO_RESUME_VALUE: &[u8] = b"No_Hiber_Resume!";

/// As soon as a valid cookie is read, it's changed to in-progress, to avoid
/// boot loops that get stuck in a hibernate resume. If a booting system sees
/// this value, it will not attempt resume, but treat it instead the same as
/// the aborting case.
const COOKIE_RESUME_IN_PROGRESS_VALUE: &[u8] = b"ResumeInProgress";

/// This cookie value indicates a resume abort was started but got interrupted.
/// If a booting system sees this, it should re-install the dm-snapshots and
/// restart the merge back to stateful.
const COOKIE_RESUME_ABORTING_VALUE: &[u8] = b"ResumeIsAborting";

/// This cookie value indicates something went wrong within the abort path and
/// the system was forced to do an emergency reboot. In this case we do not try
/// to wire up dm-snapshots again (since it didn't go well last time), but
/// instead simply try to dump logs and continue forward with the cold boot. In
/// some cases we may be able to proceed forward normally here if the snapshots
/// are not partially synced.
const COOKIE_EMERGENCY_REBOOT_VALUE: &[u8] = b"EmergencyReboot!";

/// Define the size of the magic token, in bytes.
const COOKIE_SIZE: usize = 16;

#[derive(Eq, PartialEq)]
pub enum HibernateCookieValue {
    Uninitialized,
    NoResume,
    ResumeReady,
    ResumeInProgress,
    ResumeAborting,
    EmergencyReboot,
}

impl HibernateCookie {
    /// Create a new HibernateCookie structure. This allocates resources but
    /// does not attempt to read or write the disk.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<HibernateCookie> {
        let blockdev = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_DIRECT | libc::O_SYNC)
            .open(path)
            .context("Failed to open hibernate cookie")?;

        let buffer = MmapBuffer::new(COOKIE_READ_SIZE)?;
        Ok(HibernateCookie { blockdev, buffer })
    }

    /// Read the contents of the disk to determine if the cookie is set or not.
    /// On success, returns a boolean that is true if the hibernate cookie is
    /// set (indicating the on-disk file systems should not be altered).
    pub fn read(&mut self) -> Result<HibernateCookieValue> {
        self.blockdev
            .rewind()
            .context("Failed to seek in hibernate cookie")?;
        let buffer_slice = self.buffer.u8_slice_mut();
        self.blockdev
            .read_exact(&mut buffer_slice[..COOKIE_READ_SIZE])
            .context("Failed to read hibernate cookie")?;

        // Verify there's a GPT header magic where there should be one.
        // This would catch cases like writing to the wrong place or the
        // GPT layout/location changing. This might need enlightenment for a
        // disk with 4kB blocks, this check will let us know that too.
        let gpt_sig_offset = GPT_MAGIC_OFFSET;
        let gpt_sig_offset_end = gpt_sig_offset + 8;
        let mut gpt_sig = [0u8; 8];
        let buffer_slice = self.buffer.u8_slice();
        gpt_sig.copy_from_slice(&buffer_slice[gpt_sig_offset..gpt_sig_offset_end]);
        let gpt_sig = u64::from_le_bytes(gpt_sig);
        if gpt_sig != GPT_MAGIC {
            return Err(HibernateError::CookieError(format!(
                "GPT magic not found: {:x?}",
                gpt_sig
            )))
            .context("Failed to verify GPT magic");
        }

        let magic_start = COOKIE_MAGIC_OFFSET;
        let magic_end = magic_start + COOKIE_SIZE;
        let value = &buffer_slice[magic_start..magic_end];
        if value == COOKIE_NO_RESUME_VALUE {
            Ok(HibernateCookieValue::NoResume)
        } else if value == COOKIE_RESUME_READY_VALUE {
            Ok(HibernateCookieValue::ResumeReady)
        } else if value == COOKIE_RESUME_IN_PROGRESS_VALUE {
            Ok(HibernateCookieValue::ResumeInProgress)
        } else if value == COOKIE_RESUME_ABORTING_VALUE {
            Ok(HibernateCookieValue::ResumeAborting)
        } else if value == COOKIE_EMERGENCY_REBOOT_VALUE {
            Ok(HibernateCookieValue::EmergencyReboot)
        } else {
            Ok(HibernateCookieValue::Uninitialized)
        }
    }

    /// Write the hibernate cookie to disk via a fresh read modify write
    /// operation. The valid parameter indicates whether to write a valid
    /// hibernate cookie (true, indicating on-disk file systems should be
    /// altered), or poison value (false, indicating no impending hibernate
    /// resume, file systems can be mounted RW).
    pub fn write(&mut self, value: HibernateCookieValue) -> Result<()> {
        let existing = self.read()?;
        self.blockdev
            .rewind()
            .context("Failed to seek hibernate cookie")?;
        if value == existing {
            return Ok(());
        }

        let magic_start = COOKIE_MAGIC_OFFSET;
        let magic_end = magic_start + COOKIE_SIZE;
        let cookie = match value {
            HibernateCookieValue::Uninitialized => COOKIE_NO_RESUME_VALUE,
            HibernateCookieValue::NoResume => COOKIE_NO_RESUME_VALUE,
            HibernateCookieValue::ResumeReady => COOKIE_RESUME_READY_VALUE,
            HibernateCookieValue::ResumeInProgress => COOKIE_RESUME_IN_PROGRESS_VALUE,
            HibernateCookieValue::ResumeAborting => COOKIE_RESUME_ABORTING_VALUE,
            HibernateCookieValue::EmergencyReboot => COOKIE_EMERGENCY_REBOOT_VALUE,
        };

        let buffer_slice = self.buffer.u8_slice_mut();
        buffer_slice[magic_start..magic_end].copy_from_slice(cookie);
        let end = COOKIE_WRITE_SIZE;
        self.blockdev
            .write_all(&buffer_slice[..end])
            .context("Failed to write hibernate cookie")?;

        self.blockdev
            .flush()
            .context("Failed to flush hibernate cookie")?;

        self.blockdev
            .sync_all()
            .context("Failed to sync hibernate cookie")?;
        Ok(())
    }
}

/// Public function to read the hibernate cookie and return its current value.
/// The optional path parameter contains the path to the disk to examine. If not
/// supplied, the boot disk will be examined.
pub fn get_hibernate_cookie<P: AsRef<Path>>(path_str: Option<P>) -> Result<HibernateCookieValue> {
    let mut cookie = open_hibernate_cookie(path_str)?;
    cookie.read()
}

/// Public function to set the hibernate cookie value. The value parameter
/// specified what the cookie should be set to. The optional path parameter
/// contains the path to the disk to examine.
pub fn set_hibernate_cookie<P: AsRef<Path>>(
    path: Option<P>,
    value: HibernateCookieValue,
) -> Result<()> {
    let mut cookie = open_hibernate_cookie(path)?;
    cookie.write(value)
}

/// Convert a hibernate cookie value to a human description
pub fn cookie_description(value: &HibernateCookieValue) -> &'static str {
    match value {
        HibernateCookieValue::Uninitialized => "Uninitialized",
        HibernateCookieValue::NoResume => "No Resume",
        HibernateCookieValue::ResumeReady => "Resume Ready",
        HibernateCookieValue::ResumeInProgress => "Resume in Progress",
        HibernateCookieValue::ResumeAborting => "Resume Aborting",
        HibernateCookieValue::EmergencyReboot => "Emergency Reboot",
    }
}

fn open_hibernate_cookie<P: AsRef<Path>>(path_ref: Option<P>) -> Result<HibernateCookie> {
    if let Some(path) = path_ref {
        HibernateCookie::new(path)
    } else {
        HibernateCookie::new(path_to_stateful_block()?)
    }
}
