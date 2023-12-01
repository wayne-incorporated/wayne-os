// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements support for allocating large page aligned buffers via the mmap()
//! system call. Loosely adapted from https://github.com/rbranson/rust-mmap, who
//! got it from the rust standard library before it was removed.

use libc::c_void;

use anyhow::Context;
use anyhow::Result;

use crate::hiberutil::get_page_size;
use crate::hiberutil::HibernateError;

pub struct MmapBuffer {
    data: *mut u8,
    len: usize,
}

impl MmapBuffer {
    /// Mmap() up a new anonymous buffer of at least the given size.
    pub fn new(min_len: usize) -> Result<Self> {
        let page_size = get_page_size();

        // Align the size up to a page. The page size is assumed to be a power
        // of two.
        let len = (min_len + page_size - 1) & !(page_size - 1);
        let addr: *const u8 = std::ptr::null();
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANON;
        // Safe because anonymous mmap buffers are always returned zeroed.
        let r = unsafe { libc::mmap(addr as *mut c_void, len as libc::size_t, prot, flags, -1, 0) };

        if r == libc::MAP_FAILED {
            Err(HibernateError::MmapError(libchromeos::sys::Error::last()))
                .context("Cannot create MmapBuffer")
        } else {
            Ok(Self {
                data: r as *mut u8,
                len,
            })
        }
    }

    /// Return the buffer contents as an immutable u8 slice.
    pub fn u8_slice(&self) -> &[u8] {
        // This is safe because the buffer is known to be this large.
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }

    /// Return the buffer contents as a mutable u8 slice.
    pub fn u8_slice_mut(&mut self) -> &mut [u8] {
        // This is safe because the buffer is known to be this large.
        unsafe { std::slice::from_raw_parts_mut(self.data, self.len) }
    }
}

impl Drop for MmapBuffer {
    fn drop(&mut self) {
        if self.len == 0 {
            return;
        }

        // This is safe because munmap() doesn't do anything other than release
        // the memory.
        unsafe {
            libc::munmap(self.data as *mut c_void, self.len as libc::size_t);
        }
    }
}

// It's safe for MmapBuffer to implement Send despite using a raw pointer
// because the object behind that pointer contains to references to thread
// local variables.
unsafe impl Send for MmapBuffer {}
