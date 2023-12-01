// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{anyhow, Context, Result};
use libc::{c_char, c_int, dqblk, quotactl, QCMD, QIF_BLIMITS, Q_QUOTAON, Q_SETQUOTA, USRQUOTA};
use libchromeos::sys::{debug, info};
use std::{
    ffi::{CString, OsStr},
    path::Path,
    process::{Command, Stdio},
};

// shadercached user id
const SHADERCACHED_USER: i32 = 333;
// Disk quota () for shadercached when disk is not short in storage space
const NORMAL_DISK_QUOTA: f64 = 0.10;
const QUOTA_BLOCK_SIZE: u64 = 1024;

fn get_device(path: &str) -> Result<String> {
    let rootdev_output = Command::new("rootdev")
        .arg(path)
        .stdout(Stdio::piped())
        .output()?;
    debug!("rootdev output: {:?}", rootdev_output);
    Ok(String::from_utf8(rootdev_output.stdout)?.trim().to_string())
}

fn get_device_size_in_blocks(device_path: &str, block_size: u64) -> Result<u64> {
    let mut path = device_path;
    if let Some(stripped) = device_path.strip_suffix('/') {
        path = stripped;
    }

    let splitted: Vec<&str> = path.split('/').collect();
    let device = splitted
        .last()
        .context("Failed to parse device from device")?;

    let size_512_block = Command::new("cat")
        .arg(format!("/sys/class/block/{}/size", device))
        .stdout(Stdio::piped())
        .output()?;

    debug!(
        "Device {} byte size is {:?}",
        device_path, size_512_block.stdout
    );
    let parsed: u64 = String::from_utf8(size_512_block.stdout)?.trim().parse()?;
    Ok(parsed * 512 / block_size)
}

pub fn set_quota_normal<S: AsRef<OsStr> + ?Sized>(path_like: &S) -> Result<()> {
    let path = Path::new(path_like);
    let path_str = path.to_str().context("Failed to convert path to string")?;

    let device = get_device(path_str)?;
    let max_size = get_device_size_in_blocks(&device, QUOTA_BLOCK_SIZE)?;
    let limit = (max_size as f64 * NORMAL_DISK_QUOTA) as u64;
    set_quota(&device, limit)?;
    quota_on(&device)?;
    Ok(())
}

pub fn set_quota_limited<S: AsRef<OsStr> + ?Sized>(path_like: &S) -> Result<()> {
    let path = Path::new(path_like);
    let path_str = path.to_str().context("Failed to convert path to string")?;

    let device = get_device(path_str)?;
    set_quota(&device, 1)?;
    quota_on(&device)?;
    Ok(())
}

fn set_quota(device: &str, limit: u64) -> Result<()> {
    let mut data = dqblk {
        dqb_bhardlimit: limit,
        dqb_bsoftlimit: limit,
        dqb_curspace: 0,
        dqb_ihardlimit: 0,
        dqb_isoftlimit: 0,
        dqb_curinodes: 0,
        dqb_btime: 0,
        dqb_itime: 0,
        dqb_valid: QIF_BLIMITS,
    };
    info!(
        "Setting shadercached quota, device={}, soft_block={}, hard_block={}",
        device, data.dqb_bsoftlimit, data.dqb_bhardlimit
    );
    let device_cstr = CString::new(device)?;
    let result = unsafe {
        quotactl(
            QCMD(Q_SETQUOTA, USRQUOTA),
            device_cstr.as_c_str().as_ptr() as *const c_char,
            SHADERCACHED_USER as c_int,
            &mut data as *mut _ as *mut c_char,
        )
    };
    if result != 0 {
        return Err(anyhow!(
            "quotactl failed, {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

fn quota_on(device: &str) -> Result<()> {
    // TODO(endlesspring): Remove this once all filesystems are mounted with
    // quota on by default.
    info!("Setting quota on in best effort: device={}", device);
    let device_cstr = CString::new(device)?;
    let result = unsafe {
        quotactl(
            QCMD(Q_QUOTAON, USRQUOTA),
            device_cstr.as_c_str().as_ptr() as *const c_char,
            SHADERCACHED_USER as c_int,
            &mut "" as *mut _ as *mut c_char,
        )
    };
    if result != 0 {
        debug!(
            "quotactl Q_QUOTAON failed, {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(())
}
