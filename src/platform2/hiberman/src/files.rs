// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! High level support for creating and opening the files used by hibernate.

use std::fs::create_dir;
use std::fs::remove_file;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use log::warn;

/// Define the directory where hibernate state files are kept.
pub const HIBERMETA_DIR: &str = "/mnt/hibermeta";
/// Define the ramfs location where ephemeral files are stored that should not
/// persist across even an unexpected reboot.
pub const TMPFS_DIR: &str = "/run/hibernate/";
/// Define the name of the token file indicating resume is in progress. Note:
/// Services outside of hiberman use this file, so don't change this name
/// carelessly.
const RESUME_IN_PROGRESS_FILE: &str = "resume_in_progress";
/// Define the attempts count file name.
const HIBER_ATTEMPTS_FILE_NAME: &str = "attempts_count";
/// Define the hibernate failures count file name.
const HIBER_FAILURES_FILE_NAME: &str = "hibernate_failures";
/// Define the resume failures count file name.
const RESUME_FAILURES_FILE_NAME: &str = "resume_failures";

/// Open a metrics file.
fn open_cumulative_metrics_file(path: &Path) -> Result<File> {
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .context("Cannot open metrics file")?;
    Ok(file)
}

/// Open the attempts_count file, to keep track of the number of hibernate
/// attempts for metric tracking purposes.
pub fn open_attempts_file() -> Result<File> {
    let path = Path::new(HIBERMETA_DIR).join(HIBER_ATTEMPTS_FILE_NAME);
    open_cumulative_metrics_file(&path)
}

/// Open the hibernate_failures file, to keep track of the number of hibernate
/// failures for metric tracking purposes.
pub fn open_hiber_fails_file() -> Result<File> {
    let path = Path::new(HIBERMETA_DIR).join(HIBER_FAILURES_FILE_NAME);
    open_cumulative_metrics_file(&path)
}

/// Open the resume_failures file, to keep track of the number of resume
/// failures for metric tracking purposes.
pub fn open_resume_failures_file() -> Result<File> {
    let path = Path::new(HIBERMETA_DIR).join(RESUME_FAILURES_FILE_NAME);
    open_cumulative_metrics_file(&path)
}

/// Read the given metrics file
pub fn read_metric_file(file: &mut File) -> Result<String> {
    let mut value_str = String::new();
    file.read_to_string(&mut value_str)
        .context("Failed to parse metric value")?;
    Ok(value_str)
}

/// Increment the value in the counter file
pub fn increment_file_counter(file: &mut File) -> Result<()> {
    let value_str = read_metric_file(file)?;
    let mut value: u32 = value_str.parse().unwrap_or(0);
    value += 1;
    file.rewind()?;
    file.write_all(value.to_string().as_bytes())
        .context("Failed to increment counter")
}

/// Add the resuming file token that other services can check to quickly see if
/// a resume is in progress.
pub fn create_resume_in_progress_file() -> Result<()> {
    if !Path::new(TMPFS_DIR).exists() {
        create_dir(TMPFS_DIR).context("Cannot create tmpfs directory")?;
    }

    let rip_path = Path::new(TMPFS_DIR).join(RESUME_IN_PROGRESS_FILE);
    if rip_path.exists() {
        warn!("{} unexpectedly already exists", rip_path.display());
    }

    OpenOptions::new()
        .write(true)
        .create(true)
        .open(rip_path)
        .context("Failed to create resume token file")?;

    Ok(())
}

/// Remove the resume_in_progress file if it exists. A result is not returned
/// because besides logging (done here) there's really no handling of this error
/// that could be done.
pub fn remove_resume_in_progress_file() {
    let rip_path = Path::new(TMPFS_DIR).join(RESUME_IN_PROGRESS_FILE);
    if rip_path.exists() {
        if let Err(e) = remove_file(&rip_path) {
            warn!("Failed to remove {}: {}", rip_path.display(), e);
            if rip_path.exists() {
                warn!("{} still exists!", rip_path.display());
            }
        }
    }
}
