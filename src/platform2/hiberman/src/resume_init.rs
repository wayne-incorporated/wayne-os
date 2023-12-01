// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Executes early resume initialization.

use std::path::PathBuf;
use std::unreachable;

use anyhow::Context;
use anyhow::Result;
use log::debug;
use log::info;
use log::warn;

use crate::cookie::cookie_description;
use crate::cookie::get_hibernate_cookie;
use crate::cookie::set_hibernate_cookie;
use crate::cookie::HibernateCookieValue;
use crate::files::create_resume_in_progress_file;
use crate::hiberutil::HibernateError;
use crate::hiberutil::ResumeInitOptions;
use crate::volume::VolumeManager;

pub struct ResumeInitConductor {
    options: ResumeInitOptions,
}

impl ResumeInitConductor {
    pub fn new(options: ResumeInitOptions) -> Self {
        Self { options }
    }

    pub fn resume_init(&mut self) -> Result<()> {
        let cookie =
            get_hibernate_cookie::<PathBuf>(None).context("Failed to get hibernate cookie")?;

        if cookie == HibernateCookieValue::ResumeReady || self.options.force {
            if cookie != HibernateCookieValue::ResumeReady {
                info!("Hibernate cookie was not set, continuing anyway due to --force");
            }

            self.prepare_resume()?;

            debug!("Done with resume init");

            return Ok(());
        }

        // no resume pending

        match cookie {
            // In the most common case, no resume from hibernate will be imminent.
            HibernateCookieValue::NoResume | HibernateCookieValue::Uninitialized => {
                debug!("Hibernate cookie was not set, doing nothing");

                if cookie == HibernateCookieValue::Uninitialized {
                    set_hibernate_cookie::<PathBuf>(None, HibernateCookieValue::NoResume)
                        .context("Failed to set hibernate cookie to NoResume")?;
                }

                Err(HibernateError::CookieError(
                    "Cookie not set, doing nothing".to_string(),
                ))
                .context("Not preparing for resume")
            }

            // This is the error path, where the system rebooted unexpectedly
            // while a resume or abort was underway. If a resume was
            // interrupted, the snapshots may contain data we want to preserve
            // (logs for investigation). If an abort was interrupted, the
            // stateful disk could be halfway merged. Either way, set up the
            // snapshots for a merge later in boot.
            HibernateCookieValue::ResumeInProgress | HibernateCookieValue::ResumeAborting => {
                info!(
                    "Hibernate interrupted (cookie was {}), wiring up snapshots",
                    cookie_description(&cookie)
                );

                self.setup_snapshots()?;

                // The snapshots are valid and wired. Indicate to the main
                // hiberman resume process that it should immediately abort and
                // merge.
                set_hibernate_cookie::<PathBuf>(None, HibernateCookieValue::ResumeAborting)
                    .context("Failed to set hibernate cookie to ResumeAborting")?;

                Ok(())
            }

            // This is the bad error path, where the previous attempt to resume
            // or abort resulted in an emergency reboot. Do nothing here, as our
            // only goal in this state is to replay logs and proceed with a
            // normal boot.
            HibernateCookieValue::EmergencyReboot => {
                warn!("System emergency rebooted, not wiring up snapshots");

                Err(HibernateError::CookieError(
                    "Emergency reboot, not wiring up snapshots".to_string(),
                ))
                .context("Not preparing for resume")
            }

            HibernateCookieValue::ResumeReady => {
                unreachable!("ResumeReady should have been handled above");
            }
        }
    }

    fn prepare_resume(&self) -> Result<()> {
        self.setup_snapshots()?;

        // Create the resume_in_progress file other system services use as a
        // quick check to determine a resume is underway.
        create_resume_in_progress_file()?;

        // The snapshots are valid, so indicate that a resume is in progress,
        // and the main resume process later should go for it.
        set_hibernate_cookie::<PathBuf>(None, HibernateCookieValue::ResumeInProgress)
            .context("Failed to set hibernate cookie to ResumeInProgress")
    }

    /// Wire up the snapshot images on top of the logical volumes.
    fn setup_snapshots(&self) -> Result<()> {
        // First clear the cookie to try and minimize the chances of getting
        // stuck in a boot loop. If this is the first time through (eg for a
        // valid resume image), the snapshots are not yet valid and have no
        // data, so not wiring them up upon interruption is the right thing to
        // do. If this is not the first time around (eg crash/powerloss during
        // resume), then this at least avoids getting stuck in a boot loop due
        // to a crash within this setup code.
        set_hibernate_cookie::<PathBuf>(None, HibernateCookieValue::NoResume)
            .context("Failed to set hibernate cookie to NoResume")?;
        let mut volmgr = VolumeManager::new().context("Failed to create volume manager")?;

        volmgr
            .setup_stateful_snapshots()
            .context("Failed to set up stateful snapshots")?;

        // Change the thinpool to be read-only to avoid accidental thinpool
        // metadata changes that somehow get around the snapshot. Ideally we'd
        // do this before activating all the LVs under the snapshots, but doing
        // the activation seems to flip the pool back to being writeable.
        volmgr
            .activate_thinpool_ro()
            .context("Failed to activate thinpool RO")?;

        Ok(())
    }
}
