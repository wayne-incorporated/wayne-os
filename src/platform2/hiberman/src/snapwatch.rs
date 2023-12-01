// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements a monitor that watches for a given set of dm-snapshots to become
//! nearly full, and kicks off an abort if a threshold is reached.

use anyhow::Result;
use log::error;
use log::info;
use log::warn;

use std::convert::TryInto;
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::thread::{self};
use std::time::Duration;

use crate::hiberutil::emergency_reboot;
use crate::resume_dbus::send_abort;
use crate::volume::get_snapshot_size;

/// Define how full the snapshot has to get (as a percentage of its overall
/// space) before resume is aborted and the snapshot is merged.
const SNAPSHOT_FULL_ABORT_PERCENT: i32 = 75;

pub struct DmSnapshotSpaceMonitor {
    channel_tx: Sender<SnapshotMonitorMessage>,
    thread: Option<JoinHandle<()>>,
}

impl DmSnapshotSpaceMonitor {
    pub fn new(name: &str) -> Result<Self> {
        let (channel_tx, channel_rx) = channel();
        let state = DmSnapshotSpaceMonitorState {
            name: name.to_string(),
            channel_rx,
            report_percent: 10,
            aborted: false,
        };

        let thread = Some(thread::spawn(|| snapshot_monitor_thread(state)));

        Ok(Self { channel_tx, thread })
    }

    pub fn stop(&mut self) {
        let thread = self.thread.take();
        if let Some(thread) = thread {
            self.channel_tx
                .send(SnapshotMonitorMessage::Stop)
                .expect("Snapshot monitor channel should never fill");
            if let Err(e) = thread.join() {
                warn!("Failed to join dm-snapshot space monitor thread: {:?}", e);
            }
        }
    }
}

struct DmSnapshotSpaceMonitorState {
    name: String,
    channel_rx: Receiver<SnapshotMonitorMessage>,
    report_percent: i32,
    aborted: bool,
}

enum SnapshotMonitorMessage {
    Stop,
}

fn snapshot_monitor_thread(mut state: DmSnapshotSpaceMonitorState) {
    info!("Started watching snapshot {}", state.name);
    loop {
        match get_snapshot_size(&state.name) {
            Ok((allocated, total)) => {
                let percent_full = allocated * 100 / total;
                let percent_full: i32 = percent_full.try_into().unwrap_or(i32::MAX);

                // Print logs occasionally as the snapshot progresses towards being full.
                if percent_full >= state.report_percent {
                    info!("Snapshot {} is {}% full", state.name, percent_full);
                    while state.report_percent <= percent_full {
                        state.report_percent += 10;
                    }
                }

                // Abort resume if the snapshot becomes close enough to full to
                // be concerning, given that we only check it periodically.
                if !state.aborted && percent_full > SNAPSHOT_FULL_ABORT_PERCENT {
                    error!(
                        "Snapshot {} is {}% full, aborting resume",
                        state.name, percent_full
                    );
                    state.aborted = true;
                    match send_abort(&format!(
                        "Snapshot {} became >={}% full",
                        state.name, SNAPSHOT_FULL_ABORT_PERCENT
                    )) {
                        Ok(()) => {
                            state.aborted = true;
                        }
                        Err(e) => {
                            error!("Attempting to abort returned: {}", e);
                            emergency_reboot("Failed to abort from snapshot monitor thread");
                        }
                    }
                }

                // If the snapshot is totally full, the kernel has deactivated
                // it, and it's in an inconsistent state. Don't try to sync it,
                // we're better off doing an emergency reboot to get back to a
                // consistent state from hibernate time.
                if percent_full == 100 {
                    error!("Snapshot {} is totally full, rebooting!", state.name);
                    emergency_reboot("Snapshot filled completely");
                }
            }
            Err(e) => {
                warn!("Error getting snapshot size: {}", e);
            }
        }

        // Wait for a bit, or receive a message from the main thread.
        match state.channel_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(message) => match message {
                SnapshotMonitorMessage::Stop => {
                    info!("Stopped monitoring {}", state.name);
                    break;
                }
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(e) => {
                error!("Failed to recv in dm-snapshot monitor: {}", e);
                break;
            }
        }
    }
}
