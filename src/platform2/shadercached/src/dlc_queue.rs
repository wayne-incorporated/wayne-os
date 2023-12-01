// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This module creates thread-safe DlcQueue

use libchromeos::sys::debug;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::common::{SteamAppId, MAX_INSTALL_QUEUE_SIZE};

#[derive(Debug)]
pub struct DlcQueue {
    // LIFO queue - latest installations should be prioritized over older
    // installation requests because on game launch, installations are
    // requested.
    install_queue: VecDeque<SteamAppId>,
    // Uninstall queue does not matter whether it is FIFO or LIFO, they do not
    // have to be prioritized. However, it is using VecQueue so that we can
    // reuse utility functions.
    uninstall_queue: VecDeque<SteamAppId>,
    // Currently installing set of games.
    installing: HashSet<SteamAppId>,
}

pub type DlcQueuePtr = Arc<RwLock<DlcQueue>>;

fn remove_from_queue<T: std::cmp::PartialEq>(queue: &mut VecDeque<T>, to_remove: &T) {
    if let Some(index) = queue.iter().position(|item| *item == *to_remove) {
        queue.remove(index);
    }
}

impl DlcQueue {
    pub fn queue_install(self: &mut DlcQueue, steam_app_id: &SteamAppId) {
        if self.installing.contains(steam_app_id) {
            return;
        }

        remove_from_queue(&mut self.uninstall_queue, steam_app_id);
        remove_from_queue(&mut self.install_queue, steam_app_id);

        // Put the item to the front of the vector, so that pop_front() returns
        // it (LIFO).
        self.install_queue.push_front(*steam_app_id);
        if self.install_queue.len() > MAX_INSTALL_QUEUE_SIZE {
            if let Some(removed) = self.install_queue.pop_back() {
                debug!("Max install queue size reached, removed {}", removed);
            }
        }
    }

    pub fn next_to_install(self: &mut DlcQueue) -> Option<SteamAppId> {
        if let Some(app_id) = self.install_queue.pop_front() {
            // Add the item to installing set, so that we know what is being
            // installed preemptively.
            self.add_installing(&app_id);
            return Some(app_id);
        }
        None
    }

    pub fn count_installing_dlcs(self: &DlcQueue) -> usize {
        self.installing.len()
    }

    pub fn remove_installing(self: &mut DlcQueue, steam_app_id: &SteamAppId) -> bool {
        self.installing.remove(steam_app_id)
    }

    fn add_installing(self: &mut DlcQueue, steam_app_id: &SteamAppId) -> bool {
        self.installing.insert(*steam_app_id)
    }

    pub fn queue_uninstall_multi(self: &mut DlcQueue, ids: &HashSet<SteamAppId>) {
        for steam_app_id in ids {
            self.installing.remove(steam_app_id);
        }
        for steam_app_id in ids {
            remove_from_queue(&mut self.install_queue, steam_app_id);
        }
        self.uninstall_queue.extend(ids);
    }

    pub fn queue_uninstall(self: &mut DlcQueue, steam_app_id: &SteamAppId) {
        self.remove_installing(steam_app_id);

        remove_from_queue(&mut self.install_queue, steam_app_id);

        self.uninstall_queue.push_front(*steam_app_id);
    }

    pub fn next_to_uninstall(self: &mut DlcQueue) -> Option<SteamAppId> {
        self.uninstall_queue.pop_front()
    }
}

impl std::fmt::Display for DlcQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "DlcQueue{{ install_queue:{:?} installing:{:?} uninstall_queue:{:?} }}",
            self.install_queue, self.installing, self.uninstall_queue,
        ))?;
        Ok(())
    }
}

pub fn new_queue() -> DlcQueuePtr {
    Arc::new(RwLock::new(DlcQueue {
        install_queue: VecDeque::new(),
        installing: HashSet::new(),
        uninstall_queue: VecDeque::new(),
    }))
}
