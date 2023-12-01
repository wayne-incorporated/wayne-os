// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use async_trait::async_trait;
use log::debug;
use tokio::sync::mpsc;
use uwb_core::error::{Error as UwbError, Result as UwbResult};
use uwb_core::uci::{UciHal, UciHalPacket};

// TODO(b/229540825): Implement the UCI HAL for ChromeOS.
/// A UciHal implementation for ChromeOS.
pub struct UciHalImpl {}

#[async_trait]
impl UciHal for UciHalImpl {
    async fn open(&mut self, _packet_sender: mpsc::UnboundedSender<UciHalPacket>) -> UwbResult<()> {
        debug!("UciHalImpl::open() is not implemented");
        Err(UwbError::Unknown)
    }
    async fn close(&mut self) -> UwbResult<()> {
        debug!("UciHalImpl::close() is not implemented");
        Err(UwbError::Unknown)
    }
    async fn send_packet(&mut self, packet: UciHalPacket) -> UwbResult<()> {
        debug!("UciHalImpl::send_packet({:?}) is not implemented", packet);
        Err(UwbError::Unknown)
    }
}
