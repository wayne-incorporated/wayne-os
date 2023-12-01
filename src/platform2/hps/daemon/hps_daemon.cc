// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <chromeos/dbus/service_constants.h>

#include <hps/daemon/dbus_adaptor.h>
#include <hps/hps_impl.h>

#include "hps/daemon/hps_daemon.h"

namespace hps {

HpsDaemon::HpsDaemon(std::unique_ptr<DevInterface> dev,
                     uint32_t poll_time_ms,
                     bool skip_boot,
                     uint32_t version,
                     const base::FilePath& mcu_fw_image,
                     const base::FilePath& fpga_bitstream,
                     const base::FilePath& fpga_app_image)
    : brillo::DBusServiceDaemon(::hps::kHpsServiceName),
      hps_(std::make_unique<HPS_impl>(std::move(dev))),
      poll_time_ms_(poll_time_ms) {
  hps_->Init(version, mcu_fw_image, fpga_bitstream, fpga_app_image);
  if (!skip_boot) {
    LOG(INFO) << "Booting HPS device";
    hps_->Boot();
  }
}

HpsDaemon::~HpsDaemon() = default;

void HpsDaemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  adaptor_.reset(new DBusAdaptor(bus_, std::move(hps_), poll_time_ms_));
  adaptor_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed", true));
}

}  // namespace hps
