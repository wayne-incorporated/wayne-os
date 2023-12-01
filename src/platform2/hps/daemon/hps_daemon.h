// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_DAEMON_HPS_DAEMON_H_
#define HPS_DAEMON_HPS_DAEMON_H_

#include <memory>
#include <string>

#include <brillo/daemons/dbus_daemon.h>

#include <hps/daemon/dbus_adaptor.h>
#include <hps/hps_impl.h>
#include <hps/hps.h>

namespace hps {

class HpsDaemon : public brillo::DBusServiceDaemon {
 public:
  HpsDaemon(std::unique_ptr<DevInterface> dev,
            uint32_t poll_time_ms,
            bool skip_boot,
            uint32_t version,
            const base::FilePath& mcu_fw_image,
            const base::FilePath& fpga_bitstream,
            const base::FilePath& fpga_app_image);
  HpsDaemon(const HpsDaemon&) = delete;
  HpsDaemon& operator=(const HpsDaemon&) = delete;
  ~HpsDaemon() override;

 private:
  friend class HpsDaemonTest;

  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

  std::unique_ptr<DBusAdaptor> adaptor_;
  std::unique_ptr<HPS> hps_;
  const uint32_t poll_time_ms_;
};

}  // namespace hps

#endif  // HPS_DAEMON_HPS_DAEMON_H_
