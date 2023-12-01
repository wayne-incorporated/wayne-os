// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_DAEMON_H_
#define HERMES_DAEMON_H_

#include <memory>
#include <string>

#include <brillo/daemons/dbus_daemon.h>
#include <glib-bridge/glib_bridge.h>
#include <glib-bridge/glib_logger.h>
#include <google-lpa/lpa/card/euicc_card.h>
#include <google-lpa/lpa/core/lpa.h>

#include "hermes/adaptor_factory.h"
#include "hermes/euicc_interface.h"
#include "hermes/executor.h"
#include "hermes/libmbim_impl.h"
#include "hermes/logger.h"
#include "hermes/manager.h"
#include "hermes/smdp.h"
#include "hermes/smds.h"

namespace hermes {

class Daemon : public brillo::DBusServiceDaemon {
 public:
  explicit Daemon(const std::string& fw_path);
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

 private:
  // brillo::Daemon override.
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

  // Objects for use with google-lpa.
  Executor executor_;
  Logger logger_;
  SmdpFactory smdp_;
  SmdsFactory smds_;
  std::unique_ptr<EuiccInterface> modem_;
  std::unique_ptr<LibmbimImpl> libmbim_;
  std::unique_ptr<lpa::core::Lpa> lpa_;
  AdaptorFactory adaptor_factory_;
  std::unique_ptr<Manager> manager_;
  std::unique_ptr<glib_bridge::GlibBridge> glib_bridge_;
  base::FilePath fw_path_;
};

}  // namespace hermes

#endif  // HERMES_DAEMON_H_
