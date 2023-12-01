// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>

#include <base/command_line.h>
#include <base/time/time.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>

#include "permission_broker/permission_broker.h"

namespace permission_broker {

using brillo::dbus_utils::AsyncEventSequencer;

class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon(const std::string& udev_run_path, const base::TimeDelta& poll_interval)
      : DBusServiceDaemon(kPermissionBrokerServiceName),
        udev_run_path_(udev_run_path),
        poll_interval_(poll_interval) {}
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

 protected:
  void RegisterDBusObjectsAsync(AsyncEventSequencer* sequencer) override {
    broker_ = std::make_unique<PermissionBroker>(bus_, udev_run_path_,
                                                 poll_interval_);
    broker_->RegisterAsync(AsyncEventSequencer::GetDefaultCompletionAction());
  }

 private:
  std::unique_ptr<PermissionBroker> broker_;
  std::string udev_run_path_;
  base::TimeDelta poll_interval_;
};

}  // namespace permission_broker

int main(int argc, char** argv) {
  DEFINE_int32(poll_interval, 100,
               "The interval at which to poll for udev events. "
               "Given in milliseconds.");
  DEFINE_string(udev_run_path, "/run/udev",
                "The path to udev's run directory.");

  brillo::FlagHelper::Init(argc, argv, "Chromium OS Permission Broker");
  brillo::InitLog(brillo::kLogToSyslog);

  permission_broker::Daemon daemon(FLAGS_udev_run_path,
                                   base::Milliseconds(FLAGS_poll_interval));
  return daemon.Run();
}
