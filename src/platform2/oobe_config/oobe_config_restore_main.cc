// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/syslog_logging.h>
#include <dbus/oobe_config/dbus-constants.h>

#include "oobe_config/oobe_config.h"
#include "oobe_config/oobe_config_restore_service.h"

using brillo::dbus_utils::AsyncEventSequencer;
using brillo::dbus_utils::DBusObject;

namespace oobe_config {

namespace {

void InitLog() {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  logging::SetLogItems(true /* enable_process_id */,
                       true /* enable_thread_id */, true /* enable_timestamp */,
                       true /* enable_tickcount */);
}

}  // namespace

class OobeConfigRestoreDaemon : public brillo::DBusServiceDaemon {
 public:
  OobeConfigRestoreDaemon()
      : DBusServiceDaemon(kOobeConfigRestoreServiceName) {}
  OobeConfigRestoreDaemon(const OobeConfigRestoreDaemon&) = delete;
  OobeConfigRestoreDaemon& operator=(const OobeConfigRestoreDaemon&) = delete;

 protected:
  void RegisterDBusObjectsAsync(AsyncEventSequencer* sequencer) override {
    auto dbus_object = std::make_unique<DBusObject>(
        nullptr, bus_,
        org::chromium::OobeConfigRestoreAdaptor::GetObjectPath());

    service_ =
        std::make_unique<OobeConfigRestoreService>(std::move(dbus_object));
    service_->RegisterAsync(sequencer->GetHandler(
        "OobeConfigRestoreService.RegisterAsync() failed.", true));
  }

  void OnShutdown(int* return_code) override {
    DBusServiceDaemon::OnShutdown(return_code);
    service_.reset();
  }

 private:
  std::unique_ptr<OobeConfigRestoreService> service_;
};

// Runs OobeConfigRestoreDaemon.
int RunDaemon() {
  LOG(INFO) << "Starting oobe_config_restore daemon";
  OobeConfigRestoreDaemon daemon;
  int res = daemon.Run();

  LOG(INFO) << "oobe_config_restore stopping with exit code " << res;
  return res;
}

}  // namespace oobe_config

int main(int argc, char* argv[]) {
  oobe_config::InitLog();
  return oobe_config::RunDaemon();
}
