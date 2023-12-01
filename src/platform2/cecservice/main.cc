// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/command_line.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>

#include "cecservice/cecservice_dbus_adaptor.h"

namespace {

// Main daemon class.
class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon() : DBusServiceDaemon(cecservice::kCecServiceName) {}
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

  ~Daemon() override = default;

 protected:
  // brillo::DBusServiceDaemon:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    adaptor_ = std::make_unique<cecservice::CecServiceDBusAdaptor>(bus_);
    adaptor_->RegisterAsync(sequencer->GetHandler(
        "RegisterAsync() failed.", true));
  }

 private:
  std::unique_ptr<cecservice::CecServiceDBusAdaptor> adaptor_;
};

}  // namespace

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  return Daemon().Run();
}
