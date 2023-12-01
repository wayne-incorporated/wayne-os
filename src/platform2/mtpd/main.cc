// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A simple daemon to detect and access PTP/MTP devices.

#include <memory>

#include <sysexits.h>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>

#include "mtpd/mtpd_server_impl.h"

using base::CommandLine;

namespace {

// Messages logged at a level lower than this don't get logged anywhere.
static const char kMinLogLevelSwitch[] = "minloglevel";

void SetupLogging() {
  brillo::InitLog(brillo::kLogToSyslog);

  std::string log_level_str =
      CommandLine::ForCurrentProcess()->GetSwitchValueASCII(kMinLogLevelSwitch);
  int log_level = 0;
  if (base::StringToInt(log_level_str, &log_level) && log_level >= 0)
    logging::SetMinLogLevel(log_level);
}

}  // namespace

namespace mtpd {

class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon() : DBusServiceDaemon(kMtpdServiceName) {}
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

 protected:
  // brillo::DBusServiceDaemon overrides.
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    adaptor_.reset(new MtpdServer(bus_));
    adaptor_->RegisterAsync(
        sequencer->GetHandler("RegisterAsync() failed", true));
  }

  int OnInit() override {
    int exit_code = DBusServiceDaemon::OnInit();
    if (exit_code != EX_OK)
      return exit_code;

    // The lifetime of |adaptor_| is tied to this instance,
    // so base::Unretained here is safe.
    controller_ = base::FileDescriptorWatcher::WatchReadable(
        adaptor_->GetDeviceEventDescriptor(),
        base::BindRepeating(&MtpdServer::ProcessDeviceEvents,
                            base::Unretained(adaptor_.get())));
    return EX_OK;
  }

  void OnShutdown(int* exit_code) override {
    controller_.reset();
    DBusServiceDaemon::OnShutdown(exit_code);
  }

 private:
  std::unique_ptr<MtpdServer> adaptor_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> controller_;
};

}  // namespace mtpd

int main(int argc, char** argv) {
  CommandLine::Init(argc, argv);
  SetupLogging();

  return mtpd::Daemon().Run();
}
