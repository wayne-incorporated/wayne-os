// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/mount.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/timer/timer.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>

#include "swap_management/swap_management_dbus_adaptor.h"

namespace {

class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon() : DBusServiceDaemon(swap_management::kSwapManagementServiceName) {
    daemon_shutdown_timer_ = std::make_unique<base::OneShotTimer>();
    daemon_shutdown_timer_->Start(
        FROM_HERE, base::Seconds(30),
        base::BindOnce(&Daemon::Quit, weak_factory_.GetWeakPtr()));
  }
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    adaptor_.reset(new swap_management::SwapManagementDBusAdaptor(
        bus_, std::move(daemon_shutdown_timer_)));
    adaptor_->RegisterAsync(
        sequencer->GetHandler("RegisterAsync() failed.", true));
  }

 private:
  std::unique_ptr<swap_management::SwapManagementDBusAdaptor> adaptor_;
  std::unique_ptr<base::OneShotTimer> daemon_shutdown_timer_;
  base::WeakPtrFactory<Daemon> weak_factory_{this};
};
}  // namespace

int main(int argc, char* argv[]) {
  brillo::FlagHelper::Init(argc, argv, "CrOS swap_management");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  if (argc > 1) {
    LOG(ERROR) << "Unhandled arguments; please see --help for more info.";
    return EX_USAGE;
  }

  Daemon().Run();
  return EX_OK;
}
