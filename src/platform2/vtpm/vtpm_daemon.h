// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_VTPM_DAEMON_H_
#define VTPM_VTPM_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>

#include "vtpm/commands/command.h"
#include "vtpm/dbus_interface.h"
#include "vtpm/vtpm_service.h"

namespace vtpm {

// This class runs the D-Bus service of virtual TPM.
class VtpmDaemon : public brillo::DBusServiceDaemon {
 public:
  VtpmDaemon() = delete;
  explicit VtpmDaemon(Command* command)
      : DBusServiceDaemon(kVtpmServiceName), command_(command) {}
  VtpmDaemon(const VtpmDaemon&) = delete;
  VtpmDaemon& operator=(const VtpmDaemon&) = delete;

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    service_.reset(new VtpmService(command_));
    adaptor_.reset(new VtpmServiceAdaptor(service_.get(), bus_));
    adaptor_->RegisterAsync(
        sequencer->GetHandler("RegisterAsync() failed", true));
  }

 private:
  Command* const command_;
  std::unique_ptr<VtpmService> service_;
  std::unique_ptr<VtpmServiceAdaptor> adaptor_;
};

}  // namespace vtpm

#endif  // VTPM_VTPM_DAEMON_H_
