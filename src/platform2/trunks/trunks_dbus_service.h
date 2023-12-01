// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TRUNKS_DBUS_SERVICE_H_
#define TRUNKS_TRUNKS_DBUS_SERVICE_H_

#include <memory>
#include <string>

#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/dbus/dbus_object.h>

#include "trunks/command_transceiver.h"
#include "trunks/power_manager.h"
#include "trunks/resilience/write_error_tracker.h"
#include "trunks/trunks_interface.pb.h"

namespace trunks {

// TrunksDBusService registers for and handles all incoming D-Bus messages for
// the trunksd system daemon.
//
// Example Usage:
//
// TrunksDBusService service;
// service.set_transceiver(&my_transceiver);
// service.Run();
class TrunksDBusService : public brillo::DBusServiceDaemon {
 public:
  explicit TrunksDBusService(WriteErrorTracker& write_error_tracker);
  TrunksDBusService(const TrunksDBusService&) = delete;
  TrunksDBusService& operator=(const TrunksDBusService&) = delete;

  ~TrunksDBusService() override = default;

  // The |transceiver| will be the target of all incoming TPM commands. This
  // class does not take ownership of |transceiver|.
  void set_transceiver(CommandTransceiver* transceiver) {
    transceiver_ = transceiver;
  }

  // The |power_manager| will be initialized with D-Bus object.
  // This class does not take ownership of |power_manager|.
  void set_power_manager(PowerManager* power_manager) {
    power_manager_ = power_manager;
  }

 protected:
  // Exports D-Bus methods.
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

  // Tears down dependant objects.
  void OnShutdown(int* exit_code) override;

 private:
  // Handles calls to the 'SendCommand' method.
  void HandleSendCommand(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                             const SendCommandResponse&>> response_sender,
                         const SendCommandRequest& request);

  base::WeakPtr<TrunksDBusService> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

  std::unique_ptr<brillo::dbus_utils::DBusObject> trunks_dbus_object_;
  CommandTransceiver* transceiver_ = nullptr;
  PowerManager* power_manager_ = nullptr;
  WriteErrorTracker& write_error_tracker_;

  // Declared last so weak pointers are invalidated first on destruction.
  base::WeakPtrFactory<TrunksDBusService> weak_factory_{this};
};

}  // namespace trunks

#endif  // TRUNKS_TRUNKS_DBUS_SERVICE_H_
