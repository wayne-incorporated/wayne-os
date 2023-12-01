// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_VTPM_SERVICE_H_
#define VTPM_VTPM_SERVICE_H_

#include <memory>
#include <string>
#include <utility>

#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/dbus/dbus_object.h>
#include <trunks/trunks_factory.h>

#include "vtpm/commands/command.h"
#include "vtpm/dbus_interface.h"
#include "vtpm/vtpm_interface.pb.h"

// Requires `vtpm/vtpm_interface.pb.h`
#include "vtpm/dbus_adaptors/org.chromium.Vtpm.h"

namespace vtpm {

class VtpmService : public org::chromium::VtpmInterface {
 public:
  // Creates an instance. The command execution is delegated to `command`.
  explicit VtpmService(Command* command);
  VtpmService(const VtpmService&) = delete;
  VtpmService& operator=(const VtpmService&) = delete;

  ~VtpmService() override = default;

  // org::chromium::VtpmInterface overrides.
  void SendCommand(
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<SendCommandResponse>> response,
      const SendCommandRequest& request) override;

 private:
  // Simply make `response` returns `send_commnad_response` put in a
  // `SendCommandResponse`. This helper is made so it can converts a callback
  // that is cancelled automatically once `this` is destroyed`.
  void RunResponseCallback(
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<SendCommandResponse>> response,
      const std::string& send_command_response);
  // Posts `RunResponseCallback` to the D-Bus calling thread. The `PostTask()`
  // operation regardless where it is called, even if it's already on the D-Bus
  // calling thread.
  void PostResponseCallback(
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<SendCommandResponse>> response,
      const std::string& send_command_response);
  // Wraps `PostResponseCallback()` into `CommandResponseCallback` type, which
  // `command_` can call directly.
  CommandResponseCallback MakeCallingThreadCallback(
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<SendCommandResponse>>
          response);

  scoped_refptr<base::TaskRunner> origin_task_runner_ =
      base::SingleThreadTaskRunner::GetCurrentDefault();

  // the delegate of the TPM command execution.
  Command* const command_;

  // Declared last so any weak pointers are destroyed first.
  base::WeakPtrFactory<VtpmService> weak_factory_{this};
};

class VtpmServiceAdaptor : public org::chromium::VtpmAdaptor {
 public:
  explicit VtpmServiceAdaptor(org::chromium::VtpmInterface* vtpm_interface,
                              scoped_refptr<dbus::Bus> bus)
      : org::chromium::VtpmAdaptor(vtpm_interface),
        dbus_object_(nullptr, bus, dbus::ObjectPath(kVtpmServicePath)) {}
  VtpmServiceAdaptor(const VtpmServiceAdaptor&) = delete;
  VtpmServiceAdaptor& operator=(const VtpmServiceAdaptor&) = delete;

  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
    RegisterWithDBusObject(&dbus_object_);
    dbus_object_.RegisterAsync(std::move(cb));
  }

 private:
  brillo::dbus_utils::DBusObject dbus_object_;
};

}  // namespace vtpm

#endif  // VTPM_VTPM_SERVICE_H_
