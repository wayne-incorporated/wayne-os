// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_DAEMON_H_
#define RUNTIME_PROBE_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/dbus/dbus_object.h>

// Include the protobuf before generated D-Bus adaptors to ensure the protobuf
// messages are defined before adaptors.
// TODO(crbug.com/1255584): Includes headers in alphabetical order.
#include "runtime_probe/proto_bindings/runtime_probe.pb.h"
#include "runtime_probe/dbus_adaptors/org.chromium.RuntimeProbe.h"  // NOLINT(build/include_alpha)

namespace runtime_probe {

// Implementation of the runtime_probe D-Bus methods.
// Daemon class for the runtime_probe D-Bus service daemon.
class Daemon : public brillo::DBusServiceDaemon,
               public org::chromium::RuntimeProbeAdaptor,
               public org::chromium::RuntimeProbeInterface {
 public:
  Daemon();
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

  ~Daemon() override = default;

  template <typename... Types>
  using DBusCallback = typename std::unique_ptr<
      brillo::dbus_utils::DBusMethodResponse<Types...>>;

  // org::chromium::RuntimeProbeInterface overrides.
  void ProbeCategories(DBusCallback<ProbeResult> cb,
                       const ProbeRequest& request) override;
  void GetKnownComponents(DBusCallback<GetKnownComponentsResult> cb,
                          const GetKnownComponentsRequest& request) override;
  void ProbeSsfcComponents(DBusCallback<ProbeSsfcComponentsResponse> cb,
                           const ProbeSsfcComponentsRequest& request) override;

 private:
  // brillo::DBusServiceDaemon overrides.
  int OnInit() override;

  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_DAEMON_H_
