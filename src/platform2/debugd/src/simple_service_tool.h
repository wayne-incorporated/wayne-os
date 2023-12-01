// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_SIMPLE_SERVICE_TOOL_H_
#define DEBUGD_SRC_SIMPLE_SERVICE_TOOL_H_

#include <map>
#include <memory>
#include <string>

#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <brillo/dbus/dbus_method_response.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>

namespace debugd {

// Manages the vm_concierge service.
class SimpleServiceTool {
 public:
  explicit SimpleServiceTool(const std::string& name,
                             scoped_refptr<dbus::Bus> bus,
                             const std::string& dbus_service_name,
                             const std::string& dbus_service_path);
  SimpleServiceTool(const SimpleServiceTool&) = delete;
  SimpleServiceTool& operator=(const SimpleServiceTool&) = delete;

  ~SimpleServiceTool() = default;

  void StartService(
      std::map<std::string, std::string> args,
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response);
  void StopService();

 private:
  // Called when the owner of the concierge service changes.
  void HandleNameOwnerChanged(const std::string& old_owner,
                              const std::string& new_owner);

  // Name of the service.
  const std::string name_;

  // Connection to the system bus.
  scoped_refptr<dbus::Bus> bus_;

  // Proxy to the service dbus remote object.  Owned by |bus_|.
  dbus::ObjectProxy* proxy_;

  // Whether the concierge service is running.
  bool running_;

  base::WeakPtrFactory<SimpleServiceTool> weak_factory_{this};
};

}  // namespace debugd

#endif  // DEBUGD_SRC_SIMPLE_SERVICE_TOOL_H_
