// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_HELPERS_SHILL_PROXY_H_
#define DEBUGD_SRC_HELPERS_SHILL_PROXY_H_

#include <memory>
#include <optional>
#include <string>

#include <base/memory/ref_counted.h>

#include "debugd/src/helpers/system_service_proxy.h"

namespace debugd {

// Implements a D-Bus proxy to interact with the shill system service.
// See SystemServiceProxy for typical usages.
class ShillProxy : public SystemServiceProxy {
 public:
  // Creates a D-Bus proxy for the shill system service and connects to the
  // system bus. Returns an instance after it successfully connects to the
  // system bus, or nullptr on error.
  static std::unique_ptr<ShillProxy> Create();

  ~ShillProxy() override = default;

  // Gets the properties associated with the interface named |interface_name|
  // of a D-Bus object identified by |object_path| through the GetProperties()
  // D-Bus method exposed by shill. Returns std::nullopt on error.
  std::optional<base::Value::Dict> GetProperties(
      const std::string& interface_name,
      const dbus::ObjectPath& object_path) override;

 private:
  explicit ShillProxy(scoped_refptr<dbus::Bus> bus);
  ShillProxy(const ShillProxy&) = delete;
  ShillProxy& operator=(const ShillProxy&) = delete;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_HELPERS_SHILL_PROXY_H_
