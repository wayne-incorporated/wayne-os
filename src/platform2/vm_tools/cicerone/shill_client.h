// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_SHILL_CLIENT_H_
#define VM_TOOLS_CICERONE_SHILL_CLIENT_H_

#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback_forward.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <shill/dbus-proxies.h>

namespace vm_tools {
namespace cicerone {

// Listens for shill signals over D-Bus in order to identify network changes.
class ShillClient final {
 public:
  explicit ShillClient(scoped_refptr<dbus::Bus> bus);
  ShillClient(const ShillClient&) = delete;
  ShillClient& operator=(const ShillClient&) = delete;

  void RegisterDefaultServiceChangedHandler(
      base::RepeatingCallback<void()> callback);

 private:
  void OnShillServiceOwnerChange(const std::string& old_owner,
                                 const std::string& new_owner);
  void OnManagerPropertyChangeRegistration(const std::string& interface,
                                           const std::string& signal_name,
                                           bool success);
  void OnManagerPropertyChange(const std::string& property_name,
                               const brillo::Any& property_value);

  base::RepeatingCallback<void()> default_service_changed_callback_;

  scoped_refptr<dbus::Bus> bus_;
  std::unique_ptr<org::chromium::flimflam::ManagerProxy> manager_proxy_;

  base::WeakPtrFactory<ShillClient> weak_factory_{this};
};

}  // namespace cicerone
}  // namespace vm_tools

#endif  // VM_TOOLS_CICERONE_SHILL_CLIENT_H_
