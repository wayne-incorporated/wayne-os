// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_POWER_MANAGER_CLIENT_H_
#define VM_TOOLS_CONCIERGE_POWER_MANAGER_CLIENT_H_

#include <stdint.h>

#include <string>

#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <gtest/gtest_prod.h>

namespace vm_tools {
namespace concierge {

// Provides a proxy connection to the power manager dbus service.
class PowerManagerClient final {
 public:
  explicit PowerManagerClient(scoped_refptr<dbus::Bus> bus);
  PowerManagerClient(const PowerManagerClient&) = delete;
  PowerManagerClient& operator=(const PowerManagerClient&) = delete;

  ~PowerManagerClient();

  // Registers a suspend delay with the power manager.  Calls
  // |suspend_imminent_cb| whenever the device is about to suspend and
  // |suspend_done_cb| when the device resumes.
  void RegisterSuspendDelay(const base::RepeatingClosure& suspend_imminent_cb,
                            const base::RepeatingClosure& suspend_done_cb);

 private:
  void HandleSuspendImminent(dbus::Signal* signal);
  void HandleSuspendDone(dbus::Signal* signal);

  void HandleNameOwnerChanged(const std::string& old_owner,
                              const std::string& new_owner);

  void HandleSignalConnected(const std::string& interface_name,
                             const std::string& signal_name,
                             bool success);

  scoped_refptr<dbus::Bus> bus_;
  dbus::ObjectProxy* power_manager_proxy_;  // owned by |bus_|

  int32_t delay_id_;
  int32_t current_suspend_id_;

  base::RepeatingClosure suspend_imminent_cb_;
  base::RepeatingClosure suspend_done_cb_;

  base::WeakPtrFactory<PowerManagerClient> weak_factory_{this};

  FRIEND_TEST(PowerManagerClientTest, SuspendReadiness);
  FRIEND_TEST(PowerManagerClientTest, SuspendImminent);
  FRIEND_TEST(PowerManagerClientTest, SuspendDone);
  FRIEND_TEST(PowerManagerClientTest, WrongSuspendId);
  FRIEND_TEST(PowerManagerClientTest, MultipleSuspendImminents);
  FRIEND_TEST(PowerManagerClientTest, NameOwnerChanged);
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_POWER_MANAGER_CLIENT_H_
