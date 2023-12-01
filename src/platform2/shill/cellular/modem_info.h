// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MODEM_INFO_H_
#define SHILL_CELLULAR_MODEM_INFO_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/cellular/dbus_objectmanager_proxy_interface.h"
#include "shill/data_types.h"
#include "shill/error.h"

namespace shill {

class ControlInterface;
class Manager;
class Modem;
class PendingActivationStore;

// Handles the modem manager service and creates and destroys modem instances.
class ModemInfo {
 public:
  ModemInfo(ControlInterface* control, Manager* manager);
  ModemInfo(const ModemInfo&) = delete;
  ModemInfo& operator=(const ModemInfo&) = delete;

  virtual ~ModemInfo();

  // Starts watching for and handling the DBus modem manager service.
  void Start();

  // Called when a Cellular Device is created.
  virtual void OnDeviceInfoAvailable(const std::string& link_name);

  ControlInterface* control_interface() const { return control_interface_; }
  Manager* manager() const { return manager_; }
  PendingActivationStore* pending_activation_store() const {
    return pending_activation_store_.get();
  }

 protected:
  // The following methods are virtual to support test overrides.
  virtual std::unique_ptr<DBusObjectManagerProxyInterface> CreateProxy();
  virtual std::unique_ptr<Modem> CreateModem(
      const RpcIdentifier& path, const InterfaceToProperties& properties);

 private:
  friend class MockModemInfo;
  friend class ModemInfoTest;

  FRIEND_TEST(ModemInfoTest, AddRemoveModem);
  FRIEND_TEST(ModemInfoTest, ConnectDisconnect);
  FRIEND_TEST(ModemInfoTest, AddRemoveInterfaces);
  FRIEND_TEST(ModemInfoTest, Connect);
  FRIEND_TEST(ModemInfoTest, StartStop);
  FRIEND_TEST(ModemInfoTest, ModemManagerDown);
  FRIEND_TEST(ModemInfoTest, RestartModemManager);

  // Stops watching for the DBus modem manager service and destroys any
  // associated modems.
  void Stop();

  void Connect();
  void Disconnect();

  bool ModemExists(const RpcIdentifier& path) const;
  void AddModem(const RpcIdentifier& path,
                const InterfaceToProperties& properties);
  void RemoveModem(const RpcIdentifier& path);

  // Service availability callbacks.
  void OnAppeared();
  void OnVanished();

  // DBusObjectManagerProxyDelegate signal methods
  void OnInterfacesAddedSignal(const RpcIdentifier& object_path,
                               const InterfaceToProperties& properties);
  void OnInterfacesRemovedSignal(const RpcIdentifier& object_path,
                                 const std::vector<std::string>& interfaces);

  // DBusObjectManagerProxyDelegate method callbacks
  void OnGetManagedObjectsReply(
      const ObjectsWithProperties& objects_with_properties, const Error& error);

  ControlInterface* control_interface_;
  Manager* manager_;
  std::unique_ptr<DBusObjectManagerProxyInterface> proxy_;
  std::map<RpcIdentifier, std::unique_ptr<Modem>> modems_;
  bool service_connected_ = false;

  // Post-payment activation state of the modem.
  std::unique_ptr<PendingActivationStore> pending_activation_store_;

  base::WeakPtrFactory<ModemInfo> weak_ptr_factory_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MODEM_INFO_H_
