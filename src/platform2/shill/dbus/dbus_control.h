// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_DBUS_CONTROL_H_
#define SHILL_DBUS_DBUS_CONTROL_H_

#include <memory>
#include <string>

#include <brillo/dbus/exported_object_manager.h>

#include "shill/control_interface.h"

namespace shill {

class EventDispatcher;
class Manager;

class DBusControl : public ControlInterface {
 public:
  static RpcIdentifier NullRpcIdentifier();

  explicit DBusControl(EventDispatcher* dispatcher);
  ~DBusControl() override;

  void RegisterManagerObject(
      Manager* manager, base::OnceClosure registration_done_callback) override;
  std::unique_ptr<DeviceAdaptorInterface> CreateDeviceAdaptor(
      Device* device) override;
  std::unique_ptr<IPConfigAdaptorInterface> CreateIPConfigAdaptor(
      IPConfig* ipconfig) override;
  std::unique_ptr<ManagerAdaptorInterface> CreateManagerAdaptor(
      Manager* manager) override;
  std::unique_ptr<ProfileAdaptorInterface> CreateProfileAdaptor(
      Profile* profile) override;
  std::unique_ptr<RpcTaskAdaptorInterface> CreateRpcTaskAdaptor(
      RpcTask* task) override;
  std::unique_ptr<ServiceAdaptorInterface> CreateServiceAdaptor(
      Service* service) override;
#ifndef DISABLE_VPN
  std::unique_ptr<ThirdPartyVpnAdaptorInterface> CreateThirdPartyVpnAdaptor(
      ThirdPartyVpnDriver* driver) override;
#endif

  // The caller retains ownership of 'delegate'.  It must not be deleted before
  // the proxy.
  std::unique_ptr<PowerManagerProxyInterface> CreatePowerManagerProxy(
      PowerManagerProxyDelegate* delegate,
      const base::RepeatingClosure& service_appeared_callback,
      const base::RepeatingClosure& service_vanished_callback) override;

  std::unique_ptr<SupplicantProcessProxyInterface> CreateSupplicantProcessProxy(
      const base::RepeatingClosure& service_appeared_callback,
      const base::RepeatingClosure& service_vanished_callback) override;

  std::unique_ptr<SupplicantInterfaceProxyInterface>
  CreateSupplicantInterfaceProxy(SupplicantEventDelegateInterface* delegate,
                                 const RpcIdentifier& object_path) override;

  std::unique_ptr<SupplicantNetworkProxyInterface> CreateSupplicantNetworkProxy(
      const RpcIdentifier& object_path) override;

  // See comment in supplicant_bss_proxy.h, about bare pointer.
  std::unique_ptr<SupplicantBSSProxyInterface> CreateSupplicantBSSProxy(
      WiFiEndpoint* wifi_endpoint, const RpcIdentifier& object_path) override;

  std::unique_ptr<UpstartProxyInterface> CreateUpstartProxy() override;

  std::unique_ptr<DHCPCDListenerInterface> CreateDHCPCDListener(
      DHCPProvider* provider) override;

  std::unique_ptr<DHCPProxyInterface> CreateDHCPProxy(
      const std::string& service) override;

  std::unique_ptr<DBusPropertiesProxy> CreateDBusPropertiesProxy(
      const RpcIdentifier& path, const std::string& service) override;

  std::unique_ptr<DBusObjectManagerProxyInterface> CreateDBusObjectManagerProxy(
      const RpcIdentifier& path,
      const std::string& service,
      const base::RepeatingClosure& service_appeared_callback,
      const base::RepeatingClosure& service_vanished_callback) override;

  // Proxies for ModemManager1 interfaces
  std::unique_ptr<mm1::ModemLocationProxyInterface> CreateMM1ModemLocationProxy(
      const RpcIdentifier& path, const std::string& service) override;

  std::unique_ptr<mm1::ModemModem3gppProxyInterface>
  CreateMM1ModemModem3gppProxy(const RpcIdentifier& path,
                               const std::string& service) override;

  std::unique_ptr<mm1::ModemModem3gppProfileManagerProxyInterface>
  CreateMM1ModemModem3gppProfileManagerProxy(
      const RpcIdentifier& path, const std::string& service) override;

  std::unique_ptr<mm1::ModemProxyInterface> CreateMM1ModemProxy(
      const RpcIdentifier& path, const std::string& service) override;

  std::unique_ptr<mm1::ModemSignalProxyInterface> CreateMM1ModemSignalProxy(
      const RpcIdentifier& path, const std::string& service) override;

  std::unique_ptr<mm1::ModemSimpleProxyInterface> CreateMM1ModemSimpleProxy(
      const RpcIdentifier& path, const std::string& service) override;

  std::unique_ptr<mm1::SimProxyInterface> CreateMM1SimProxy(
      const RpcIdentifier& path, const std::string& service) override;

#if !defined(DISABLE_FLOSS)
  std::unique_ptr<BluetoothManagerProxyInterface> CreateBluetoothManagerProxy(
      const base::RepeatingClosure& service_appeared_callback) override;

  std::unique_ptr<BluetoothAdapterProxyInterface> CreateBluetoothAdapterProxy(
      int32_t hci) override;

  std::unique_ptr<BluetoothBlueZProxyInterface> CreateBluetoothBlueZProxy()
      override;
#endif  // DISABLE_FLOSS

 private:
  void OnDBusServiceRegistered(base::OnceCallback<void(bool)> completion_action,
                               bool success);
  void TakeServiceOwnership(bool success);

  static const char kNullPath[];

  // Use separate bus connection for adaptors and proxies.  This allows the
  // proxy to receive all broadcast signal messages that it is interested in.
  // Refer to crbug.com/446837 for more info.
  scoped_refptr<dbus::Bus> adaptor_bus_;
  scoped_refptr<dbus::Bus> proxy_bus_;
  EventDispatcher* dispatcher_;
  base::OnceClosure registration_done_callback_;
};

}  // namespace shill

#endif  // SHILL_DBUS_DBUS_CONTROL_H_
