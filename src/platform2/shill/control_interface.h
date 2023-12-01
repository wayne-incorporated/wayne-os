// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CONTROL_INTERFACE_H_
#define SHILL_CONTROL_INTERFACE_H_

#include <algorithm>
#include <memory>
#include <string>

#include <base/functional/callback.h>

#include "shill/data_types.h"
#include "shill/logging.h"

namespace shill {

#if !defined(DISABLE_FLOSS)
class BluetoothAdapterProxyInterface;
class BluetoothBlueZProxyInterface;
class BluetoothManagerProxyInterface;
#endif  // DISABLE_FLOSS
class DBusObjectManagerProxyInterface;
class DBusPropertiesProxy;
class Device;
class DeviceAdaptorInterface;
class DHCPCDListenerInterface;
class DHCPProvider;
class DHCPProxyInterface;
class IPConfig;
class IPConfigAdaptorInterface;
class Manager;
class ManagerAdaptorInterface;
class PowerManagerProxyDelegate;
class PowerManagerProxyInterface;
class Profile;
class ProfileAdaptorInterface;
class RpcTask;
class RpcTaskAdaptorInterface;
class Service;
class ServiceAdaptorInterface;
class SupplicantBSSProxyInterface;
class SupplicantEventDelegateInterface;
class SupplicantInterfaceProxyInterface;
class SupplicantNetworkProxyInterface;
class SupplicantProcessProxyInterface;
class ThirdPartyVpnDriver;
class ThirdPartyVpnAdaptorInterface;
class UpstartProxyInterface;
class WiFiEndpoint;

namespace mm1 {

class ModemLocationProxyInterface;
class ModemModem3gppProxyInterface;
class ModemModem3gppProfileManagerProxyInterface;
class ModemProxyInterface;
class ModemSimpleProxyInterface;
class ModemSignalProxyInterface;
class SimProxyInterface;

}  // namespace mm1

// This is the Interface for an object factory that creates adaptor/proxy
// objects
class ControlInterface {
 public:
  virtual ~ControlInterface() = default;
  virtual void RegisterManagerObject(
      Manager* manager, base::OnceClosure registration_done_callback) = 0;
  virtual std::unique_ptr<DeviceAdaptorInterface> CreateDeviceAdaptor(
      Device* device) = 0;
  virtual std::unique_ptr<IPConfigAdaptorInterface> CreateIPConfigAdaptor(
      IPConfig* ipconfig) = 0;
  virtual std::unique_ptr<ManagerAdaptorInterface> CreateManagerAdaptor(
      Manager* manager) = 0;
  virtual std::unique_ptr<ProfileAdaptorInterface> CreateProfileAdaptor(
      Profile* profile) = 0;
  virtual std::unique_ptr<ServiceAdaptorInterface> CreateServiceAdaptor(
      Service* service) = 0;
  virtual std::unique_ptr<RpcTaskAdaptorInterface> CreateRpcTaskAdaptor(
      RpcTask* task) = 0;
#ifndef DISABLE_VPN
  virtual std::unique_ptr<ThirdPartyVpnAdaptorInterface>
  CreateThirdPartyVpnAdaptor(ThirdPartyVpnDriver* driver) = 0;
#endif

  // The caller retains ownership of 'delegate'.  It must not be deleted before
  // the proxy.
  virtual std::unique_ptr<PowerManagerProxyInterface> CreatePowerManagerProxy(
      PowerManagerProxyDelegate* delegate,
      const base::RepeatingClosure& service_appeared_callback,
      const base::RepeatingClosure& service_vanished_callback) = 0;

  virtual std::unique_ptr<SupplicantProcessProxyInterface>
  CreateSupplicantProcessProxy(
      const base::RepeatingClosure& service_appeared_callback,
      const base::RepeatingClosure& service_vanished_callback) = 0;

  virtual std::unique_ptr<SupplicantInterfaceProxyInterface>
  CreateSupplicantInterfaceProxy(SupplicantEventDelegateInterface* delegate,
                                 const RpcIdentifier& object_path) = 0;

  virtual std::unique_ptr<SupplicantNetworkProxyInterface>
  CreateSupplicantNetworkProxy(const RpcIdentifier& object_path) = 0;

  // See comment in supplicant_bss_proxy.h, about bare pointer.
  virtual std::unique_ptr<SupplicantBSSProxyInterface> CreateSupplicantBSSProxy(
      WiFiEndpoint* wifi_endpoint, const RpcIdentifier& object_path) = 0;

  virtual std::unique_ptr<UpstartProxyInterface> CreateUpstartProxy() = 0;

  virtual std::unique_ptr<DHCPCDListenerInterface> CreateDHCPCDListener(
      DHCPProvider* provider) = 0;

  virtual std::unique_ptr<DHCPProxyInterface> CreateDHCPProxy(
      const std::string& service) = 0;

  virtual std::unique_ptr<DBusPropertiesProxy> CreateDBusPropertiesProxy(
      const RpcIdentifier& path, const std::string& service) = 0;

  virtual std::unique_ptr<DBusObjectManagerProxyInterface>
  CreateDBusObjectManagerProxy(
      const RpcIdentifier& path,
      const std::string& service,
      const base::RepeatingClosure& service_appeared_callback,
      const base::RepeatingClosure& service_vanished_callback) = 0;

  virtual std::unique_ptr<mm1::ModemLocationProxyInterface>
  CreateMM1ModemLocationProxy(const RpcIdentifier& path,
                              const std::string& service) = 0;

  virtual std::unique_ptr<mm1::ModemModem3gppProxyInterface>
  CreateMM1ModemModem3gppProxy(const RpcIdentifier& path,
                               const std::string& service) = 0;

  virtual std::unique_ptr<mm1::ModemModem3gppProfileManagerProxyInterface>
  CreateMM1ModemModem3gppProfileManagerProxy(const RpcIdentifier& path,
                                             const std::string& service) = 0;

  virtual std::unique_ptr<mm1::ModemProxyInterface> CreateMM1ModemProxy(
      const RpcIdentifier& path, const std::string& service) = 0;

  virtual std::unique_ptr<mm1::ModemSignalProxyInterface>
  CreateMM1ModemSignalProxy(const RpcIdentifier& path,
                            const std::string& service) = 0;

  virtual std::unique_ptr<mm1::ModemSimpleProxyInterface>
  CreateMM1ModemSimpleProxy(const RpcIdentifier& path,
                            const std::string& service) = 0;

  virtual std::unique_ptr<mm1::SimProxyInterface> CreateMM1SimProxy(
      const RpcIdentifier& path, const std::string& service) = 0;

#if !defined(DISABLE_FLOSS)
  virtual std::unique_ptr<BluetoothManagerProxyInterface>
  CreateBluetoothManagerProxy(
      const base::RepeatingClosure& service_appeared_callback) = 0;

  virtual std::unique_ptr<BluetoothAdapterProxyInterface>
  CreateBluetoothAdapterProxy(int32_t hci) = 0;

  virtual std::unique_ptr<BluetoothBlueZProxyInterface>
  CreateBluetoothBlueZProxy() = 0;
#endif  // DISABLE_FLOSS
};

}  // namespace shill

#endif  // SHILL_CONTROL_INTERFACE_H_
