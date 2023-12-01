// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/dbus_control.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <chromeos/dbus/service_constants.h>

#if !defined(DISABLE_FLOSS)
#include "shill/bluetooth/bluetooth_adapter_proxy_interface.h"
#include "shill/bluetooth/bluetooth_bluez_proxy_interface.h"
#include "shill/bluetooth/bluetooth_manager_proxy_interface.h"
#include "shill/dbus/bluetooth_adapter_proxy.h"
#include "shill/dbus/bluetooth_bluez_proxy.h"
#include "shill/dbus/bluetooth_manager_proxy.h"
#endif  // DISABLE_FLOSS
#include "shill/dbus/dbus_objectmanager_proxy.h"
#include "shill/dbus/dbus_properties_proxy.h"
#include "shill/dbus/device_dbus_adaptor.h"
#include "shill/dbus/dhcpcd_listener.h"
#include "shill/dbus/dhcpcd_proxy.h"
#include "shill/dbus/ipconfig_dbus_adaptor.h"
#include "shill/dbus/manager_dbus_adaptor.h"
#include "shill/dbus/mm1_modem_location_proxy.h"
#include "shill/dbus/mm1_modem_modem3gpp_profile_manager_proxy.h"
#include "shill/dbus/mm1_modem_modem3gpp_proxy.h"
#include "shill/dbus/mm1_modem_proxy.h"
#include "shill/dbus/mm1_modem_signal_proxy.h"
#include "shill/dbus/mm1_modem_simple_proxy.h"
#include "shill/dbus/mm1_sim_proxy.h"
#include "shill/dbus/power_manager_proxy.h"
#include "shill/dbus/profile_dbus_adaptor.h"
#include "shill/dbus/rpc_task_dbus_adaptor.h"
#include "shill/dbus/service_dbus_adaptor.h"
#include "shill/dbus/supplicant_bss_proxy.h"
#include "shill/dbus/supplicant_interface_proxy.h"
#include "shill/dbus/supplicant_network_proxy.h"
#include "shill/dbus/supplicant_process_proxy.h"
#include "shill/dbus/third_party_vpn_dbus_adaptor.h"
#include "shill/dbus/upstart_proxy.h"

#include "shill/manager.h"

namespace shill {

// static.
const char DBusControl::kNullPath[] = "/";

DBusControl::DBusControl(EventDispatcher* dispatcher)
    : dispatcher_(dispatcher) {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;

  adaptor_bus_ = new dbus::Bus(options);
  proxy_bus_ = new dbus::Bus(options);
  CHECK(adaptor_bus_->Connect());
  CHECK(proxy_bus_->Connect());
}

DBusControl::~DBusControl() {
  if (adaptor_bus_) {
    adaptor_bus_->ShutdownAndBlock();
  }
  if (proxy_bus_) {
    proxy_bus_->ShutdownAndBlock();
  }
}

// static
RpcIdentifier DBusControl::NullRpcIdentifier() {
  return RpcIdentifier(kNullPath);
}

void DBusControl::RegisterManagerObject(
    Manager* manager, base::OnceClosure registration_done_callback) {
  registration_done_callback_ = std::move(registration_done_callback);
  scoped_refptr<brillo::dbus_utils::AsyncEventSequencer> sequencer(
      new brillo::dbus_utils::AsyncEventSequencer());
  manager->RegisterAsync(base::BindOnce(
      &DBusControl::OnDBusServiceRegistered, base::Unretained(this),
      sequencer->GetHandler("Manager.RegisterAsync() failed.", true)));
  sequencer->OnAllTasksCompletedCall(base::BindOnce(
      &DBusControl::TakeServiceOwnership, base::Unretained(this)));
}

void DBusControl::OnDBusServiceRegistered(
    base::OnceCallback<void(bool)> completion_action, bool success) {
  // The DBus control interface will take over the ownership of the DBus service
  // in this callback.  The daemon will crash if registration failed.
  std::move(completion_action).Run(success);

  // We can start the manager now that we have ownership of the D-Bus service.
  // Doing so earlier would allow the manager to emit signals before service
  // ownership was acquired.
  std::move(registration_done_callback_).Run();
}

void DBusControl::TakeServiceOwnership(bool success) {
  // Success should always be true since we've said that failures are fatal.
  CHECK(success) << "Init of one or more objects has failed.";
  CHECK(adaptor_bus_->RequestOwnershipAndBlock(kFlimflamServiceName,
                                               dbus::Bus::REQUIRE_PRIMARY))
      << "Unable to take ownership of " << kFlimflamServiceName;
}

std::unique_ptr<DeviceAdaptorInterface> DBusControl::CreateDeviceAdaptor(
    Device* device) {
  return std::make_unique<DeviceDBusAdaptor>(adaptor_bus_, device);
}

std::unique_ptr<IPConfigAdaptorInterface> DBusControl::CreateIPConfigAdaptor(
    IPConfig* config) {
  return std::make_unique<IPConfigDBusAdaptor>(adaptor_bus_, config);
}

std::unique_ptr<ManagerAdaptorInterface> DBusControl::CreateManagerAdaptor(
    Manager* manager) {
  return std::make_unique<ManagerDBusAdaptor>(adaptor_bus_, proxy_bus_,
                                              manager);
}

std::unique_ptr<ProfileAdaptorInterface> DBusControl::CreateProfileAdaptor(
    Profile* profile) {
  return std::make_unique<ProfileDBusAdaptor>(adaptor_bus_, profile);
}

std::unique_ptr<RpcTaskAdaptorInterface> DBusControl::CreateRpcTaskAdaptor(
    RpcTask* task) {
  return std::make_unique<RpcTaskDBusAdaptor>(adaptor_bus_, task);
}

std::unique_ptr<ServiceAdaptorInterface> DBusControl::CreateServiceAdaptor(
    Service* service) {
  return std::make_unique<ServiceDBusAdaptor>(adaptor_bus_, service);
}

#ifndef DISABLE_VPN
std::unique_ptr<ThirdPartyVpnAdaptorInterface>
DBusControl::CreateThirdPartyVpnAdaptor(ThirdPartyVpnDriver* driver) {
  return std::make_unique<ThirdPartyVpnDBusAdaptor>(adaptor_bus_, driver);
}
#endif

std::unique_ptr<PowerManagerProxyInterface>
DBusControl::CreatePowerManagerProxy(
    PowerManagerProxyDelegate* delegate,
    const base::RepeatingClosure& service_appeared_callback,
    const base::RepeatingClosure& service_vanished_callback) {
  return std::make_unique<PowerManagerProxy>(dispatcher_, proxy_bus_, delegate,
                                             service_appeared_callback,
                                             service_vanished_callback);
}

std::unique_ptr<SupplicantProcessProxyInterface>
DBusControl::CreateSupplicantProcessProxy(
    const base::RepeatingClosure& service_appeared_callback,
    const base::RepeatingClosure& service_vanished_callback) {
  return std::make_unique<SupplicantProcessProxy>(dispatcher_, proxy_bus_,
                                                  service_appeared_callback,
                                                  service_vanished_callback);
}

std::unique_ptr<SupplicantInterfaceProxyInterface>
DBusControl::CreateSupplicantInterfaceProxy(
    SupplicantEventDelegateInterface* delegate,
    const RpcIdentifier& object_path) {
  return std::make_unique<SupplicantInterfaceProxy>(proxy_bus_, object_path,
                                                    delegate);
}

std::unique_ptr<SupplicantNetworkProxyInterface>
DBusControl::CreateSupplicantNetworkProxy(const RpcIdentifier& object_path) {
  return std::make_unique<SupplicantNetworkProxy>(proxy_bus_, object_path);
}

std::unique_ptr<SupplicantBSSProxyInterface>
DBusControl::CreateSupplicantBSSProxy(WiFiEndpoint* wifi_endpoint,
                                      const RpcIdentifier& object_path) {
  return std::make_unique<SupplicantBSSProxy>(proxy_bus_, object_path,
                                              wifi_endpoint);
}

std::unique_ptr<DHCPCDListenerInterface> DBusControl::CreateDHCPCDListener(
    DHCPProvider* provider) {
  return std::make_unique<DHCPCDListener>(proxy_bus_, dispatcher_, provider);
}

std::unique_ptr<DHCPProxyInterface> DBusControl::CreateDHCPProxy(
    const std::string& service) {
  return std::make_unique<DHCPCDProxy>(proxy_bus_, service);
}

std::unique_ptr<UpstartProxyInterface> DBusControl::CreateUpstartProxy() {
  return std::make_unique<UpstartProxy>(proxy_bus_);
}

std::unique_ptr<DBusPropertiesProxy> DBusControl::CreateDBusPropertiesProxy(
    const RpcIdentifier& path, const std::string& service) {
  return std::make_unique<DBusPropertiesProxy>(proxy_bus_, path, service);
}

std::unique_ptr<DBusObjectManagerProxyInterface>
DBusControl::CreateDBusObjectManagerProxy(
    const RpcIdentifier& path,
    const std::string& service,
    const base::RepeatingClosure& service_appeared_callback,
    const base::RepeatingClosure& service_vanished_callback) {
  return std::make_unique<DBusObjectManagerProxy>(
      dispatcher_, proxy_bus_, path, service, service_appeared_callback,
      service_vanished_callback);
}

// Proxies for ModemManager1 interfaces
std::unique_ptr<mm1::ModemLocationProxyInterface>
DBusControl::CreateMM1ModemLocationProxy(const RpcIdentifier& path,
                                         const std::string& service) {
  return std::make_unique<mm1::ModemLocationProxy>(proxy_bus_, path, service);
}

std::unique_ptr<mm1::ModemModem3gppProxyInterface>
DBusControl::CreateMM1ModemModem3gppProxy(const RpcIdentifier& path,
                                          const std::string& service) {
  return std::make_unique<mm1::ModemModem3gppProxy>(proxy_bus_, path, service);
}

std::unique_ptr<mm1::ModemModem3gppProfileManagerProxyInterface>
DBusControl::CreateMM1ModemModem3gppProfileManagerProxy(
    const RpcIdentifier& path, const std::string& service) {
  return std::make_unique<mm1::ModemModem3gppProfileManagerProxy>(
      proxy_bus_, path, service);
}

std::unique_ptr<mm1::ModemProxyInterface> DBusControl::CreateMM1ModemProxy(
    const RpcIdentifier& path, const std::string& service) {
  return std::make_unique<mm1::ModemProxy>(proxy_bus_, path, service);
}

std::unique_ptr<mm1::ModemSignalProxyInterface>
DBusControl::CreateMM1ModemSignalProxy(const RpcIdentifier& path,
                                       const std::string& service) {
  return std::make_unique<mm1::ModemSignalProxy>(proxy_bus_, path, service);
}

std::unique_ptr<mm1::ModemSimpleProxyInterface>
DBusControl::CreateMM1ModemSimpleProxy(const RpcIdentifier& path,
                                       const std::string& service) {
  return std::make_unique<mm1::ModemSimpleProxy>(proxy_bus_, path, service);
}

std::unique_ptr<mm1::SimProxyInterface> DBusControl::CreateMM1SimProxy(
    const RpcIdentifier& path, const std::string& service) {
  return std::make_unique<mm1::SimProxy>(proxy_bus_, path, service);
}

#if !defined(DISABLE_FLOSS)
std::unique_ptr<BluetoothManagerProxyInterface>
DBusControl::CreateBluetoothManagerProxy(
    const base::RepeatingClosure& service_appeared_callback) {
  return std::make_unique<BluetoothManagerProxy>(proxy_bus_, dispatcher_,
                                                 service_appeared_callback);
}

std::unique_ptr<BluetoothAdapterProxyInterface>
DBusControl::CreateBluetoothAdapterProxy(int32_t hci) {
  return std::make_unique<BluetoothAdapterProxy>(proxy_bus_, hci);
}

std::unique_ptr<BluetoothBlueZProxyInterface>
DBusControl::CreateBluetoothBlueZProxy() {
  return std::make_unique<BluetoothBlueZProxy>(proxy_bus_, dispatcher_);
}
#endif  // DISABLE_FLOSS

}  // namespace shill
