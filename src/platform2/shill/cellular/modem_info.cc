// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/modem_info.h"

#include <memory>
#include <utility>

#include <chromeos/dbus/service_constants.h>
#include <ModemManager/ModemManager.h>

#include "shill/cellular/dbus_objectmanager_proxy_interface.h"
#include "shill/cellular/modem.h"
#include "shill/cellular/pending_activation_store.h"
#include "shill/control_interface.h"
#include "shill/dbus/dbus_objectmanager_proxy.h"
#include "shill/logging.h"
#include "shill/manager.h"

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kModem;
}  // namespace Logging

ModemInfo::ModemInfo(ControlInterface* control_interface, Manager* manager)
    : control_interface_(control_interface),
      manager_(manager),
      weak_ptr_factory_(this) {}

ModemInfo::~ModemInfo() {
  Stop();
}

void ModemInfo::Start() {
  LOG(INFO) << __func__;

  pending_activation_store_.reset(new PendingActivationStore());
  pending_activation_store_->InitStorage(manager_->storage_path());

  CHECK(!proxy_);
  proxy_ = CreateProxy();
}

void ModemInfo::Stop() {
  LOG(INFO) << __func__;
  pending_activation_store_.reset();
  proxy_.reset();
  Disconnect();
}

void ModemInfo::OnDeviceInfoAvailable(const std::string& link_name) {
  for (const auto& modem_entry : modems_) {
    modem_entry.second->OnDeviceInfoAvailable(link_name);
  }
}

std::unique_ptr<DBusObjectManagerProxyInterface> ModemInfo::CreateProxy() {
  std::unique_ptr<DBusObjectManagerProxyInterface> proxy =
      control_interface_->CreateDBusObjectManagerProxy(
          RpcIdentifier(modemmanager::kModemManager1ServicePath),
          modemmanager::kModemManager1ServiceName,
          base::BindRepeating(&ModemInfo::OnAppeared,
                              weak_ptr_factory_.GetWeakPtr()),
          base::BindRepeating(&ModemInfo::OnVanished,
                              weak_ptr_factory_.GetWeakPtr()));
  proxy->set_interfaces_added_callback(base::BindRepeating(
      &ModemInfo::OnInterfacesAddedSignal, weak_ptr_factory_.GetWeakPtr()));
  proxy->set_interfaces_removed_callback(base::BindRepeating(
      &ModemInfo::OnInterfacesRemovedSignal, weak_ptr_factory_.GetWeakPtr()));
  return proxy;
}

std::unique_ptr<Modem> ModemInfo::CreateModem(
    const RpcIdentifier& path, const InterfaceToProperties& properties) {
  SLOG(1) << __func__ << ": " << path.value();
  auto modem = std::make_unique<Modem>(modemmanager::kModemManager1ServiceName,
                                       path, manager_->device_info());
  modem->CreateDevice(properties);
  return modem;
}

void ModemInfo::Connect() {
  LOG(INFO) << __func__;
  service_connected_ = true;
  CHECK(proxy_);
  proxy_->GetManagedObjects(base::BindOnce(&ModemInfo::OnGetManagedObjectsReply,
                                           weak_ptr_factory_.GetWeakPtr()));
}

void ModemInfo::Disconnect() {
  LOG(INFO) << __func__;
  modems_.clear();
  service_connected_ = false;
}

bool ModemInfo::ModemExists(const RpcIdentifier& path) const {
  CHECK(service_connected_);
  return base::Contains(modems_, path);
}

void ModemInfo::AddModem(const RpcIdentifier& path,
                         const InterfaceToProperties& properties) {
  if (ModemExists(path)) {
    LOG(WARNING) << "Modem " << path.value() << " already exists.";
    return;
  }
  LOG(INFO) << __func__ << ": " << path.value();
  std::unique_ptr<Modem> modem = CreateModem(path, properties);
  modems_[modem->path()] = std::move(modem);
}

void ModemInfo::RemoveModem(const RpcIdentifier& path) {
  LOG(INFO) << __func__ << ": " << path.value();
  CHECK(service_connected_);
  modems_.erase(path);
}

void ModemInfo::OnAppeared() {
  LOG(INFO) << __func__;
  Connect();
}

void ModemInfo::OnVanished() {
  LOG(INFO) << __func__;
  Disconnect();
}

void ModemInfo::OnInterfacesAddedSignal(
    const RpcIdentifier& object_path, const InterfaceToProperties& properties) {
  LOG(INFO) << __func__ << ": " << object_path.value();
  if (!base::Contains(properties, MM_DBUS_INTERFACE_MODEM)) {
    LOG(ERROR) << "Interfaces added, but not modem interface.";
    return;
  }
  AddModem(object_path, properties);
}

void ModemInfo::OnInterfacesRemovedSignal(
    const RpcIdentifier& object_path,
    const std::vector<std::string>& interfaces) {
  LOG(INFO) << __func__ << ": " << object_path.value();
  if (!base::Contains(interfaces, MM_DBUS_INTERFACE_MODEM)) {
    // In theory, a modem could drop, say, 3GPP, but not CDMA.  In
    // practice, we don't expect this.
    LOG(ERROR) << "Interfaces removed, but not modem interface";
    return;
  }
  RemoveModem(object_path);
}

void ModemInfo::OnGetManagedObjectsReply(const ObjectsWithProperties& objects,
                                         const Error& error) {
  LOG(INFO) << __func__ << ": " << error.IsSuccess();
  if (!error.IsSuccess()) {
    error.Log();
    return;
  }
  for (const auto& object_properties_pair : objects) {
    OnInterfacesAddedSignal(object_properties_pair.first,
                            object_properties_pair.second);
  }
}

}  // namespace shill
