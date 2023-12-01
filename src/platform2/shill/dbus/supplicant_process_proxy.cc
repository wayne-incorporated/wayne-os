// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/supplicant_process_proxy.h"

#include "shill/logging.h"
#include "shill/supplicant/wpa_supplicant.h"

#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const dbus::ObjectPath* p) {
  return p->value();
}
}  // namespace Logging

const char SupplicantProcessProxy::kInterfaceName[] = "fi.w1.wpa_supplicant1";
const char SupplicantProcessProxy::kPropertyDebugLevel[] = "DebugLevel";
const char SupplicantProcessProxy::kPropertyDebugTimestamp[] = "DebugTimestamp";
const char SupplicantProcessProxy::kPropertyDebugShowKeys[] = "DebugShowKeys";
const char SupplicantProcessProxy::kPropertyInterfaces[] = "Interfaces";
const char SupplicantProcessProxy::kPropertyEapMethods[] = "EapMethods";

SupplicantProcessProxy::PropertySet::PropertySet(
    dbus::ObjectProxy* object_proxy,
    const std::string& interface_name,
    const PropertyChangedCallback& callback)
    : dbus::PropertySet(object_proxy, interface_name, callback) {
  RegisterProperty(kPropertyDebugLevel, &debug_level);
  RegisterProperty(kPropertyDebugTimestamp, &debug_timestamp);
  RegisterProperty(kPropertyDebugShowKeys, &debug_show_keys);
  RegisterProperty(kPropertyInterfaces, &interfaces);
  RegisterProperty(kPropertyEapMethods, &eap_methods);
}

SupplicantProcessProxy::SupplicantProcessProxy(
    EventDispatcher* dispatcher,
    const scoped_refptr<dbus::Bus>& bus,
    const base::RepeatingClosure& service_appeared_callback,
    const base::RepeatingClosure& service_vanished_callback)
    : supplicant_proxy_(new fi::w1::wpa_supplicant1Proxy(
          bus,
          WPASupplicant::kDBusAddr,
          dbus::ObjectPath(WPASupplicant::kDBusPath))),
      dispatcher_(dispatcher),
      service_appeared_callback_(service_appeared_callback),
      service_vanished_callback_(service_vanished_callback),
      service_available_(false) {
  // Register properties.
  properties_.reset(new PropertySet(
      supplicant_proxy_->GetObjectProxy(), kInterfaceName,
      base::BindRepeating(&SupplicantProcessProxy::OnPropertyChanged,
                          weak_factory_.GetWeakPtr())));

  // Register signal handlers.
  auto on_connected_callback = base::BindRepeating(
      &SupplicantProcessProxy::OnSignalConnected, weak_factory_.GetWeakPtr());
  supplicant_proxy_->RegisterInterfaceAddedSignalHandler(
      base::BindRepeating(&SupplicantProcessProxy::InterfaceAdded,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  supplicant_proxy_->RegisterInterfaceRemovedSignalHandler(
      base::BindRepeating(&SupplicantProcessProxy::InterfaceRemoved,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  supplicant_proxy_->RegisterPropertiesChangedSignalHandler(
      base::BindRepeating(&SupplicantProcessProxy::PropertiesChanged,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);

  // Connect property signals and initialize cached values. Based on
  // recommendations from src/dbus/property.h.
  properties_->ConnectSignals();
  properties_->GetAll();

  // Monitor service owner changes. This callback lives for the lifetime of
  // the ObjectProxy.
  supplicant_proxy_->GetObjectProxy()->SetNameOwnerChangedCallback(
      base::BindRepeating(&SupplicantProcessProxy::OnServiceOwnerChanged,
                          weak_factory_.GetWeakPtr()));

  // One time callback when service becomes available.
  supplicant_proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(
      base::BindOnce(&SupplicantProcessProxy::OnServiceAvailable,
                     weak_factory_.GetWeakPtr()));
}

SupplicantProcessProxy::~SupplicantProcessProxy() = default;

bool SupplicantProcessProxy::CreateInterface(const KeyValueStore& args,
                                             RpcIdentifier* rpc_identifier) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2) << __func__;
  if (!service_available_) {
    LOG(ERROR) << "Supplicant process not present";
    return false;
  }
  brillo::VariantDictionary dict =
      KeyValueStore::ConvertToVariantDictionary(args);
  dbus::ObjectPath path;
  brillo::ErrorPtr error;
  if (!supplicant_proxy_->CreateInterface(dict, &path, &error)) {
    // Interface might already been created by wpasupplicant.
    LOG(INFO) << "Failed to create interface: " << error->GetCode() << " "
              << error->GetMessage();
    return false;
  }
  *rpc_identifier = path;
  return true;
}

bool SupplicantProcessProxy::RemoveInterface(
    const RpcIdentifier& rpc_identifier) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2)
      << __func__ << ": " << rpc_identifier.value();
  if (!service_available_) {
    LOG(ERROR) << "Supplicant process not present";
    return false;
  }

  brillo::ErrorPtr error;
  if (!supplicant_proxy_->RemoveInterface(rpc_identifier, &error)) {
    // Interface may already be removed by wpa_supplicant.
    LOG(INFO) << "Failed to remove interface " << rpc_identifier.value() << ": "
              << error->GetCode() << " " << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantProcessProxy::GetInterface(const std::string& ifname,
                                          RpcIdentifier* rpc_identifier) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2) << __func__ << ": " << ifname;
  if (!service_available_) {
    LOG(ERROR) << "Supplicant process not present";
    return false;
  }

  dbus::ObjectPath path;
  brillo::ErrorPtr error;
  if (!supplicant_proxy_->GetInterface(ifname, &path, &error)) {
    // Interface may not yet be available at the wpa_supplicant layer.
    LOG(INFO) << "Failed to get interface " << ifname << ": "
              << error->GetCode() << " " << error->GetMessage();
    return false;
  }
  *rpc_identifier = path;
  return rpc_identifier;
}

bool SupplicantProcessProxy::SetDebugLevel(const std::string& level) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2) << __func__ << ": " << level;
  if (!service_available_) {
    LOG(ERROR) << "Supplicant process not present";
    return false;
  }

  if (!properties_->debug_level.SetAndBlock(level)) {
    LOG(ERROR) << __func__ << " failed: " << level;
    return false;
  }
  return true;
}

bool SupplicantProcessProxy::GetDebugLevel(std::string* level) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2) << __func__;
  if (!service_available_) {
    LOG(ERROR) << "Supplicant process not present";
    return false;
  }
  if (!properties_->debug_level.GetAndBlock()) {
    LOG(ERROR) << "Failed to get DebugLevel";
    return false;
  }
  *level = properties_->debug_level.value();
  return true;
}

bool SupplicantProcessProxy::ExpectDisconnect() {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2) << __func__;
  if (!service_available_) {
    LOG(ERROR) << "Supplicant process not present";
    return false;
  }
  brillo::ErrorPtr error;
  supplicant_proxy_->ExpectDisconnect(&error);
  return true;
}

void SupplicantProcessProxy::InterfaceAdded(
    const dbus::ObjectPath& /*path*/,
    const brillo::VariantDictionary& /*properties*/) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2) << __func__;
}

void SupplicantProcessProxy::InterfaceRemoved(
    const dbus::ObjectPath& /*path*/) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2) << __func__;
}

void SupplicantProcessProxy::PropertiesChanged(
    const brillo::VariantDictionary& /*properties*/) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2) << __func__;
}

void SupplicantProcessProxy::OnServiceAvailable(bool available) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2) << __func__ << ": " << available;

  // The callback might invoke calls to the ObjectProxy, so defer the callback
  // to event loop.
  if (available && !service_appeared_callback_.is_null()) {
    dispatcher_->PostTask(FROM_HERE, service_appeared_callback_);
  } else if (!available && !service_vanished_callback_.is_null()) {
    dispatcher_->PostTask(FROM_HERE, service_vanished_callback_);
  }
  service_available_ = available;
}

void SupplicantProcessProxy::OnServiceOwnerChanged(
    const std::string& old_owner, const std::string& new_owner) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2)
      << __func__ << ": old: " << old_owner << " new: " << new_owner;
  if (new_owner.empty()) {
    OnServiceAvailable(false);
  } else {
    OnServiceAvailable(true);
  }
}

void SupplicantProcessProxy::OnPropertyChanged(
    const std::string& property_name) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2)
      << __func__ << ": " << property_name;
}

void SupplicantProcessProxy::OnSignalConnected(
    const std::string& interface_name,
    const std::string& signal_name,
    bool success) {
  SLOG(&supplicant_proxy_->GetObjectPath(), 2)
      << __func__ << ": interface: " << interface_name
      << " signal: " << signal_name << "success: " << success;
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

}  // namespace shill
