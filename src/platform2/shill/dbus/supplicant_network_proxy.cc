// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/supplicant_network_proxy.h"

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>

#include "shill/logging.h"
#include "shill/supplicant/wpa_supplicant.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const dbus::ObjectPath* p) {
  return p->value();
}
}  // namespace Logging

// static.
const char SupplicantNetworkProxy::kInterfaceName[] =
    "fi.w1.wpa_supplicant1.Network";
const char SupplicantNetworkProxy::kPropertyEnabled[] = "Enabled";
const char SupplicantNetworkProxy::kPropertyProperties[] = "Properties";

SupplicantNetworkProxy::PropertySet::PropertySet(
    dbus::ObjectProxy* object_proxy,
    const std::string& interface_name,
    const PropertyChangedCallback& callback)
    : dbus::PropertySet(object_proxy, interface_name, callback) {
  RegisterProperty(kPropertyEnabled, &enabled);
  RegisterProperty(kPropertyProperties, &properties);
}

SupplicantNetworkProxy::SupplicantNetworkProxy(
    const scoped_refptr<dbus::Bus>& bus, const RpcIdentifier& object_path)
    : network_proxy_(new fi::w1::wpa_supplicant1::NetworkProxy(
          bus, WPASupplicant::kDBusAddr, object_path)) {
  // Register properties.
  properties_.reset(new PropertySet(
      network_proxy_->GetObjectProxy(), kInterfaceName,
      base::BindRepeating(&SupplicantNetworkProxy::OnPropertyChanged,
                          weak_factory_.GetWeakPtr())));

  // Register signal handler.
  network_proxy_->RegisterPropertiesChangedSignalHandler(
      base::BindRepeating(&SupplicantNetworkProxy::PropertiesChanged,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&SupplicantNetworkProxy::OnSignalConnected,
                     weak_factory_.GetWeakPtr()));

  // Connect property signals and initialize cached values. Based on
  // recommendations from src/dbus/property.h.
  properties_->ConnectSignals();
  properties_->GetAll();
}

SupplicantNetworkProxy::~SupplicantNetworkProxy() {
  network_proxy_->ReleaseObjectProxy(base::DoNothing());
}

bool SupplicantNetworkProxy::SetEnabled(bool enabled) {
  SLOG(&network_proxy_->GetObjectPath(), 2) << __func__;
  if (!properties_->enabled.SetAndBlock(enabled)) {
    LOG(ERROR) << "Failed to SetEnabled: " << enabled;
    return false;
  }
  return true;
}

bool SupplicantNetworkProxy::SetProperties(const KeyValueStore& props) {
  SLOG(&network_proxy_->GetObjectPath(), 2) << __func__;
  brillo::VariantDictionary dict =
      KeyValueStore::ConvertToVariantDictionary(props);
  if (!properties_->properties.SetAndBlock(dict)) {
    LOG(ERROR) << "Failed to SetProperties";
    return false;
  }
  return true;
}

void SupplicantNetworkProxy::PropertiesChanged(
    const brillo::VariantDictionary& /*properties*/) {
  SLOG(&network_proxy_->GetObjectPath(), 2) << __func__;
}

void SupplicantNetworkProxy::OnPropertyChanged(
    const std::string& property_name) {
  SLOG(&network_proxy_->GetObjectPath(), 2)
      << __func__ << ": " << property_name;
}

// Called when signal is connected to the ObjectProxy.
void SupplicantNetworkProxy::OnSignalConnected(
    const std::string& interface_name,
    const std::string& signal_name,
    bool success) {
  SLOG(&network_proxy_->GetObjectPath(), 2)
      << __func__ << ": interface: " << interface_name
      << " signal: " << signal_name << "success: " << success;
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

}  // namespace shill
