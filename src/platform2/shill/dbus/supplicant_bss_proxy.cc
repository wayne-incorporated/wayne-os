// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/supplicant_bss_proxy.h"

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>

#include "shill/logging.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/wifi/wifi_endpoint.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const dbus::ObjectPath* p) {
  return p->value();
}
}  // namespace Logging

SupplicantBSSProxy::SupplicantBSSProxy(const scoped_refptr<dbus::Bus>& bus,
                                       const RpcIdentifier& object_path,
                                       WiFiEndpoint* wifi_endpoint)
    : bss_proxy_(new fi::w1::wpa_supplicant1::BSSProxy(
          bus, WPASupplicant::kDBusAddr, object_path)),
      wifi_endpoint_(wifi_endpoint) {
  // Register signal handler.
  bss_proxy_->RegisterPropertiesChangedSignalHandler(
      base::BindRepeating(&SupplicantBSSProxy::PropertiesChanged,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&SupplicantBSSProxy::OnSignalConnected,
                     weak_factory_.GetWeakPtr()));
}

SupplicantBSSProxy::~SupplicantBSSProxy() {
  bss_proxy_->ReleaseObjectProxy(base::DoNothing());
}

void SupplicantBSSProxy::PropertiesChanged(
    const brillo::VariantDictionary& properties) {
  SLOG(&bss_proxy_->GetObjectPath(), 2) << __func__;
  KeyValueStore store = KeyValueStore::ConvertFromVariantDictionary(properties);
  wifi_endpoint_->PropertiesChanged(store);
}

// Called when signal is connected to the ObjectProxy.
void SupplicantBSSProxy::OnSignalConnected(const std::string& interface_name,
                                           const std::string& signal_name,
                                           bool success) {
  SLOG(&bss_proxy_->GetObjectPath(), 2)
      << __func__ << ": interface: " << interface_name
      << " signal: " << signal_name << "success: " << success;
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

}  // namespace shill
