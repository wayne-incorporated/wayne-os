// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_modem_modem3gpp_profile_manager_proxy.h"

#include <utility>

#include "shill/cellular/cellular_error.h"
#include "shill/logging.h"

#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const dbus::ObjectPath* p) {
  return p->value();
}
}  // namespace Logging

namespace mm1 {

ModemModem3gppProfileManagerProxy::ModemModem3gppProfileManagerProxy(
    const scoped_refptr<dbus::Bus>& bus,
    const RpcIdentifier& path,
    const std::string& service)
    : proxy_(new org::freedesktop::ModemManager1::Modem::Modem3gpp::
                 ProfileManagerProxy(bus, service, path)) {
  // Register signal handlers.
  proxy_->RegisterUpdatedSignalHandler(
      base::BindRepeating(&ModemModem3gppProfileManagerProxy::OnUpdated,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&ModemModem3gppProfileManagerProxy::OnSignalConnected,
                     weak_factory_.GetWeakPtr()));
}

ModemModem3gppProfileManagerProxy::~ModemModem3gppProfileManagerProxy() =
    default;

void ModemModem3gppProfileManagerProxy::List(
    ResultVariantDictionariesOnceCallback callback, int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->ListAsync(
      base::BindOnce(&ModemModem3gppProfileManagerProxy::OnListSuccess,
                     weak_factory_.GetWeakPtr(),
                     std::move(split_callback.first)),
      base::BindOnce(&ModemModem3gppProfileManagerProxy::OnListFailure,
                     weak_factory_.GetWeakPtr(),
                     std::move(split_callback.second)),
      timeout);
}

void ModemModem3gppProfileManagerProxy::OnListSuccess(
    ResultVariantDictionariesOnceCallback callback,
    const std::vector<brillo::VariantDictionary>& profiles) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  std::move(callback).Run(profiles, Error());
}

void ModemModem3gppProfileManagerProxy::OnListFailure(
    ResultVariantDictionariesOnceCallback callback, brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run(VariantDictionaries(), error);
}

void ModemModem3gppProfileManagerProxy::OnUpdated() {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  if (updated_callback_.is_null()) {
    return;
  }
  updated_callback_.Run();
}

void ModemModem3gppProfileManagerProxy::SetUpdatedCallback(
    const base::RepeatingCallback<void()>& callback) {
  CHECK(updated_callback_.is_null());
  updated_callback_ = callback;
}

void ModemModem3gppProfileManagerProxy::OnSignalConnected(
    const std::string& interface_name,
    const std::string& signal_name,
    bool success) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << ": interface: " << interface_name
      << " signal: " << signal_name << " success: " << success;
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

}  // namespace mm1
}  // namespace shill
