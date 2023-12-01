// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_modem_modem3gpp_proxy.h"

#include <utility>

#include <base/logging.h>
#include <base/time/time.h>

#include "shill/cellular/cellular_error.h"
#include "shill/logging.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const dbus::ObjectPath* p) {
  return p->value();
}
}  // namespace Logging

namespace {
constexpr base::TimeDelta kScanTimeout = base::Minutes(2);
constexpr base::TimeDelta kSetInitialEpsBearerTimeout = base::Seconds(45);
constexpr base::TimeDelta kRegisterTimeout = base::Seconds(90);
}  // namespace

namespace mm1 {

ModemModem3gppProxy::ModemModem3gppProxy(const scoped_refptr<dbus::Bus>& bus,
                                         const RpcIdentifier& path,
                                         const std::string& service)
    : proxy_(new org::freedesktop::ModemManager1::Modem::Modem3gppProxy(
          bus, service, path)) {}

ModemModem3gppProxy::~ModemModem3gppProxy() = default;

void ModemModem3gppProxy::Register(const std::string& operator_id,
                                   ResultCallback callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << operator_id;
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->RegisterAsync(operator_id,
                        base::BindOnce(&ModemModem3gppProxy::OnRegisterSuccess,
                                       weak_factory_.GetWeakPtr(),
                                       std::move(split_callback.first)),
                        base::BindOnce(&ModemModem3gppProxy::OnRegisterFailure,
                                       weak_factory_.GetWeakPtr(),
                                       std::move(split_callback.second)),
                        kRegisterTimeout.InMilliseconds());
}

void ModemModem3gppProxy::Scan(KeyValueStoresCallback callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->ScanAsync(base::BindOnce(&ModemModem3gppProxy::OnScanSuccess,
                                   weak_factory_.GetWeakPtr(),
                                   std::move(split_callback.first)),
                    base::BindOnce(&ModemModem3gppProxy::OnScanFailure,
                                   weak_factory_.GetWeakPtr(),
                                   std::move(split_callback.second)),
                    kScanTimeout.InMilliseconds());
}

void ModemModem3gppProxy::SetInitialEpsBearerSettings(
    const KeyValueStore& properties, ResultCallback callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  brillo::VariantDictionary properties_dict =
      KeyValueStore::ConvertToVariantDictionary(properties);
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->SetInitialEpsBearerSettingsAsync(
      properties_dict,
      base::BindOnce(&ModemModem3gppProxy::OnSetInitialEpsBearerSettingsSuccess,
                     weak_factory_.GetWeakPtr(),
                     std::move(split_callback.first)),
      base::BindOnce(&ModemModem3gppProxy::OnSetInitialEpsBearerSettingsFailure,
                     weak_factory_.GetWeakPtr(),
                     std::move(split_callback.second)),
      kSetInitialEpsBearerTimeout.InMilliseconds());
}

void ModemModem3gppProxy::OnRegisterSuccess(ResultCallback callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  std::move(callback).Run(Error());
}

void ModemModem3gppProxy::OnRegisterFailure(ResultCallback callback,
                                            brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run(error);
}

void ModemModem3gppProxy::OnScanSuccess(
    KeyValueStoresCallback callback,
    const std::vector<brillo::VariantDictionary>& results) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  std::vector<KeyValueStore> result_stores;
  for (const auto& result : results) {
    KeyValueStore result_store =
        KeyValueStore::ConvertFromVariantDictionary(result);
    result_stores.push_back(result_store);
  }
  std::move(callback).Run(result_stores, Error());
}

void ModemModem3gppProxy::OnScanFailure(KeyValueStoresCallback callback,
                                        brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run(std::vector<KeyValueStore>(), error);
}

void ModemModem3gppProxy::OnSetInitialEpsBearerSettingsSuccess(
    ResultCallback callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  std::move(callback).Run(Error());
}

void ModemModem3gppProxy::OnSetInitialEpsBearerSettingsFailure(
    ResultCallback callback, brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run(error);
}

}  // namespace mm1
}  // namespace shill
