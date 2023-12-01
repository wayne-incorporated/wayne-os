// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_modem_signal_proxy.h"

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

ModemSignalProxy::ModemSignalProxy(const scoped_refptr<dbus::Bus>& bus,
                                   const RpcIdentifier& path,
                                   const std::string& service)
    : proxy_(new org::freedesktop::ModemManager1::Modem::SignalProxy(
          bus, service, path)) {}

ModemSignalProxy::~ModemSignalProxy() = default;

void ModemSignalProxy::Setup(const int rate,
                             Error* /*error*/,
                             ResultCallback callback,
                             int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << rate;
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->SetupAsync(rate,
                     base::BindOnce(&ModemSignalProxy::OnSetupSuccess,
                                    weak_factory_.GetWeakPtr(),
                                    std::move(split_callback.first)),
                     base::BindOnce(&ModemSignalProxy::OnSetupFailure,
                                    weak_factory_.GetWeakPtr(),
                                    std::move(split_callback.second)),
                     timeout);
}

void ModemSignalProxy::OnSetupSuccess(ResultCallback callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  std::move(callback).Run(Error());
}

void ModemSignalProxy::OnSetupFailure(ResultCallback callback,
                                      brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run(error);
}

void ModemSignalProxy::SetupThresholds(const KeyValueStore& settings,
                                       Error* /*error*/,
                                       ResultCallback callback,
                                       int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  brillo::VariantDictionary settings_dict =
      KeyValueStore::ConvertToVariantDictionary(settings);
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->SetupThresholdsAsync(
      settings_dict,
      base::BindOnce(&ModemSignalProxy::OnSetupThresholdsSuccess,
                     weak_factory_.GetWeakPtr(),
                     std::move(split_callback.first)),
      base::BindOnce(&ModemSignalProxy::OnSetupThresholdsFailure,
                     weak_factory_.GetWeakPtr(),
                     std::move(split_callback.second)),
      timeout);
}

void ModemSignalProxy::OnSetupThresholdsSuccess(ResultCallback callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  std::move(callback).Run(Error());
}

void ModemSignalProxy::OnSetupThresholdsFailure(ResultCallback callback,
                                                brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run(error);
}

}  // namespace mm1
}  // namespace shill
