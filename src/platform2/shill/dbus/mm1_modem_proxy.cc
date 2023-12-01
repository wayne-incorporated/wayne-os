// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_modem_proxy.h"

#include <tuple>
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

ModemProxy::ModemProxy(const scoped_refptr<dbus::Bus>& bus,
                       const RpcIdentifier& path,
                       const std::string& service)
    : proxy_(
          new org::freedesktop::ModemManager1::ModemProxy(bus, service, path)) {
  // Register signal handlers.
  proxy_->RegisterStateChangedSignalHandler(
      base::BindRepeating(&ModemProxy::StateChanged,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&ModemProxy::OnSignalConnected,
                     weak_factory_.GetWeakPtr()));
}

ModemProxy::~ModemProxy() = default;

void ModemProxy::Enable(bool enable, ResultCallback callback, int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << enable;
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  proxy_->EnableAsync(
      enable,
      base::BindOnce(&ModemProxy::OnOperationSuccess,
                     weak_factory_.GetWeakPtr(), std::move(cb1), __func__),
      base::BindOnce(&ModemProxy::OnOperationFailure,
                     weak_factory_.GetWeakPtr(), std::move(cb2), __func__),
      timeout);
}

void ModemProxy::CreateBearer(const KeyValueStore& properties,
                              RpcIdentifierCallback callback,
                              int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  brillo::VariantDictionary properties_dict =
      KeyValueStore::ConvertToVariantDictionary(properties);
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  proxy_->CreateBearerAsync(
      properties_dict,
      base::BindOnce(&ModemProxy::OnCreateBearerSuccess,
                     weak_factory_.GetWeakPtr(), std::move(cb1)),
      base::BindOnce(&ModemProxy::OnCreateBearerFailure,
                     weak_factory_.GetWeakPtr(), std::move(cb2)),
      timeout);
}

void ModemProxy::DeleteBearer(const RpcIdentifier& bearer,
                              ResultCallback callback,
                              int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << bearer.value();
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  proxy_->DeleteBearerAsync(
      bearer,
      base::BindOnce(&ModemProxy::OnOperationSuccess,
                     weak_factory_.GetWeakPtr(), std::move(cb1), __func__),
      base::BindOnce(&ModemProxy::OnOperationFailure,
                     weak_factory_.GetWeakPtr(), std::move(cb2), __func__),
      timeout);
}

void ModemProxy::Reset(ResultCallback callback, int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  proxy_->ResetAsync(
      base::BindOnce(&ModemProxy::OnOperationSuccess,
                     weak_factory_.GetWeakPtr(), std::move(cb1), __func__),
      base::BindOnce(&ModemProxy::OnOperationFailure,
                     weak_factory_.GetWeakPtr(), std::move(cb2), __func__),
      timeout);
}

void ModemProxy::FactoryReset(const std::string& code,
                              ResultCallback callback,
                              int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  proxy_->FactoryResetAsync(
      code,
      base::BindOnce(&ModemProxy::OnOperationSuccess,
                     weak_factory_.GetWeakPtr(), std::move(cb1), __func__),
      base::BindOnce(&ModemProxy::OnOperationFailure,
                     weak_factory_.GetWeakPtr(), std::move(cb2), __func__),
      timeout);
}

void ModemProxy::SetCurrentCapabilities(uint32_t capabilities,
                                        ResultCallback callback,
                                        int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << capabilities;
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  proxy_->SetCurrentCapabilitiesAsync(
      capabilities,
      base::BindOnce(&ModemProxy::OnOperationSuccess,
                     weak_factory_.GetWeakPtr(), std::move(cb1), __func__),
      base::BindOnce(&ModemProxy::OnOperationFailure,
                     weak_factory_.GetWeakPtr(), std::move(cb2), __func__),
      timeout);
}

void ModemProxy::SetCurrentModes(uint32_t allowed_modes,
                                 uint32_t preferred_mode,
                                 ResultCallback callback,
                                 int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << ": " << allowed_modes << " " << preferred_mode;
  std::tuple<uint32_t, uint32_t> modes{allowed_modes, preferred_mode};
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  proxy_->SetCurrentModesAsync(
      modes,
      base::BindOnce(&ModemProxy::OnOperationSuccess,
                     weak_factory_.GetWeakPtr(), std::move(cb1), __func__),
      base::BindOnce(&ModemProxy::OnOperationFailure,
                     weak_factory_.GetWeakPtr(), std::move(cb2), __func__),
      timeout);
}

void ModemProxy::SetCurrentBands(const std::vector<uint32_t>& bands,
                                 ResultCallback callback,
                                 int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  proxy_->SetCurrentBandsAsync(
      bands,
      base::BindOnce(&ModemProxy::OnOperationSuccess,
                     weak_factory_.GetWeakPtr(), std::move(cb1), __func__),
      base::BindOnce(&ModemProxy::OnOperationFailure,
                     weak_factory_.GetWeakPtr(), std::move(cb2), __func__),
      timeout);
}

void ModemProxy::SetPrimarySimSlot(uint32_t slot,
                                   ResultCallback callback,
                                   int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << slot;
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  proxy_->SetPrimarySimSlotAsync(
      slot,
      base::BindOnce(&ModemProxy::OnOperationSuccess,
                     weak_factory_.GetWeakPtr(), std::move(cb1), __func__),
      base::BindOnce(&ModemProxy::OnOperationFailure,
                     weak_factory_.GetWeakPtr(), std::move(cb2), __func__),
      timeout);
}

void ModemProxy::Command(const std::string& cmd,
                         uint32_t user_timeout,
                         StringCallback callback,
                         int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << cmd;
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  proxy_->CommandAsync(
      cmd, user_timeout,
      base::BindOnce(&ModemProxy::OnCommandSuccess, weak_factory_.GetWeakPtr(),
                     std::move(cb1)),
      base::BindOnce(&ModemProxy::OnCommandFailure, weak_factory_.GetWeakPtr(),
                     std::move(cb2)),
      timeout);
}

void ModemProxy::SetPowerState(uint32_t power_state,
                               ResultCallback callback,
                               int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << power_state;
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  proxy_->SetPowerStateAsync(
      power_state,
      base::BindOnce(&ModemProxy::OnOperationSuccess,
                     weak_factory_.GetWeakPtr(), std::move(cb1), __func__),
      base::BindOnce(&ModemProxy::OnOperationFailure,
                     weak_factory_.GetWeakPtr(), std::move(cb2), __func__),
      timeout);
}

void ModemProxy::StateChanged(int32_t old, int32_t _new, uint32_t reason) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  if (state_changed_callback_.is_null()) {
    return;
  }
  state_changed_callback_.Run(old, _new, reason);
}

void ModemProxy::OnCreateBearerSuccess(RpcIdentifierCallback callback,
                                       const dbus::ObjectPath& path) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << path.value();
  std::move(callback).Run(path, Error());
}

void ModemProxy::OnCreateBearerFailure(RpcIdentifierCallback callback,
                                       brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run(RpcIdentifier(""), error);
}

void ModemProxy::OnCommandSuccess(StringCallback callback,
                                  const std::string& response) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << response;
  std::move(callback).Run(response, Error());
}

void ModemProxy::OnCommandFailure(StringCallback callback,
                                  brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run("", error);
}

void ModemProxy::OnOperationSuccess(ResultCallback callback,
                                    const std::string& operation) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << operation;
  std::move(callback).Run(Error());
}

void ModemProxy::OnOperationFailure(ResultCallback callback,
                                    const std::string& operation,
                                    brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << operation;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run(error);
}

void ModemProxy::OnSignalConnected(const std::string& interface_name,
                                   const std::string& signal_name,
                                   bool success) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << ": interface: " << interface_name
      << " signal: " << signal_name << "success: " << success;
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

}  // namespace mm1
}  // namespace shill
