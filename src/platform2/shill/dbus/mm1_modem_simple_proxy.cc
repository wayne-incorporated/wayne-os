// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_modem_simple_proxy.h"

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

ModemSimpleProxy::ModemSimpleProxy(const scoped_refptr<dbus::Bus>& bus,
                                   const RpcIdentifier& path,
                                   const std::string& service)
    : proxy_(new org::freedesktop::ModemManager1::Modem::SimpleProxy(
          bus, service, path)) {}

ModemSimpleProxy::~ModemSimpleProxy() = default;

void ModemSimpleProxy::Connect(const KeyValueStore& properties,
                               RpcIdentifierCallback callback,
                               int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  brillo::VariantDictionary properties_dict =
      KeyValueStore::ConvertToVariantDictionary(properties);
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->ConnectAsync(properties_dict,
                       base::BindOnce(&ModemSimpleProxy::OnConnectSuccess,
                                      weak_factory_.GetWeakPtr(),
                                      std::move(split_callback.first)),
                       base::BindOnce(&ModemSimpleProxy::OnConnectFailure,
                                      weak_factory_.GetWeakPtr(),
                                      std::move(split_callback.second)),
                       timeout);
}

void ModemSimpleProxy::Disconnect(const RpcIdentifier& bearer,
                                  ResultCallback callback,
                                  int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << bearer.value();
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->DisconnectAsync(dbus::ObjectPath(bearer),
                          base::BindOnce(&ModemSimpleProxy::OnDisconnectSuccess,
                                         weak_factory_.GetWeakPtr(),
                                         std::move(split_callback.first)),
                          base::BindOnce(&ModemSimpleProxy::OnDisconnectFailure,
                                         weak_factory_.GetWeakPtr(),
                                         std::move(split_callback.second)),
                          timeout);
}

void ModemSimpleProxy::OnConnectSuccess(RpcIdentifierCallback callback,
                                        const dbus::ObjectPath& path) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << path.value();
  std::move(callback).Run(path, Error());
}

void ModemSimpleProxy::OnConnectFailure(RpcIdentifierCallback callback,
                                        brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run(RpcIdentifier(""), error);
}

void ModemSimpleProxy::OnDisconnectSuccess(ResultCallback callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  std::move(callback).Run(Error());
}

void ModemSimpleProxy::OnDisconnectFailure(ResultCallback callback,
                                           brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run(error);
}

}  // namespace mm1
}  // namespace shill
