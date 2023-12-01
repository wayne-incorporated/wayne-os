// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_sim_proxy.h"

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

namespace {
constexpr base::TimeDelta kDefaultTimeout = base::Seconds(5);
constexpr base::TimeDelta kSendPinTimeout = base::Seconds(20);
constexpr base::TimeDelta kSendPukTimeout = base::Seconds(20);
}  // namespace

namespace mm1 {

SimProxy::SimProxy(const scoped_refptr<dbus::Bus>& bus,
                   const RpcIdentifier& path,
                   const std::string& service)
    : proxy_(
          new org::freedesktop::ModemManager1::SimProxy(bus, service, path)) {}

SimProxy::~SimProxy() = default;

void SimProxy::SendPin(const std::string& pin, ResultCallback callback) {
  // pin is intentionally not logged.
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->SendPinAsync(
      pin,
      base::BindOnce(&SimProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                     std::move(split_callback.first), __func__),
      base::BindOnce(&SimProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                     std::move(split_callback.second), __func__),
      kSendPinTimeout.InMilliseconds());
}

void SimProxy::SendPuk(const std::string& puk,
                       const std::string& pin,
                       ResultCallback callback) {
  // pin and puk are intentionally not logged.
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->SendPukAsync(
      puk, pin,
      base::BindOnce(&SimProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                     std::move(split_callback.first), __func__),
      base::BindOnce(&SimProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                     std::move(split_callback.second), __func__),
      kSendPukTimeout.InMilliseconds());
}

void SimProxy::EnablePin(const std::string& pin,
                         const bool enabled,
                         ResultCallback callback) {
  // pin is intentionally not logged.
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << enabled;
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->EnablePinAsync(
      pin, enabled,
      base::BindOnce(&SimProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                     std::move(split_callback.first), __func__),
      base::BindOnce(&SimProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                     std::move(split_callback.second), __func__),
      kDefaultTimeout.InMilliseconds());
}

void SimProxy::ChangePin(const std::string& old_pin,
                         const std::string& new_pin,
                         ResultCallback callback) {
  // old_pin and new_pin are intentionally not logged.
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  proxy_->ChangePinAsync(
      old_pin, new_pin,
      base::BindOnce(&SimProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                     std::move(split_callback.first), __func__),
      base::BindOnce(&SimProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                     std::move(split_callback.second), __func__),
      kDefaultTimeout.InMilliseconds());
}

void SimProxy::OnOperationSuccess(ResultCallback callback,
                                  const std::string& operation) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << operation;
  std::move(callback).Run(Error());
}

void SimProxy::OnOperationFailure(ResultCallback callback,
                                  const std::string& operation,
                                  brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << operation;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  std::move(callback).Run(error);
}

}  // namespace mm1
}  // namespace shill
