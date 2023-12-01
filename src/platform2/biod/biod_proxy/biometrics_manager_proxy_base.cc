// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/biod_proxy/biometrics_manager_proxy_base.h"

#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <chromeos/dbus/service_constants.h>

#include "biod/biod_constants.h"
#include "biod/biod_proxy/util.h"

namespace biod {

using FinishCallback = base::RepeatingCallback<void(bool success)>;

const char* BiometricsManagerStatusToString(
    const BiometricsManagerStatus& status) {
  switch (status) {
    case BiometricsManagerStatus::INITIALIZED:
      return "Initialized";
    default:
      return "Unknown status";
  }
}

BiometricsManagerProxyBase::BiometricsManagerProxyBase()
    : proxy_(nullptr), weak_factory_(this), biod_auth_session_(nullptr) {}

bool BiometricsManagerProxyBase::Initialize(const scoped_refptr<dbus::Bus>& bus,
                                            const dbus::ObjectPath& path) {
  bus_ = bus;
  proxy_ = bus_->GetObjectProxy(biod::kBiodServiceName, path);

  if (!proxy_)
    return false;

  proxy_->ConnectToSignal(
      biod::kBiometricsManagerInterface,
      biod::kBiometricsManagerSessionFailedSignal,
      base::BindRepeating(&BiometricsManagerProxyBase::OnSessionFailed,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&BiometricsManagerProxyBase::OnSignalConnected,
                     weak_factory_.GetWeakPtr()));
  return true;
}

std::unique_ptr<BiometricsManagerProxyBase> BiometricsManagerProxyBase::Create(
    const scoped_refptr<dbus::Bus>& bus, const dbus::ObjectPath& path) {
  // Using new to access non-public constructor. See https://abseil.io/tips/134.
  auto biometrics_manager_proxy_base =
      base::WrapUnique(new BiometricsManagerProxyBase());

  if (!biometrics_manager_proxy_base->Initialize(bus, path))
    return nullptr;

  return biometrics_manager_proxy_base;
}

void BiometricsManagerProxyBase::ConnectToAuthScanDoneSignal(
    SignalCallback signal_callback, OnConnectedCallback on_connected_callback) {
  proxy_->ConnectToSignal(biod::kBiometricsManagerInterface,
                          biod::kBiometricsManagerAuthScanDoneSignal,
                          std::move(signal_callback),
                          std::move(on_connected_callback));
}

const dbus::ObjectPath BiometricsManagerProxyBase::path() const {
  return proxy_->object_path();
}

void BiometricsManagerProxyBase::SetFinishHandler(
    const FinishCallback& on_finish) {
  on_finish_ = on_finish;
}

dbus::ObjectProxy* BiometricsManagerProxyBase::HandleAuthSessionResponse(
    dbus::Response* response) {
  if (!response) {
    LOG(ERROR) << biod::kBiometricsManagerStartAuthSessionMethod
               << " had no response.";
    return nullptr;
  }

  dbus::MessageReader response_reader(response);
  dbus::ObjectPath auth_path;
  if (!response_reader.PopObjectPath(&auth_path)) {
    LOG(ERROR) << biod::kBiometricsManagerStartAuthSessionMethod
               << " had incorrect response.";
    return nullptr;
  }
  return bus_->GetObjectProxy(biod::kBiodServiceName, auth_path);
}

bool BiometricsManagerProxyBase::StartAuthSession() {
  LOG(INFO) << "Starting biometric auth session.";
  dbus::MethodCall method_call(biod::kBiometricsManagerInterface,
                               biod::kBiometricsManagerStartAuthSessionMethod);

  std::unique_ptr<dbus::Response> response =
      proxy_->CallMethodAndBlock(&method_call, dbus_constants::kDbusTimeoutMs);

  biod_auth_session_ = HandleAuthSessionResponse(response.get());
  return biod_auth_session_ != nullptr;
}

void BiometricsManagerProxyBase::OnStartAuthSessionResp(
    base::OnceCallback<void(bool success)> callback, dbus::Response* response) {
  biod_auth_session_ = HandleAuthSessionResponse(response);
  std::move(callback).Run(biod_auth_session_ != nullptr);
}

void BiometricsManagerProxyBase::StartAuthSessionAsync(
    base::OnceCallback<void(bool success)> callback) {
  LOG(INFO) << "Starting biometric auth session.";
  dbus::MethodCall method_call(biod::kBiometricsManagerInterface,
                               biod::kBiometricsManagerStartAuthSessionMethod);

  proxy_->CallMethod(
      &method_call, dbus_constants::kDbusTimeoutMs,
      base::BindOnce(&BiometricsManagerProxyBase::OnStartAuthSessionResp,
                     base::Unretained(this), std::move(callback)));
}

void BiometricsManagerProxyBase::EndAuthSession() {
  LOG(INFO) << "Ending biometric authentication";
  dbus::MethodCall end_call(biod::kAuthSessionInterface,
                            biod::kAuthSessionEndMethod);
  biod_auth_session_->CallMethodAndBlock(&end_call,
                                         dbus_constants::kDbusTimeoutMs);
}

void BiometricsManagerProxyBase::OnFinish(bool success) {
  if (on_finish_)
    on_finish_.Run(success);
}

void BiometricsManagerProxyBase::OnSessionFailed(dbus::Signal* signal) {
  LOG(ERROR) << "Biometric device failed";
  OnFinish(false);
}

void BiometricsManagerProxyBase::OnSignalConnected(const std::string& interface,
                                                   const std::string& signal,
                                                   bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to connect to signal " << signal << " on interface "
               << interface;
    OnFinish(false);
  }
}

}  // namespace biod
