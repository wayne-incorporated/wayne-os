// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dns-proxy/chrome_features_service_client.h"

#include <optional>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>

namespace dns_proxy {

std::unique_ptr<ChromeFeaturesServiceClient> ChromeFeaturesServiceClient::New(
    scoped_refptr<dbus::Bus> bus) {
  auto* proxy = bus->GetObjectProxy(
      chromeos::kChromeFeaturesServiceName,
      dbus::ObjectPath(chromeos::kChromeFeaturesServicePath));
  if (!proxy) {
    LOG(ERROR) << "Failed to create object proxy for "
               << chromeos::kChromeFeaturesServiceName;
    return nullptr;
  }

  return std::make_unique<ChromeFeaturesServiceClient>(proxy);
}

ChromeFeaturesServiceClient::ChromeFeaturesServiceClient(
    dbus::ObjectProxy* proxy)
    : proxy_(proxy) {}

void ChromeFeaturesServiceClient::IsDNSProxyEnabled(
    IsFeatureEnabledCallback callback) {
  if (!proxy_) {
    LOG(DFATAL) << "No object proxy";
    return;
  }

  proxy_->WaitForServiceToBeAvailable(base::BindOnce(
      &ChromeFeaturesServiceClient::OnWaitForServiceAndCallMethod,
      weak_ptr_factory_.GetWeakPtr(),
      chromeos::kChromeFeaturesServiceIsDNSProxyEnabledMethod,
      std::move(callback)));
}

void ChromeFeaturesServiceClient::OnWaitForServiceAndCallMethod(
    const std::string& method_name,
    IsFeatureEnabledCallback callback,
    bool available) {
  if (!available) {
    std::move(callback).Run(std::nullopt);
    return;
  }

  dbus::MethodCall call(chromeos::kChromeFeaturesServiceInterface, method_name);
  dbus::MessageWriter writer(&call);
  proxy_->CallMethod(
      &call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(&ChromeFeaturesServiceClient::HandleCallResponse,
                     weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
}

void ChromeFeaturesServiceClient::HandleCallResponse(
    IsFeatureEnabledCallback callback, dbus::Response* response) {
  if (!response) {
    std::move(callback).Run(std::nullopt);
    return;
  }

  dbus::MessageReader reader(response);
  bool feature_enabled = false;
  if (!reader.PopBool(&feature_enabled)) {
    std::move(callback).Run(std::nullopt);
    return;
  }

  std::move(callback).Run(feature_enabled);
}

}  // namespace dns_proxy
