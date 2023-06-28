// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/chrome_features_service_client.h"

#include <utility>

#include <base/bind.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

namespace login_manager {

ChromeFeaturesServiceClient::ChromeFeaturesServiceClient(
    dbus::ObjectProxy* proxy)
    : proxy_(proxy) {}

ChromeFeaturesServiceClient::~ChromeFeaturesServiceClient() = default;

void ChromeFeaturesServiceClient::IsFeatureEnabled(
    const std::string& feature_name, IsFeatureEnabledCallback callback) {
  proxy_->WaitForServiceToBeAvailable(base::BindOnce(
      &ChromeFeaturesServiceClient::OnWaitForServiceForIsFeatureEnabled,
      weak_ptr_factory_.GetWeakPtr(), feature_name, std::move(callback)));
}

void ChromeFeaturesServiceClient::OnWaitForServiceForIsFeatureEnabled(
    const std::string& feature_name,
    IsFeatureEnabledCallback callback,
    bool available) {
  if (!available) {
    std::move(callback).Run(base::nullopt);
    return;
  }

  CallIsFeatureEnabled(feature_name, std::move(callback));
}

void ChromeFeaturesServiceClient::CallIsFeatureEnabled(
    const std::string& feature_name, IsFeatureEnabledCallback callback) {
  dbus::MethodCall call(chromeos::kChromeFeaturesServiceInterface,
                        chromeos::kChromeFeaturesServiceIsFeatureEnabledMethod);
  dbus::MessageWriter writer(&call);
  writer.AppendString(feature_name);
  proxy_->CallMethod(
      &call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(
          &ChromeFeaturesServiceClient::HandlelIsFeatureEnabledResponse,
          weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
}

void ChromeFeaturesServiceClient::HandlelIsFeatureEnabledResponse(
    IsFeatureEnabledCallback callback, dbus::Response* response) {
  if (!response) {
    std::move(callback).Run(base::nullopt);
    return;
  }

  dbus::MessageReader reader(response);
  bool feature_enabled = false;
  if (!reader.PopBool(&feature_enabled)) {
    std::move(callback).Run(base::nullopt);
    return;
  }

  std::move(callback).Run(feature_enabled);
}

}  // namespace login_manager
