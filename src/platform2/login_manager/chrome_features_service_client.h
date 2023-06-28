// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_CHROME_FEATURES_SERVICE_CLIENT_H_
#define LOGIN_MANAGER_CHROME_FEATURES_SERVICE_CLIENT_H_

#include <string>

#include <base/callback.h>
#include <base/macros.h>
#include <base/memory/weak_ptr.h>
#include <base/optional.h>

namespace dbus {
class ObjectProxy;
class Response;
}  // namespace dbus

namespace login_manager {

// Helper to call chrome features dbus service.
class ChromeFeaturesServiceClient {
 public:
  explicit ChromeFeaturesServiceClient(dbus::ObjectProxy* proxy);
  ChromeFeaturesServiceClient(const ChromeFeaturesServiceClient&) = delete;
  ChromeFeaturesServiceClient& operator=(const ChromeFeaturesServiceClient&) =
      delete;

  ~ChromeFeaturesServiceClient();

  // Async call to check whether given feature is enabled. |enabled| is
  // base::nullopt if there is error calling the service. Otherwise,
  // |enable.value()| indicates whether the feature is enabled or not.
  using IsFeatureEnabledCallback =
      base::OnceCallback<void(base::Optional<bool> enabled)>;
  void IsFeatureEnabled(const std::string& feature_name,
                        IsFeatureEnabledCallback callback);

 private:
  void OnWaitForServiceForIsFeatureEnabled(const std::string& feature_name,
                                           IsFeatureEnabledCallback callback,
                                           bool available);

  void CallIsFeatureEnabled(const std::string& feature_name,
                            IsFeatureEnabledCallback callback);
  void HandlelIsFeatureEnabledResponse(IsFeatureEnabledCallback callback,
                                       dbus::Response* response);

  dbus::ObjectProxy* proxy_ = nullptr;

  base::WeakPtrFactory<ChromeFeaturesServiceClient> weak_ptr_factory_{this};
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_CHROME_FEATURES_SERVICE_CLIENT_H_
