// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DNS_PROXY_CHROME_FEATURES_SERVICE_CLIENT_H_
#define DNS_PROXY_CHROME_FEATURES_SERVICE_CLIENT_H_

#include <memory>
#include <optional>
#include <string>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>

namespace dns_proxy {

// Helper to call chrome features dbus service.
class ChromeFeaturesServiceClient {
 public:
  static std::unique_ptr<ChromeFeaturesServiceClient> New(
      scoped_refptr<dbus::Bus> bus);

  explicit ChromeFeaturesServiceClient(dbus::ObjectProxy* proxy);
  ChromeFeaturesServiceClient(const ChromeFeaturesServiceClient&) = delete;
  ChromeFeaturesServiceClient& operator=(const ChromeFeaturesServiceClient&) =
      delete;
  virtual ~ChromeFeaturesServiceClient() = default;

  // Async call to check whether given feature is enabled. |enabled| is
  // std::nullopt if there is error calling the service. Otherwise,
  // |enable.value()| indicates whether the feature is enabled or not.
  using IsFeatureEnabledCallback =
      base::OnceCallback<void(std::optional<bool> enabled)>;

  // Checks the Chrome Features service to determine whether or not the
  // dns-proxy service is enabled.
  virtual void IsDNSProxyEnabled(IsFeatureEnabledCallback callback);

 private:
  void OnWaitForServiceAndCallMethod(const std::string& method_name,
                                     IsFeatureEnabledCallback callback,
                                     bool available);

  void HandleCallResponse(IsFeatureEnabledCallback callback,
                          dbus::Response* response);

  dbus::ObjectProxy* proxy_ = nullptr;

  base::WeakPtrFactory<ChromeFeaturesServiceClient> weak_ptr_factory_{this};
};

}  // namespace dns_proxy

#endif  // DNS_PROXY_CHROME_FEATURES_SERVICE_CLIENT_H_
