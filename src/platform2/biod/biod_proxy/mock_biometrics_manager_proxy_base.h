// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_PROXY_MOCK_BIOMETRICS_MANAGER_PROXY_BASE_H_
#define BIOD_BIOD_PROXY_MOCK_BIOMETRICS_MANAGER_PROXY_BASE_H_

#include <biod/biod_proxy/biometrics_manager_proxy_base.h>
#include <gmock/gmock.h>

namespace biod {
class MockBiometricsManagerProxyBase : public BiometricsManagerProxyBase {
 public:
  MockBiometricsManagerProxyBase() = default;
  ~MockBiometricsManagerProxyBase() override = default;

  MOCK_METHOD(void,
              ConnectToAuthScanDoneSignal,
              (SignalCallback signal_callback,
               OnConnectedCallback on_connected_callback),
              (override));

  MOCK_METHOD(const dbus::ObjectPath, path, (), (const, override));

  MOCK_METHOD(void,
              SetFinishHandler,
              (const FinishCallback& on_finish),
              (override));

  MOCK_METHOD(bool, StartAuthSession, (), (override));

  MOCK_METHOD(void,
              StartAuthSessionAsync,
              (base::OnceCallback<void(bool success)> callback),
              (override));

  MOCK_METHOD(void, EndAuthSession, (), (override));
};
}  // namespace biod

#endif  // BIOD_BIOD_PROXY_MOCK_BIOMETRICS_MANAGER_PROXY_BASE_H_
