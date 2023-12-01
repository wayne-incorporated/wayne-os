// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_PROXY_MOCK_AUTH_STACK_MANAGER_PROXY_BASE_H_
#define BIOD_BIOD_PROXY_MOCK_AUTH_STACK_MANAGER_PROXY_BASE_H_

#include <string>

#include <biod/biod_proxy/auth_stack_manager_proxy_base.h>
#include <gmock/gmock.h>

namespace biod {
class MockAuthStackManagerProxyBase : public AuthStackManagerProxyBase {
 public:
  MockAuthStackManagerProxyBase() = default;
  ~MockAuthStackManagerProxyBase() override = default;

  MOCK_METHOD(void,
              ConnectToEnrollScanDoneSignal,
              (SignalCallback signal_callback,
               OnConnectedCallback on_connected_callback),
              (override));

  MOCK_METHOD(void,
              ConnectToAuthScanDoneSignal,
              (SignalCallback signal_callback,
               OnConnectedCallback on_connected_callback),
              (override));

  MOCK_METHOD(void,
              ConnectToSessionFailedSignal,
              (SignalCallback signal_callback,
               OnConnectedCallback on_connected_callback),
              (override));

  MOCK_METHOD(void,
              StartEnrollSession,
              (base::OnceCallback<void(bool success)> callback),
              (override));

  MOCK_METHOD(void, EndEnrollSession, (), (override));

  MOCK_METHOD(void,
              CreateCredential,
              (const CreateCredentialRequest&, CreateCredentialCallback),
              (override));

  MOCK_METHOD(void,
              StartAuthSession,
              (std::string, base::OnceCallback<void(bool success)> callback),
              (override));

  MOCK_METHOD(void, EndAuthSession, (), (override));

  MOCK_METHOD(void,
              AuthenticateCredential,
              (const AuthenticateCredentialRequest&,
               AuthenticateCredentialCallback),
              (override));
};
}  // namespace biod

#endif  // BIOD_BIOD_PROXY_MOCK_AUTH_STACK_MANAGER_PROXY_BASE_H_
