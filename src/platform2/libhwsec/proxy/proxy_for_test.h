// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_PROXY_PROXY_FOR_TEST_H_
#define LIBHWSEC_PROXY_PROXY_FOR_TEST_H_

#include <memory>

#include <gmock/gmock.h>

#include "libhwsec/proxy/proxy.h"

#ifndef BUILD_LIBHWSEC
#error "Don't include this file outside libhwsec!"
#endif

// Forward declarations for mocks
namespace hwsec::overalls {
class MockOveralls;
}  // namespace hwsec::overalls

namespace trunks {
class MockCommandTransceiver;
class MockTpm;
class MockTpmCache;
class MockTpmState;
class MockTpmUtility;
class MockAuthorizationDelegate;
class MockHmacSession;
class MockPolicySession;
class MockBlobParser;
class TrunksFactoryForTest;
}  // namespace trunks

namespace org::chromium {
class TpmManagerProxyMock;
class TpmNvramProxyMock;
}  // namespace org::chromium

namespace hwsec {
class FakePlatform;

// A proxy implementation for testing. Custom instances can be injected. If no
// instance has been injected, a default mock instance will be used. Objects for
// which ownership is passed to the caller are instantiated as forwarders which
// simply forward calls to the current instance set for the class.
//
// Example usage:
//   ProxyForTest proxy;
//   org::chromium::TpmManagerProxyMock mock_tpm_manager;
//   proxy.SetTpmManager(mock_tpm_manager);
//   // Set expectations on mock_tpm_manager...

class ProxyForTest : public Proxy {
 public:
  ProxyForTest();
  ~ProxyForTest() override;

  hwsec::overalls::MockOveralls& GetMockOveralls();
  trunks::MockCommandTransceiver& GetMockCommandTransceiver();
  trunks::MockTpm& GetMockTpm();
  trunks::MockTpmCache& GetMockTpmCache();
  trunks::MockTpmState& GetMockTpmState();
  trunks::MockTpmUtility& GetMockTpmUtility();
  trunks::MockAuthorizationDelegate& GetMockAuthorizationDelegate();
  trunks::MockHmacSession& GetMockHmacSession();
  trunks::MockPolicySession& GetMockPolicySession();
  trunks::MockPolicySession& GetMockTrialSession();
  trunks::MockBlobParser& GetMockBlobParser();
  org::chromium::TpmManagerProxyMock& GetMockTpmManagerProxy();
  org::chromium::TpmNvramProxyMock& GetMockTpmNvramProxy();
  crossystem::Crossystem& GetFakeCrossystem();
  FakePlatform& GetFakePlatform();

 private:
  // The InnerData implementation is in the cpp file.
  struct InnerData;

  std::unique_ptr<InnerData> inner_data_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_PROXY_PROXY_FOR_TEST_H_
