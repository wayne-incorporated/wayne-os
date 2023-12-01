// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/factory/tpm2_simulator_factory_for_test.h"

#include <memory>
#include <utility>

#include "libhwsec/backend/mock_backend.h"
#include "libhwsec/backend/tpm2/backend.h"
#include "libhwsec/middleware/middleware_owner.h"
#include "libhwsec/proxy/tpm2_simulator_proxy_for_test.h"

namespace hwsec {
namespace {

std::unique_ptr<MiddlewareOwner> GetAndInitMiddlewareOwner(
    ThreadingMode mode, Proxy& proxy, MockBackend*& mock_backend_ptr) {
  auto backend = std::make_unique<BackendTpm2>(proxy, MiddlewareDerivative{});
  BackendTpm2* backend_ptr = backend.get();
  auto mock_backend = std::make_unique<MockBackend>(std::move(backend));
  mock_backend_ptr = mock_backend.get();
  auto middleware =
      std::make_unique<MiddlewareOwner>(std::move(mock_backend), mode);
  backend_ptr->set_middleware_derivative_for_test(middleware->Derive());
  return middleware;
}

}  // namespace

Tpm2SimulatorFactoryForTestData::Tpm2SimulatorFactoryForTestData()
    : mock_backend_ptr_(nullptr) {
  auto proxy = std::make_unique<Tpm2SimulatorProxyForTest>();
  CHECK(proxy->Init());
  proxy_ = std::move(proxy);
}

Tpm2SimulatorFactoryForTestData::~Tpm2SimulatorFactoryForTestData() = default;

Tpm2SimulatorFactoryForTest::Tpm2SimulatorFactoryForTest(ThreadingMode mode)
    : FactoryImpl(GetAndInitMiddlewareOwner(mode, *proxy_, mock_backend_ptr_)) {
}

Tpm2SimulatorFactoryForTest::~Tpm2SimulatorFactoryForTest() = default;

MockBackend& Tpm2SimulatorFactoryForTest::GetMockBackend() {
  return *mock_backend_ptr_;
}

FakeTpmNvramForTest& Tpm2SimulatorFactoryForTest::GetFakeTpmNvramForTest() {
  return proxy_->GetFakeTpmNvramForTest();
}

bool Tpm2SimulatorFactoryForTest::ExtendPCR(uint32_t index,
                                            const std::string& data) {
  return proxy_->ExtendPCR(index, data);
}

}  // namespace hwsec
