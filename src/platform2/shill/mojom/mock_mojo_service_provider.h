// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOJOM_MOCK_MOJO_SERVICE_PROVIDER_H_
#define SHILL_MOJOM_MOCK_MOJO_SERVICE_PROVIDER_H_

#include <gmock/gmock.h>

#include "shill/mojom/mojo_service_provider.h"

namespace shill {

class Manager;

class MockMojoServiceProvider : public MojoServiceProvider {
 public:
  explicit MockMojoServiceProvider(Manager* manager)
      : MojoServiceProvider(manager) {}
  MockMojoServiceProvider(const MockMojoServiceProvider&) = delete;
  MockMojoServiceProvider& operator=(const MockMojoServiceProvider&) = delete;

  ~MockMojoServiceProvider() override = default;

  MOCK_METHOD(void, Start, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
};

}  // namespace shill

#endif  // SHILL_MOJOM_MOCK_MOJO_SERVICE_PROVIDER_H_
