// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_MOCK_RUNTIME_PROBE_CLIENT_H_
#define RMAD_SYSTEM_MOCK_RUNTIME_PROBE_CLIENT_H_

#include "rmad/system/runtime_probe_client.h"

#include <vector>

#include <gmock/gmock.h>

namespace rmad {

class MockRuntimeProbeClient : public RuntimeProbeClient {
 public:
  MockRuntimeProbeClient() = default;
  MockRuntimeProbeClient(const MockRuntimeProbeClient&) = delete;
  MockRuntimeProbeClient& operator=(const MockRuntimeProbeClient&) = delete;
  ~MockRuntimeProbeClient() override = default;

  MOCK_METHOD(bool,
              ProbeCategories,
              (const std::vector<RmadComponent>&,
               bool,
               ComponentsWithIdentifier*),
              (override));
  MOCK_METHOD(bool,
              ProbeSsfcComponents,
              (bool, ComponentsWithIdentifier*),
              (override));
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_MOCK_RUNTIME_PROBE_CLIENT_H_
