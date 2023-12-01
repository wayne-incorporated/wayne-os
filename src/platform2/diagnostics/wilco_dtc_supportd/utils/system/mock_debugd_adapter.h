// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_MOCK_DEBUGD_ADAPTER_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_MOCK_DEBUGD_ADAPTER_H_

#include <gmock/gmock.h>

#include "diagnostics/wilco_dtc_supportd/utils/system/debugd_adapter.h"

namespace diagnostics {
namespace wilco {

class MockDebugdAdapter : public DebugdAdapter {
 public:
  MockDebugdAdapter();
  MockDebugdAdapter(const MockDebugdAdapter&) = delete;
  MockDebugdAdapter& operator=(const MockDebugdAdapter&) = delete;
  ~MockDebugdAdapter() override;

  MOCK_METHOD(void, GetSmartAttributes, (OnceStringResultCallback), (override));
  MOCK_METHOD(void, GetNvmeIdentity, (OnceStringResultCallback), (override));
  MOCK_METHOD(StringResult, GetNvmeIdentitySync, (), (override));
  MOCK_METHOD(void,
              RunNvmeShortSelfTest,
              (OnceStringResultCallback),
              (override));
  MOCK_METHOD(void,
              RunNvmeLongSelfTest,
              (OnceStringResultCallback),
              (override));
  MOCK_METHOD(void, StopNvmeSelfTest, (OnceStringResultCallback), (override));
  MOCK_METHOD(void,
              GetNvmeLog,
              (uint32_t, uint32_t, bool, OnceStringResultCallback),
              (override));
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_MOCK_DEBUGD_ADAPTER_H_
