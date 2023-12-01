// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SSFC_MOCK_SSFC_PROBER_H_
#define RMAD_SSFC_MOCK_SSFC_PROBER_H_

#include "rmad/ssfc/ssfc_prober.h"

#include "gmock/gmock.h"

namespace rmad {

class MockSsfcProber : public SsfcProber {
 public:
  MockSsfcProber() = default;
  ~MockSsfcProber() override = default;

  MOCK_METHOD(bool, IsSsfcRequired, (), (const, override));
  MOCK_METHOD(bool, ProbeSsfc, (uint32_t*), (const, override));
};

}  // namespace rmad

#endif  // RMAD_SSFC_MOCK_SSFC_PROBER_H_
