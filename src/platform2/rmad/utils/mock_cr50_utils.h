// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_CR50_UTILS_H_
#define RMAD_UTILS_MOCK_CR50_UTILS_H_

#include "rmad/utils/cr50_utils.h"

#include <string>

#include <gmock/gmock.h>

namespace rmad {

class MockCr50Utils : public Cr50Utils {
 public:
  MockCr50Utils() = default;
  ~MockCr50Utils() override = default;

  MOCK_METHOD(bool, GetRsuChallengeCode, (std::string*), (const, override));
  MOCK_METHOD(bool, PerformRsu, (const std::string&), (const, override));
  MOCK_METHOD(bool, EnableFactoryMode, (), (const, override));
  MOCK_METHOD(bool, DisableFactoryMode, (), (const, override));
  MOCK_METHOD(bool, IsFactoryModeEnabled, (), (const, override));
  MOCK_METHOD(bool, GetBoardIdType, (std::string*), (const, override));
  MOCK_METHOD(bool, GetBoardIdFlags, (std::string*), (const, override));
  MOCK_METHOD(bool, SetBoardId, (bool), (const, override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_CR50_UTILS_H_
