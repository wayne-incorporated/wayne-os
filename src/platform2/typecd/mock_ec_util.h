// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_MOCK_EC_UTIL_H_
#define TYPECD_MOCK_EC_UTIL_H_

#include <gmock/gmock.h>

#include "typecd/ec_util.h"

namespace typecd {

class MockECUtil : public ECUtil {
 public:
  MOCK_METHOD(bool, ModeEntrySupported, (), (override));
  MOCK_METHOD(bool, EnterMode, (int, TypeCMode), (override));
  MOCK_METHOD(bool, ExitMode, (int), (override));
  MOCK_METHOD(bool, DpState, (int, bool*), (override));
  MOCK_METHOD(bool, HpdState, (int, bool*), (override));
};

}  // namespace typecd

#endif  // TYPECD_MOCK_EC_UTIL_H_
