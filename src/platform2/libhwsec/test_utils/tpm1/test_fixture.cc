// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/test_utils/tpm1/test_fixture.h"

#include <gmock/gmock.h>

#include "libhwsec/overalls/overalls_singleton.h"

using ::testing::NiceMock;
using ::testing::StrictMock;

namespace hwsec {

namespace {

overalls::MockOveralls* CreateMockOveralls(MOCK_OVERALLS_TYPE mock_type) {
  switch (mock_type) {
    case MOCK_OVERALLS_TYPE::NICE:
      return new NiceMock<overalls::MockOveralls>();
    case MOCK_OVERALLS_TYPE::PLAIN:
      return new overalls::MockOveralls();
    case MOCK_OVERALLS_TYPE::STRICT:
      return new StrictMock<overalls::MockOveralls>();
  }
}

}  // namespace

Tpm1HwsecTest::Tpm1HwsecTest() : Tpm1HwsecTest(MOCK_OVERALLS_TYPE::NICE) {}

Tpm1HwsecTest::Tpm1HwsecTest(MOCK_OVERALLS_TYPE mock_overalls_type) {
  mock_overalls_.reset(CreateMockOveralls(mock_overalls_type));
  original_overalls_ =
      overalls::OverallsSingleton::SetInstance(mock_overalls_.get());
}

Tpm1HwsecTest::~Tpm1HwsecTest() {
  overalls::OverallsSingleton::SetInstance(original_overalls_);
}

}  // namespace hwsec
