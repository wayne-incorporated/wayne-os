// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <tuple>

#include <gtest/gtest.h>

#include "diagnostics/wilco_dtc_supportd/telemetry/ec_service.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/ec_service_test_utils.h"

namespace diagnostics {
namespace wilco {
namespace {

using EcEvent = EcService::EcEvent;
using EcEventReason = EcService::EcEvent::Reason;

// Tests for ec_event_test_utils.
//
// This is a parametrized test with the following parameters:
// * |ec_event_reason| - the expected reason of the EC event.
// * |expected_ec_event| - the expected EC event.
class EcEventTestUtilsTest
    : public testing::Test,
      public testing::WithParamInterface<std::tuple<EcEventReason, EcEvent>> {
 protected:
  EcEventReason ec_event_reason() const { return std::get<0>(GetParam()); }

  const EcEvent& expected_ec_event() const { return std::get<1>(GetParam()); }
};

// Tests the conversion from 16-bit payload to little-endian 8-bit payload is
// successful
TEST(ConvertDataInWordsToString, ConvertDataInWordsToString0) {
  constexpr char kPayload[] =
      "\x02\x01\x14\x13\x26\x25\x38\x37\x4a\x49\x5c\x5b";
  constexpr uint16_t kPayloadInWords[] = {0x0102, 0x1314, 0x2526,
                                          0x3738, 0x494a, 0x5b5c};
  EXPECT_EQ(ConvertDataInWordsToString(kPayloadInWords, 6), kPayload);
}

// Tests that GetEcEventWithReason returns the expected EC event given the
// associated EcEvent::Reason.
TEST_P(EcEventTestUtilsTest, GetEcEventWithReason) {
  EXPECT_EQ(GetEcEventWithReason(ec_event_reason()), expected_ec_event());
}

INSTANTIATE_TEST_SUITE_P(
    GetEcEventWithReason,
    EcEventTestUtilsTest,
    testing::Values(
        std::make_tuple(EcEventReason::kNonWilcoCharger,
                        kEcEventNonWilcoCharger),
        std::make_tuple(EcEventReason::kLowPowerCharger,
                        kEcEventLowPowerCharger),
        std::make_tuple(EcEventReason::kBatteryAuth, kEcEventBatteryAuth),
        std::make_tuple(EcEventReason::kDockDisplay, kEcEventDockDisplay),
        std::make_tuple(EcEventReason::kDockThunderbolt,
                        kEcEventDockThunderbolt),
        std::make_tuple(EcEventReason::kIncompatibleDock,
                        kEcEventIncompatibleDock),
        std::make_tuple(EcEventReason::kDockError, kEcEventDockError),
        std::make_tuple(EcEventReason::kSysNotification,
                        kEcEventAcAdapterNoFlags),
        std::make_tuple(EcEventReason::kNonSysNotification,
                        kEcEventNonSysNotification)));

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
