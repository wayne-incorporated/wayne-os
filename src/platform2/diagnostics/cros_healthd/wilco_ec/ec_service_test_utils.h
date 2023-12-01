// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_WILCO_EC_EC_SERVICE_TEST_UTILS_H_
#define DIAGNOSTICS_CROS_HEALTHD_WILCO_EC_EC_SERVICE_TEST_UTILS_H_

#include <cstdint>
#include <string>

#include "diagnostics/cros_healthd/wilco_ec/ec_service.h"

namespace diagnostics {

// Valid EcEvents
extern const EcService::EcEvent kEcEventNonWilcoCharger;
extern const EcService::EcEvent kEcEventLowPowerCharger;
extern const EcService::EcEvent kEcEventBatteryAuth;
extern const EcService::EcEvent kEcEventDockDisplay;
extern const EcService::EcEvent kEcEventDockThunderbolt;
extern const EcService::EcEvent kEcEventIncompatibleDock;
extern const EcService::EcEvent kEcEventDockError;

// Invalid EcEvents
extern const EcService::EcEvent kEcEventNonSysNotification;
extern const EcService::EcEvent kEcEventAcAdapterNoFlags;
extern const EcService::EcEvent kEcEventChargerNoFlags;
extern const EcService::EcEvent kEcEventUsbCNoFlags;
extern const EcService::EcEvent kEcEventNonWilcoChargerBadSubType;
extern const EcService::EcEvent kEcEventInvalidPayloadSize;

// Converts a |uint16_t| array to a |uint8_t| array using little-endian format.
// For example, data [0x0102, 0x1314, 0x2526] will be represented as
// [0x02, 0x01, 0x14, 0x13, 0x26, 0x25].
std::string ConvertDataInWordsToString(const uint16_t* data, uint16_t size);

// Returns a pre-initialized EcEvent whose reason matches the provided reason
EcService::EcEvent GetEcEventWithReason(EcService::EcEvent::Reason reason);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_WILCO_EC_EC_SERVICE_TEST_UTILS_H_
