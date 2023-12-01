// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/wilco_ec/ec_service_test_utils.h"

#include <base/check_op.h>
#include <base/logging.h>
#include <base/notreached.h>

namespace diagnostics {

namespace {

using EcEvent = diagnostics::EcService::EcEvent;

// A meaningless and meaningful EcEvent::Type
const auto kNonSystemNotifyType = static_cast<EcEvent::Type>(0xabcd);
const auto kSystemNotifyType = static_cast<EcEvent::Type>(0x0012);

// Valid payloads of |EcEvent::Type::SYSTEM_NOTIFY| type
const uint16_t kEcEventPayloadNonWilcoCharger[] = {0x0000, 0x0000, 0x0001,
                                                   0x0000, 0x0000, 0x0000};
const uint16_t kEcEventPayloadLowPowerCharger[] = {0x0000, 0x0000, 0x0002,
                                                   0x0000, 0x0000, 0x0000};
const uint16_t kEcEventPayloadBatteryAuth[] = {0x0003, 0x0000, 0x0001,
                                               0x0000, 0x0000, 0x0000};
const uint16_t kEcEventPayloadDockDisplay[] = {0x0008, 0x0200, 0x0000, 0x0000};
const uint16_t kEcEventPayloadDockThunderbolt[] = {0x0008, 0x0000, 0x0000,
                                                   0x0100};
const uint16_t kEcEventPayloadIncompatibleDock[] = {0x0008, 0x0000, 0x0000,
                                                    0x1000};
const uint16_t kEcEventPayloadDockError[] = {0x0008, 0x0000, 0x0000, 0x8000};

// Malformed payloads of |EcEvent::Type::SYSTEM_NOTIFY| type
const uint16_t kEcEventPayloadAcAdapterNoFlags[] = {0x0000, 0x0000, 0x0000,
                                                    0x0000, 0x0000, 0x0000};
const uint16_t kEcEventPayloadChargerNoFlags[] = {0x0003, 0x0000, 0x0000,
                                                  0x0000, 0x0000, 0x0000};
const uint16_t kEcEventPayloadUsbCNoFlags[] = {0x0008, 0x0000, 0x0000, 0x0000};
const uint16_t kEcEventPayloadNonWilcoChargerBadSubType[] = {
    0xffff, 0x0000, 0x0001, 0x0000, 0x0000, 0x0000};

}  // namespace

// Valid EcEvents
const EcEvent kEcEventNonWilcoCharger =
    EcEvent(6, kSystemNotifyType, kEcEventPayloadNonWilcoCharger);
const EcEvent kEcEventLowPowerCharger =
    EcEvent(6, kSystemNotifyType, kEcEventPayloadLowPowerCharger);
const EcEvent kEcEventBatteryAuth =
    EcEvent(6, kSystemNotifyType, kEcEventPayloadBatteryAuth);
const EcEvent kEcEventDockDisplay =
    EcEvent(4, kSystemNotifyType, kEcEventPayloadDockDisplay);
const EcEvent kEcEventDockThunderbolt =
    EcEvent(4, kSystemNotifyType, kEcEventPayloadDockThunderbolt);
const EcEvent kEcEventIncompatibleDock =
    EcEvent(4, kSystemNotifyType, kEcEventPayloadIncompatibleDock);
const EcEvent kEcEventDockError =
    EcEvent(4, kSystemNotifyType, kEcEventPayloadDockError);

// Non |EcEvent::Type::SYSTEM_NOTIFY| type
const EcEvent kEcEventNonSysNotification =
    EcEvent(6, kNonSystemNotifyType, kEcEventPayloadNonWilcoCharger);

// Invalid EcEvents
const EcEvent kEcEventAcAdapterNoFlags =
    EcEvent(6, kSystemNotifyType, kEcEventPayloadAcAdapterNoFlags);
const EcEvent kEcEventChargerNoFlags =
    EcEvent(6, kSystemNotifyType, kEcEventPayloadChargerNoFlags);
const EcEvent kEcEventUsbCNoFlags =
    EcEvent(4, kSystemNotifyType, kEcEventPayloadUsbCNoFlags);
const EcEvent kEcEventNonWilcoChargerBadSubType =
    EcEvent(6, kSystemNotifyType, kEcEventPayloadNonWilcoChargerBadSubType);
const EcEvent kEcEventInvalidPayloadSize =
    EcEvent(8, kNonSystemNotifyType, kEcEventPayloadBatteryAuth);

std::string ConvertDataInWordsToString(const uint16_t* data, uint16_t size) {
  DCHECK_LE(static_cast<int>(size), 6);

  char data_in_bytes[12];
  for (uint16_t i = 0; i < size; i++) {
    data_in_bytes[i * 2] = data[i] & 255;
    data_in_bytes[i * 2 + 1] = data[i] >> 8;
  }
  return std::string(data_in_bytes, size * 2);
}

EcEvent GetEcEventWithReason(EcEvent::Reason reason) {
  switch (reason) {
    case EcEvent::Reason::kNonWilcoCharger:
      return kEcEventNonWilcoCharger;
    case EcEvent::Reason::kLowPowerCharger:
      return kEcEventLowPowerCharger;
    case EcEvent::Reason::kBatteryAuth:
      return kEcEventBatteryAuth;
    case EcEvent::Reason::kDockDisplay:
      return kEcEventDockDisplay;
    case EcEvent::Reason::kDockThunderbolt:
      return kEcEventDockThunderbolt;
    case EcEvent::Reason::kIncompatibleDock:
      return kEcEventIncompatibleDock;
    case EcEvent::Reason::kDockError:
      return kEcEventDockError;
    case EcEvent::Reason::kSysNotification:
      return kEcEventAcAdapterNoFlags;
    case EcEvent::Reason::kNonSysNotification:
      return kEcEventNonSysNotification;
  }
  NOTREACHED() << "Invalid EcEvent::Reason: " << static_cast<int>(reason);
}

}  // namespace diagnostics
