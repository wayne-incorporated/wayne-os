// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_METRICS_H_
#define TYPECD_METRICS_H_

#include <metrics/metrics_library.h>

namespace typecd {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class PartnerTypeMetric {
  kOther = 0,
  kTBTDPAltHub = 1,
  kTBTDPAltPeripheral = 2,
  kTBTHub = 3,
  kTBTPeripheral = 4,
  kUSB4Hub = 5,
  kUSB4Peripheral = 6,
  kDPAltHub = 7,
  kDPAltPeripheral = 8,
  kUSBHub = 9,
  kUSBPeripheral = 10,
  kPDPowerSource = 11,
  kPDSourcingDevice = 12,
  kNonPDPowerSource = 13,
  kPDSink = 14,
  kPDSinkingHost = 15,
  kNonPDSink = 16,
  kPowerBrick = 17,
  kMaxValue = kPowerBrick,
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class CableSpeedMetric {
  kOther = 0,
  kUSB2_0 = 1,
  kUSB3_2Gen1 = 2,
  kUSB3_2USB4Gen2 = 3,
  kUSB3_1Gen1 = 4,
  kUSB3_1Gen1Gen2 = 5,
  kUSB4Gen3 = 6,
  kTBTOnly10G20G = 7,
  kMaxValue = kTBTOnly10G20G,
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class WrongConfigurationMetric {
  kTBTWrongCable = 0,
  kUSB4WrongCable = 1,
  kDPAltWrongCable = 2,
  kSpeedLimitingCable = 3,
  kNone = 4,
  kMaxValue = kNone,
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class PartnerLocationMetric {
  kOther = 0,
  // All available ports are only on one side.
  kUserHasNoChoice = 1,
  // The first partner connects to the port on the left side.
  kLeftFirst = 2,
  // The second partner connects to the port on the left side while the first is
  // also on the same side.
  kLeftSecondSameSideWithFirst = 3,
  // The second partner connects to the port on the left side while the first is
  // on the opposite side.
  kLeftSecondOppositeSideToFirst = 4,
  // The third partner connects to the port on the left side.
  kLeftThirdOrLater = 5,
  // Coldplugged partner connected to the port on the left side.
  // The connection order cannot be determined.
  kLeftColdplugged = 6,
  // The first partner connects to the port on the right side.
  kRightFirst = 7,
  // The second partner connects to the port on the right side while the first
  // is also on the same side.
  kRightSecondSameSideWithFirst = 8,
  // The second partner connects to the port on the right side while the first
  // is on the opposite side.
  kRightSecondOppositeSideToFirst = 9,
  // The third partner connects to the port on the right side.
  kRightThirdOrLater = 10,
  // Coldplugged partner connected to the port on the right side.
  // The connection order cannot be determined.
  kRightColdplugged = 11,
  kMaxValue = kRightColdplugged,
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class PowerSourceLocationMetric {
  kOther = 0,
  // All ports are only on one side.
  kUserHasNoChoice = 1,
  // The first power connection during the session to a port on the left side.
  kLeftFirst = 2,
  // Power source connected to a port on the left side while previously also
  // used a port on the left side for power. (during same session)
  kLeftConstant = 3,
  // Power source connected to a port on the left side while previously used a
  // port on the right side for power. (during same session)
  kLeftSwitched = 4,
  // The first power connection during the session to a port on the right side.
  kRightFirst = 5,
  // Power source connected to a port on the right side while previously also
  // used a port on the right side for power. (during same session)
  kRightConstant = 6,
  // Power source connected to a port on the right side while previously used a
  // port on the left side for power. (during same session)
  kRightSwitched = 7,
  kMaxValue = kRightSwitched,
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class DpSuccessMetric {
  kSuccessHpd = 0,
  kSuccessNoHpd = 1,
  kFail = 2,
  kMaxValue = kFail,
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class DataRoleMetric {
  kOther = 0,
  kDevice = 1,
  kHost = 2,
  kMaxValue = kHost,
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class PowerRoleMetric {
  kOther = 0,
  kSink = 1,
  kSource = 2,
  kMaxValue = kSource,
};

// A class for collecting UMA metrics.
class Metrics {
 public:
  Metrics() = default;
  Metrics(const Metrics&) = delete;
  Metrics& operator=(const Metrics&) = delete;

  ~Metrics() = default;

  void ReportPartnerType(PartnerTypeMetric type);
  void ReportCableSpeed(CableSpeedMetric speed);
  void ReportWrongCableError(WrongConfigurationMetric value);
  void ReportPartnerLocation(PartnerLocationMetric location);
  void ReportPowerSourceLocation(PowerSourceLocationMetric location);
  void ReportDpSuccess(DpSuccessMetric val);

  // Structured metrics
  void ReportBasicPdDeviceInfo(int vid,
                               int pid,
                               int xid,
                               bool supports_pd,
                               bool supports_usb,
                               bool supports_dp,
                               bool supports_tbt,
                               bool supports_usb4,
                               DataRoleMetric data_role,
                               PowerRoleMetric power_role);

 private:
  MetricsLibrary metrics_library_;
};

}  // namespace typecd

#endif  // TYPECD_METRICS_H_
