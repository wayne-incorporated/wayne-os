// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_METRICS_CONSTANTS_H_
#define POWER_MANAGER_COMMON_METRICS_CONSTANTS_H_

#include <base/time/time.h>

namespace power_manager::metrics {

// Suffixes added to certain metric names when on different power sources.
extern const char kAcSuffix[];
extern const char kBatterySuffix[];

// Suffixes added to certain metric names for different privacy screen states.
extern const char kPrivacyScreenDisabled[];
extern const char kPrivacyScreenEnabled[];

// Default max for percent-based metrics. Percents are reported as enums instead
// of regular exponential histograms so they'll get a linear scale.
extern const int kMaxPercent;

// Default number of buckets to use for numeric histogram metrics.
extern const int kDefaultBuckets;

// Default number of buckets to use for numeric histogram metrics covering power
// discharge.
extern const int kDefaultDischargeBuckets;

extern const char kSuspendAttemptsBeforeSuccessName[];
extern const char kHibernateAttemptsBeforeSuccessName[];
extern const char kSuspendAttemptsBeforeCancelName[];
extern const char kHibernateAttemptsBeforeCancelName[];
extern const int kSuspendAttemptsMin;
extern const int kSuspendAttemptsMax;
extern const int kSuspendAttemptsBuckets;

extern const char kSuspendDelayName[];
extern const int kSuspendDelayMin;
extern const int kSuspendDelayMax;

extern const char kShutdownReasonName[];
extern const int kShutdownReasonMax;

extern const char kBacklightLevelName[];
extern const char kKeyboardBacklightLevelName[];
extern const base::TimeDelta kBacklightLevelInterval;

extern const char kIdleAfterScreenOffName[];
extern const int kIdleAfterScreenOffMin;
extern const int kIdleAfterScreenOffMax;

extern const char kIdleName[];
extern const int kIdleMin;
extern const int kIdleMax;

extern const char kIdleAfterDimName[];
extern const int kIdleAfterDimMin;
extern const int kIdleAfterDimMax;

extern const char kBatteryChargeHealthName[];
extern const int kBatteryChargeHealthMax;

extern const char kBatteryCapacityActualSuffix[];
extern const char kBatteryCapacityDesignSuffix[];

extern const char kBatteryCapacityName[];
extern const int kBatteryCapacityMin;
extern const int kBatteryCapacityMax;

extern const char kBatteryDischargeRateName[];
extern const int kBatteryDischargeRateMin;
extern const int kBatteryDischargeRateMax;
extern const base::TimeDelta kBatteryDischargeRateInterval;

extern const char kBatteryDischargeRateWhileSuspendedName[];
extern const char kBatteryDischargeRateWhileHibernatedName[];
extern const int kBatteryDischargeRateWhileSuspendedMin;
extern const int kBatteryDischargeRateWhileSuspendedMax;
extern const base::TimeDelta kBatteryDischargeRateWhileSuspendedMinSuspend;

extern const char kBatteryLifeName[];
extern const int kBatteryLifeMin;
extern const int kBatteryLifeMax;

extern const char kBatteryLifeWhileSuspendedName[];
extern const int kBatteryLifeWhileSuspendedMin;
extern const int kBatteryLifeWhileSuspendedMax;

extern const char kBatteryRemainingWhenChargeStartsName[];
extern const char kBatteryRemainingAtEndOfSessionName[];
extern const char kBatteryRemainingAtStartOfSessionName[];
extern const char kBatteryRemainingAtBootName[];

extern const char kAdaptiveChargingMinutesDeltaName[];
extern const char kAdaptiveChargingDelayDeltaName[];
extern const char kAdaptiveChargingMinutesFullOnACName[];

extern const char kAdaptiveChargingStateActiveSuffix[];
extern const char kAdaptiveChargingStateHeuristicDisabledSuffix[];
extern const char kAdaptiveChargingStateUserCanceledSuffix[];
extern const char kAdaptiveChargingStateUserDisabledSuffix[];
extern const char kAdaptiveChargingStateShutdownSuffix[];
extern const char kAdaptiveChargingStateNotSupportedSuffix[];
extern const char kAdaptiveChargingLateSuffix[];
extern const char kAdaptiveChargingEarlySuffix[];
extern const char kAdaptiveChargingTypeNormalChargingSuffix[];
extern const char kAdaptiveChargingTypeSlowChargingSuffix[];
extern const char kAdaptiveChargingTypeMixedChargingSuffix[];
extern const int kAdaptiveChargingDeltaMin;
extern const int kAdaptiveChargingDeltaMax;

extern const char kAdaptiveChargingBatteryPercentageOnUnplugName[];

extern const char kAdaptiveChargingMinutesToFullName[];
extern const int kAdaptiveChargingMinutesToFullMin;
extern const int kAdaptiveChargingMinutesToFullMax;

extern const int kAdaptiveChargingMinutesBuckets;
extern const char kAdaptiveChargingMinutesDelayName[];
extern const char kAdaptiveChargingMinutesAvailableName[];
extern const int kAdaptiveChargingMinutesMin;
extern const int kAdaptiveChargingMinutesMax;

extern const char kNumberOfAlsAdjustmentsPerSessionName[];
extern const int kNumberOfAlsAdjustmentsPerSessionMin;
extern const int kNumberOfAlsAdjustmentsPerSessionMax;

extern const char kUserBrightnessAdjustmentsPerSessionName[];
extern const int kUserBrightnessAdjustmentsPerSessionMin;
extern const int kUserBrightnessAdjustmentsPerSessionMax;

extern const char kLengthOfSessionName[];
extern const int kLengthOfSessionMin;
extern const int kLengthOfSessionMax;

extern const char kNumOfSessionsPerChargeName[];
extern const int kNumOfSessionsPerChargeMin;
extern const int kNumOfSessionsPerChargeMax;

extern const char kPowerButtonDownTimeName[];
extern const int kPowerButtonDownTimeMin;
extern const int kPowerButtonDownTimeMax;

extern const char kPowerButtonAcknowledgmentDelayName[];
extern const int kPowerButtonAcknowledgmentDelayMin;
extern const int kPowerButtonAcknowledgmentDelayMax;

extern const char kBatteryInfoSampleName[];

extern const char kPowerSupplyMaxVoltageName[];
extern const int kPowerSupplyMaxVoltageMax;

extern const char kPowerSupplyMaxPowerName[];
extern const int kPowerSupplyMaxPowerMax;

extern const char kPowerSupplyTypeName[];

extern const char kConnectedChargingPortsName[];

extern const char kExternalBrightnessRequestResultName[];
extern const char kExternalBrightnessReadResultName[];
extern const char kExternalBrightnessWriteResultName[];
extern const char kExternalDisplayOpenResultName[];
extern const int kExternalDisplayResultMax;

extern const char kDarkResumeWakeupsPerHourName[];
extern const int kDarkResumeWakeupsPerHourMin;
extern const int kDarkResumeWakeupsPerHourMax;

extern const char kDarkResumeWakeDurationMsName[];
extern const int kDarkResumeWakeDurationMsMin;
extern const int kDarkResumeWakeDurationMsMax;

extern const char kS0ixResidencyRateName[];
extern const char kPC10RuntimeResidencyRateName[];
extern const char kPC10inS0ixRuntimeResidencyRateName[];

extern const char kDimEvent[];
extern const int kHpsEventDurationMin;
extern const int kHpsEventDurationMax;
extern const char kQuickDimDurationBeforeRevertedByHpsSec[];
extern const char kQuickDimDurationBeforeRevertedByUserSec[];
extern const char kStandardDimDurationBeforeRevertedByUserSec[];
extern const char kStandardDimDeferredByHpsSec[];

extern const char kLockEvent[];

extern const char kAmbientLightOnResumeName[];
extern const int kAmbientLightOnResumeMin;
extern const int kAmbientLightOnResumeMax;

extern const char kPeripheralReadLatencyMs[];
extern const char kPeripheralReadErrorLatencyMs[];
extern const int kPeripheralReadLatencyMsMin;
extern const int kPeripheralReadLatencyMsMax;

// Values for kBatteryInfoSampleName.
enum class BatteryInfoSampleResult {
  READ,
  GOOD,
  BAD,
  MAX,
};

// Values for kPowerSupplyTypeName. Do not renumber.
enum class PowerSupplyType {
  OTHER = 0,
  MAINS = 1,
  USB = 2,
  USB_ACA = 3,
  USB_CDP = 4,
  USB_DCP = 5,
  USB_C = 6,
  USB_PD = 7,
  USB_PD_DRP = 8,
  BRICK_ID = 9,
  // Keep this last and increment it if a new value is inserted.
  MAX = 10,
};

// Values for kConnectedChargingPortsName. Do not renumber.
enum class ConnectedChargingPorts {
  NONE = 0,
  PORT1 = 1,
  PORT2 = 2,
  PORT1_PORT2 = 3,
  TOO_MANY_PORTS = 4,
  // Keep this last and increment it if a new value is inserted.
  MAX = 5,
};

// Values for dim/undim event in StateController.
enum class DimEvent {
  STANDARD_DIM,
  QUICK_DIM,
  QUICK_DIM_TRANSITIONED_TO_STANDARD_DIM,
  QUICK_DIM_REVERTED_BY_HPS,
  QUICK_DIM_REVERTED_BY_USER,
  MAX
};

// Values for lock event in StateController.
enum class LockEvent { STANDARD_LOCK, QUICK_LOCK, MAX };

// Values for unplug metrics for AdaptiveChargingController.
enum class AdaptiveChargingState {
  ACTIVE,
  SLOWCHARGE,
  INACTIVE,
  HEURISTIC_DISABLED,
  USER_CANCELED,
  USER_DISABLED,
  SHUTDOWN,
  NOT_SUPPORTED,
  MAX
};

}  // namespace power_manager::metrics

#endif  // POWER_MANAGER_COMMON_METRICS_CONSTANTS_H_
