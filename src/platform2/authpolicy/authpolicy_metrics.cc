// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/authpolicy_metrics.h"

#include <algorithm>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>

namespace authpolicy {

namespace {

// Prefix for all metric names.
const char* kMetricNamePrefix = "AuthPolicy.";

std::string MakeFullName(const char* metric_name) {
  return std::string(kMetricNamePrefix) + metric_name;
}

// UMA histogram parameters. The bucket layout is exponential with implicit
// underflow and overflow buckets for [0, min_sample - 1) and [max_sample, inf),
// respectively, counting towards |num_buckets|. See MetricsLibrary::SendToUMA
// and base::Histogram for more details. |enum_value| is a safety parameter to
// make sure that the array index matches the enum value.
struct HistogramParams {
  int enum_value;
  const char* metric_name;
  int min_sample;
  int max_sample;
  int num_buckets;
};

// |max_sample| is the max time in milliseconds. Keep in sync with TimerType!
constexpr HistogramParams kTimerHistogramParams[TIMER_COUNT] = {
    {TIMER_NET_ADS_GPO_LIST, "TimeToRunNetAdsGpo", 1, 120000, 50},
    {TIMER_NET_ADS_INFO, "TimeToRunNetAdsInfo", 1, 120000, 50},
    {TIMER_NET_ADS_JOIN, "TimeToRunNetAdsJoin", 1, 120000, 50},
    {TIMER_NET_ADS_SEARCH, "TimeToRunNetAdsSearch", 1, 120000, 50},
    {TIMER_NET_ADS_WORKGROUP, "TimeToRunNetAdsWorkgroup", 1, 120000, 50},
    {TIMER_KINIT, "TimeToRunKinit", 1, 120000, 50},
    {TIMER_KLIST, "TimeToRunKlist", 1, 120000, 50},
    {TIMER_KPASSWD, "TimeToRunKpasswd", 1, 120000, 50},
    {TIMER_SMBCLIENT, "TimeToRunSmbclient", 1, 120000, 50},
    {TIMER_AUTHENTICATE_USER, "TimeToAuthenticateUser", 1, 600000, 50},
    {TIMER_GET_USER_STATUS, "TimeToGetUserStatus", 1, 600000, 50},
    {TIMER_GET_USER_KERBEROS_FILES, "TimeToGetUserKerberosFiles", 1, 10000, 50},
    {TIMER_JOIN_AD_DOMAIN, "TimeToJoinADDomain", 1, 600000, 50},
    {TIMER_REFRESH_USER_POLICY, "TimeToRefreshUserPolicy", 1, 600000, 50},
    {TIMER_REFRESH_DEVICE_POLICY, "TimeToRefreshDevicePolicy", 1, 600000, 50},
};

// UMA histogram parameters. The |max_sample| for the *_TRY_COUNT stats to
// (max_tries - 1), so that the overflow bucket captures everything that failed
// too many times. Keep in sync with MetricType!
constexpr HistogramParams kMetricHistogramParams[METRIC_COUNT] = {
    {METRIC_KINIT_FAILED_TRY_COUNT, "FailedTriesOfKinit", 1, 59, 30},
    {METRIC_SMBCLIENT_FAILED_TRY_COUNT, "FailedTriesOfSmbClient", 1, 4, 5},
    {METRIC_DOWNLOAD_GPO_COUNT, "NumGposToDownload", 1, 1000, 50},
};

// Enum metric name plus a parameter to make sure array indices match enum
// values, see HistogramParams.
struct EnumMetricParams {
  int enum_value;
  const char* metric_name;
};

// Keep in sync with ErrorMetricType!
constexpr EnumMetricParams kErrorMetricParams[ERROR_OF_COUNT] = {
    {ERROR_OF_AUTHENTICATE_USER, "ErrorTypeOfAuthenticateUser"},
    {ERROR_OF_GET_USER_STATUS, "ErrorTypeOfGetUserStatus"},
    {ERROR_OF_GET_USER_KERBEROS_FILES, "ErrorTypeOfGetUserKerberosFiles"},
    {ERROR_OF_JOIN_AD_DOMAIN, "ErrorTypeOfJoinADDomain"},
    {ERROR_OF_REFRESH_USER_POLICY, "ErrorTypeOfRefreshUserPolicy"},
    {ERROR_OF_REFRESH_DEVICE_POLICY, "ErrorTypeOfRefreshDevicePolicy"},
    {ERROR_OF_AUTO_TGT_RENEWAL, "ErrorTypeOfAutoTgtRenewal"},
    {ERROR_OF_AUTO_MACHINE_PASSWORD_CHANGE,
     "ErrorTypeOfAutoMachinePasswordChange"},
};

// Keep in sync with EncryptionMetricType!
constexpr EnumMetricParams kEncryptionMetricParams[ENC_METRIC_COUNT] = {
    {ENC_TYPES_OF_AUTHENTICATE_USER,
     "KerberosEncryptionTypes.AuthenticateUser"},
    {ENC_TYPES_OF_JOIN_AD_DOMAIN, "KerberosEncryptionTypes.JoinADDomain"},
};

}  // namespace

ScopedTimerReporter::ScopedTimerReporter(TimerType timer_type)
    : ScopedTimerReporter(CheckedTimerType(timer_type)) {}

ScopedTimerReporter::ScopedTimerReporter(CheckedTimerType timer_type)
    : timer_(MakeFullName(kTimerHistogramParams[timer_type.value_].metric_name),
             kTimerHistogramParams[timer_type.value_].min_sample,
             kTimerHistogramParams[timer_type.value_].max_sample,
             kTimerHistogramParams[timer_type.value_].num_buckets) {
  timer_.Start();
}

ScopedTimerReporter::~ScopedTimerReporter() {
  const bool success = (timer_.Stop() && timer_.ReportMilliseconds());
  if (!success)
    LOG(WARNING) << "Timer " << timer_.histogram_name() << " failed to report.";
}

ScopedTimerReporter::CheckedTimerType::CheckedTimerType(TimerType value)
    : value_(std::min(static_cast<TimerType>(TIMER_COUNT - 1),
                      std::max(static_cast<TimerType>(0), value))) {
  DCHECK(value >= 0 && value < TIMER_COUNT);
}

// Verifies that the array order in the k*Params matches the enum_value.
template <typename T, const T* params, int n>
void CheckArrayOrder() {
  static_assert(params[n].enum_value == n, "Bad array order");
  CheckArrayOrder<T, params, n + 1>();
}
template <>
void CheckArrayOrder<HistogramParams, kTimerHistogramParams, TIMER_COUNT>() {}
template <>
void CheckArrayOrder<HistogramParams, kMetricHistogramParams, METRIC_COUNT>() {}
template <>
void CheckArrayOrder<EnumMetricParams, kErrorMetricParams, ERROR_OF_COUNT>() {}
template <>
void CheckArrayOrder<EnumMetricParams,
                     kEncryptionMetricParams,
                     ENC_METRIC_COUNT>() {}

AuthPolicyMetrics::AuthPolicyMetrics() {
  CheckArrayOrder<HistogramParams, kTimerHistogramParams, 0>();
  CheckArrayOrder<HistogramParams, kMetricHistogramParams, 0>();
  CheckArrayOrder<EnumMetricParams, kErrorMetricParams, 0>();
  CheckArrayOrder<EnumMetricParams, kEncryptionMetricParams, 0>();

  chromeos_metrics::TimerReporter::set_metrics_lib(&metrics_);
}

AuthPolicyMetrics::~AuthPolicyMetrics() {
  chromeos_metrics::TimerReporter::set_metrics_lib(nullptr);
}

void AuthPolicyMetrics::Report(MetricType metric_type, int sample) {
  DCHECK(metric_type >= 0 && metric_type < METRIC_COUNT);
  metrics_.SendToUMA(
      MakeFullName(kMetricHistogramParams[metric_type].metric_name), sample,
      kMetricHistogramParams[metric_type].min_sample,
      kMetricHistogramParams[metric_type].max_sample,
      kMetricHistogramParams[metric_type].num_buckets);
}

void AuthPolicyMetrics::ReportError(ErrorMetricType metric_type,
                                    ErrorType error) {
  DCHECK(metric_type >= 0 && metric_type < ERROR_OF_COUNT);
  metrics_.SendEnumToUMA(
      MakeFullName(kErrorMetricParams[metric_type].metric_name),
      static_cast<int>(error), static_cast<int>(ERROR_COUNT));
}

void AuthPolicyMetrics::ReportEncryptionType(
    EncryptionMetricType metric_type,
    KerberosEncryptionTypes encryption_types) {
  DCHECK(metric_type >= 0 && metric_type < ENC_METRIC_COUNT);
  metrics_.SendEnumToUMA(
      MakeFullName(kEncryptionMetricParams[metric_type].metric_name),
      static_cast<int>(encryption_types), static_cast<int>(ENC_TYPES_COUNT));
}

}  // namespace authpolicy
