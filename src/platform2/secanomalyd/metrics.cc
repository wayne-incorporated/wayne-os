// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secanomalyd/metrics.h"

#include <base/logging.h>
#include <base/numerics/safe_conversions.h>

#include <metrics/metrics_library.h>

namespace {

constexpr char kSecurityAnomalyHistogramName[] = "ChromeOS.SecurityAnomaly";
constexpr int kSecurityAnomalyHistogramMax = 50;

constexpr char kWXMountCountHistogramName[] = "ChromeOS.WXMountCount";
// The objective of this histogram is to serve as a baseline for W+X mount
// detection. Any non-zero counts of W+X mounts represent a bypass of Verified
// boot and therefore the difference between 5, 10, or 15 W+X mounts is not
// really that important. This could be a boolean histogram as well, but we will
// benefit from knowing what kind of ballpark number of anomalous mounts we're
// talking about, so a regular histogram with a small number of buckets will
// be slightly more beneficial than a boolean one, without consuming that many
// more resources.
constexpr int kWXMountCountHistogramMinBucket = 0;
constexpr int kWXMountCountHistogramMaxBucket = 20;
constexpr int kWXMountCountHistogramNumBuckets = 20;

// This prefix is used for histograms that show the count of anomalous processes
// on the system. Each subcategory corresponds to a different type of anomaly.
constexpr char kAnomalousProcCountHistogramPrefix[] =
    "ChromeOS.AnomalousProcCount.";
constexpr int kAnomalousProcCountMinBucket = 0;
constexpr int kAnomalousProcCountMaxBucket = 30;
constexpr int kAnomalousProcCountNumBuckets = 30;
// This subcategory of |AnomalousProcCount| shows the number of processes on the
// system that have attempted to execute a memfd.
constexpr char kAttemptedMemfdExec[] = "AttemptedMemfdExec";

constexpr char kLandlockEnabled[] = "ChromeOS.Sandboxing.LandlockEnabled";

constexpr char kAnomalyUploadSuccess[] =
    "ChromeOS.SecurityAnomalyUploadSuccess";

MetricsLibraryInterface* metrics_library = nullptr;

void InitializeMetricsIfNecessary() {
  if (!metrics_library) {
    metrics_library = new MetricsLibrary();
  }
}

}  // namespace

bool SendSecurityAnomalyToUMA(SecurityAnomaly secanomaly) {
  InitializeMetricsIfNecessary();
  return metrics_library->SendEnumToUMA(kSecurityAnomalyHistogramName,
                                        static_cast<int>(secanomaly),
                                        kSecurityAnomalyHistogramMax);
}

bool SendWXMountCountToUMA(size_t wx_mount_count) {
  InitializeMetricsIfNecessary();
  return metrics_library->SendToUMA(
      kWXMountCountHistogramName, base::checked_cast<int>(wx_mount_count),
      kWXMountCountHistogramMinBucket, kWXMountCountHistogramMaxBucket,
      kWXMountCountHistogramNumBuckets);
}

bool SendAttemptedMemfdExecProcCountToUMA(size_t proc_count) {
  InitializeMetricsIfNecessary();
  return metrics_library->SendToUMA(
      std::string(kAnomalousProcCountHistogramPrefix) +
          std::string(kAttemptedMemfdExec),
      base::checked_cast<int>(proc_count), kAnomalousProcCountMinBucket,
      kAnomalousProcCountMaxBucket, kAnomalousProcCountNumBuckets);
}

bool SendLandlockStatusToUMA(bool enabled) {
  InitializeMetricsIfNecessary();
  return metrics_library->SendBoolToUMA(kLandlockEnabled, enabled);
}

bool SendAnomalyUploadResultToUMA(bool success) {
  InitializeMetricsIfNecessary();
  return metrics_library->SendBoolToUMA(kAnomalyUploadSuccess, success);
}
