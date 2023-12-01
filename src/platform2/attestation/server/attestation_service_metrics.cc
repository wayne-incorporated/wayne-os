// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/attestation_service_metrics.h"

namespace attestation {

namespace {

constexpr char kAttestationStatusHistogramPrefix[] = "Hwsec.Attestation.Status";
constexpr char kAttestationPrepareDurationHistogram[] =
    "Hwsec.Attestation.PrepareDuration";

}  // namespace

void AttestationServiceMetrics::ReportAttestationOpsStatus(
    const std::string& operation, AttestationOpsStatus status) {
  if (!metrics_library_) {
    return;
  }

  const std::string histogram =
      std::string(kAttestationStatusHistogramPrefix) + "." + operation;
  metrics_library_->SendEnumToUMA(
      histogram, static_cast<int>(status),
      static_cast<int>(AttestationOpsStatus::kMaxValue));
}

void AttestationServiceMetrics::ReportAttestationPrepareDuration(
    base::TimeDelta delta) {
  if (!metrics_library_) {
    return;
  }

  const int min_duration = 100;
  const int max_duration = 100'000;
  const int sample = static_cast<int>(delta.InMilliseconds());
  const int nBuckets = 50;
  metrics_library_->SendToUMA(kAttestationPrepareDurationHistogram, sample,
                              min_duration, max_duration, nBuckets);
}

}  // namespace attestation
