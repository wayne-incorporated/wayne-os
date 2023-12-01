// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc_setup_metrics.h"  // NOLINT - TODO(b/32971714): fix it properly.

#include <utility>

#include <metrics/metrics_library.h>

namespace arc {

namespace {

// The string value need to be the same as in Chromiums's
// src/tools/histogram.xml
constexpr char kSdkVersionUpgradeType[] = "Arc.SdkVersionUpgradeType";

}  // namespace

ArcSetupMetrics::ArcSetupMetrics()
    : metrics_library_(std::make_unique<MetricsLibrary>()) {}

bool ArcSetupMetrics::SendSdkVersionUpgradeType(
    ArcSdkVersionUpgradeType upgrade_type) {
  return metrics_library_->SendEnumToUMA(
      kSdkVersionUpgradeType, static_cast<int>(upgrade_type),
      static_cast<int>(ArcSdkVersionUpgradeType::COUNT));
}

void ArcSetupMetrics::SetMetricsLibraryForTesting(
    std::unique_ptr<MetricsLibraryInterface> metrics_library) {
  metrics_library_ = std::move(metrics_library);
}

}  // namespace arc
