// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "oobe_config/metrics/metrics_uma.h"

namespace {

// UMA metric names
constexpr char kOobeRestoreResultMetricName[] = "Rollback.OobeRestoreResult";
constexpr char kRollbackSaveResultMetricName[] = "Rollback.RollbackSaveResult";

}  // namespace

namespace oobe_config {

MetricsUMA::MetricsUMA() {}

void MetricsUMA::RecordRestoreResult(OobeRestoreResult result) {
  metrics_library_.SendEnumToUMA(kOobeRestoreResultMetricName,
                                 static_cast<int>(result),
                                 static_cast<int>(OobeRestoreResult::kCount));
}

void MetricsUMA::RecordSaveResult(RollbackSaveResult result) {
  metrics_library_.SendEnumToUMA(kRollbackSaveResultMetricName,
                                 static_cast<int>(result),
                                 static_cast<int>(RollbackSaveResult::kCount));
}

}  // namespace oobe_config
