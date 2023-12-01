// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OOBE_CONFIG_METRICS_METRICS_UMA_H_
#define OOBE_CONFIG_METRICS_METRICS_UMA_H_

#include <metrics/metrics_library.h>

namespace oobe_config {

class MetricsUMA {
 public:
  enum class OobeRestoreResult {
    kSuccess = 0,
    kStage1Failure = 1,
    kStage2Failure = 2,
    kStage3Failure = 3,
    kCount,
  };

  enum class RollbackSaveResult {
    kSuccess = 0,
    kStage1Failure = 1,
    kStage2Failure = 2,
    kCount,
  };

  MetricsUMA();
  MetricsUMA(const MetricsUMA&) = delete;
  MetricsUMA& operator=(const MetricsUMA&) = delete;

  void RecordRestoreResult(OobeRestoreResult result);

  void RecordSaveResult(RollbackSaveResult result);

 private:
  MetricsLibrary metrics_library_;
};

}  // namespace oobe_config

#endif  // OOBE_CONFIG_METRICS_METRICS_UMA_H_
