// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_MOCK_METRICS_H_
#define DLCSERVICE_MOCK_METRICS_H_

#include <gmock/gmock.h>

#include "dlcservice/metrics.h"

namespace dlcservice {

class MockMetrics : public Metrics {
 public:
  MockMetrics() = default;

  MOCK_METHOD(void,
              SendInstallResult,
              (metrics::InstallResult result),
              (override));

  MOCK_METHOD(void,
              SendUninstallResult,
              (metrics::UninstallResult result),
              (override));

 private:
  MockMetrics(const MockMetrics&) = delete;
  MockMetrics& operator=(const MockMetrics&) = delete;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_MOCK_METRICS_H_
