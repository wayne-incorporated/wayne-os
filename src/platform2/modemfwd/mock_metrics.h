// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_MOCK_METRICS_H_
#define MODEMFWD_MOCK_METRICS_H_

#include <gmock/gmock.h>

#include "modemfwd/metrics.h"

namespace modemfwd {

class MockMetrics : public Metrics {
 public:
  MockMetrics() = default;

  MOCK_METHOD(void,
              SendDlcInstallResult,
              (metrics::DlcInstallResult result),
              (override));

  MOCK_METHOD(void,
              SendDlcUninstallResult,
              (metrics::DlcUninstallResult result),
              (override));

  MOCK_METHOD(void,
              SendFwInstallResult,
              (metrics::FwInstallResult result),
              (override));

  MOCK_METHOD(void,
              SendFwUpdateLocation,
              (metrics::FwUpdateLocation location),
              (override));

  MOCK_METHOD(void, StartFwFlashTimer, (), (override));

  MOCK_METHOD(void, StopFwFlashTimer, (), (override));

  MOCK_METHOD(void, SendFwFlashTime, (), (override));

 private:
  MockMetrics(const MockMetrics&) = delete;
  MockMetrics& operator=(const MockMetrics&) = delete;
};

}  // namespace modemfwd

#endif  // MODEMFWD_MOCK_METRICS_H_
