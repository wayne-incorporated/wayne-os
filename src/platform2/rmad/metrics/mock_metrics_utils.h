// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_METRICS_MOCK_METRICS_UTILS_H_
#define RMAD_METRICS_MOCK_METRICS_UTILS_H_

#include "rmad/metrics/metrics_utils.h"

#include <base/memory/scoped_refptr.h>
#include <gmock/gmock.h>

#include "rmad/utils/json_store.h"

namespace rmad {

class MockMetricsUtils : public MetricsUtils {
 public:
  MockMetricsUtils() = default;
  ~MockMetricsUtils() override = default;

  MOCK_METHOD(bool, RecordAll, (scoped_refptr<JsonStore>), (override));
  MOCK_METHOD(bool,
              RecordShimlessRmaReport,
              (scoped_refptr<JsonStore>),
              (override));
  MOCK_METHOD(bool,
              RecordReplacedComponents,
              (scoped_refptr<JsonStore>),
              (override));
  MOCK_METHOD(bool,
              RecordOccurredErrors,
              (scoped_refptr<JsonStore>),
              (override));
  MOCK_METHOD(bool,
              RecordAdditionalActivities,
              (scoped_refptr<JsonStore>),
              (override));
  MOCK_METHOD(bool,
              RecordShimlessRmaStateReport,
              (scoped_refptr<JsonStore>),
              (override));
};

}  // namespace rmad

#endif  // RMAD_METRICS_MOCK_METRICS_UTILS_H_
