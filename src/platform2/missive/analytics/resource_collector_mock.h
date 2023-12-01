// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_MOCK_H_
#define MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_MOCK_H_

#include "missive/analytics/resource_collector.h"

#include <ctime>

#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace reporting::analytics {

class ResourceCollectorMock : public ResourceCollector {
 public:
  explicit ResourceCollectorMock(base::TimeDelta interval);
  ~ResourceCollectorMock() override;

  // Collect storage usage.
  MOCK_METHOD(void, Collect, (), (override));
  // Used to detect destructor calls
  MOCK_METHOD(void, Destruct, (), ());
};

}  // namespace reporting::analytics

#endif  // MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_MOCK_H_
