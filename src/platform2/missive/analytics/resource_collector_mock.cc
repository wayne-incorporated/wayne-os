// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/resource_collector_mock.h"

#include <base/time/time.h>

namespace reporting::analytics {

ResourceCollectorMock::ResourceCollectorMock(base::TimeDelta interval)
    : ResourceCollector(interval) {}

ResourceCollectorMock::~ResourceCollectorMock() {
  Destruct();
  StopTimer();
}

}  // namespace reporting::analytics
