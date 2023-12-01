// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_metrics.h"

using ::testing::_;
using ::testing::AnyNumber;

namespace shill {

MockMetrics::MockMetrics() {
  EXPECT_CALL(*this, AddServiceStateTransitionTimer(_, _, _, _))
      .Times(AnyNumber());
  EXPECT_CALL(*this, NotifyServiceStateChanged(_, _)).Times(AnyNumber());
}

MockMetrics::~MockMetrics() = default;

}  // namespace shill
