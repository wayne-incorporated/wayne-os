// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/client/report_queue_provider_test_helper.h"

#include "missive/analytics/metrics_test_util.h"
#include "missive/client/mock_report_queue_provider.h"
#include "missive/client/report_queue_nonchrome_provider.h"
#include "missive/client/report_queue_provider.h"

namespace reporting::report_queue_provider_test_helper {

void SetForTesting(MockReportQueueProvider* provider) {
  NonChromeReportQueueProvider::GetInstance()->SetForTesting(provider);
}

}  // namespace reporting::report_queue_provider_test_helper
