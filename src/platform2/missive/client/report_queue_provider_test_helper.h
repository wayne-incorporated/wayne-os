// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_CLIENT_REPORT_QUEUE_PROVIDER_TEST_HELPER_H_
#define MISSIVE_CLIENT_REPORT_QUEUE_PROVIDER_TEST_HELPER_H_

namespace reporting {
class MockReportQueueProvider;

namespace report_queue_provider_test_helper {
void SetForTesting(MockReportQueueProvider* provider);
}  // namespace report_queue_provider_test_helper

}  // namespace reporting

#endif  // MISSIVE_CLIENT_REPORT_QUEUE_PROVIDER_TEST_HELPER_H_
