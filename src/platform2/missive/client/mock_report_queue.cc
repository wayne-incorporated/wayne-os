// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/client/mock_report_queue.h"

#include <memory>
#include <utility>

#include <gmock/gmock.h>

using ::testing::Invoke;

namespace reporting {

MockReportQueueStrict::MockReportQueueStrict() {
  // Default action makes a synchronous call to record_producer and passes the
  // result over to plain-text mock AddRecord. Can be overridden, if necessary.
  ON_CALL(*this, AddProducedRecord)
      .WillByDefault(
          Invoke(this, &MockReportQueueStrict::ForwardProducedRecord));
}

MockReportQueueStrict::~MockReportQueueStrict() = default;

void MockReportQueueStrict::ForwardProducedRecord(
    RecordProducer record_producer,
    Priority priority,
    EnqueueCallback callback) {
  auto record_result = std::move(record_producer).Run();
  if (!record_result.ok()) {
    std::move(callback).Run(record_result.status());
    return;
  }
  AddRecord(std::move(record_result.ValueOrDie()), priority,
            std::move(callback));
}
}  // namespace reporting
