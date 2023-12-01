// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/client/report_queue.h"

#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/json/json_writer.h>
#include <base/memory/ptr_util.h>
#include <base/sequence_checker.h>
#include <base/strings/strcat.h>
#include <base/time/time.h>
#include <base/values.h>

#include "missive/analytics/metrics.h"
#include "missive/proto/record.pb.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/util/status.h"
#include "missive/util/status_macros.h"
#include "missive/util/statusor.h"

namespace reporting {

namespace {

StatusOr<std::string> ValueToJson(base::Value record) {
  std::string json_record;
  if (!base::JSONWriter::Write(record, &json_record)) {
    return Status(error::INVALID_ARGUMENT,
                  "Provided record was not convertable to a std::string");
  }
  return json_record;
}

StatusOr<std::string> ProtoToString(
    std::unique_ptr<const google::protobuf::MessageLite> record) {
  std::string protobuf_record;
  if (!record->SerializeToString(&protobuf_record)) {
    return Status(error::INVALID_ARGUMENT,
                  "Unabled to serialize record to string. Most likely due to "
                  "unset required fields.");
  }
  return protobuf_record;
}

void EnqueueResponded(ReportQueue::EnqueueCallback callback, Status status) {
  const auto res = analytics::Metrics::SendEnumToUMA(
      /*name=*/ReportQueue::kEnqueueMetricsName, status.code(),
      error::Code::MAX_VALUE);
  LOG_IF(ERROR, !res) << "SendEnumToUMA failure, "
                      << ReportQueue::kEnqueueMetricsName << " "
                      << static_cast<int>(status.code());
  std::move(callback).Run(status);
}
}  // namespace

ReportQueue::~ReportQueue() = default;

void ReportQueue::Enqueue(std::string record,
                          Priority priority,
                          ReportQueue::EnqueueCallback callback) const {
  AddProducedRecord(base::BindOnce(
                        [](std::string record) -> StatusOr<std::string> {
                          return std::move(record);
                        },
                        std::move(record)),
                    priority,
                    base::BindOnce(&EnqueueResponded, std::move(callback)));
}

void ReportQueue::Enqueue(base::Value record,
                          Priority priority,
                          ReportQueue::EnqueueCallback callback) const {
  AddProducedRecord(base::BindOnce(&ValueToJson, std::move(record)), priority,
                    base::BindOnce(&EnqueueResponded, std::move(callback)));
}

void ReportQueue::Enqueue(
    std::unique_ptr<const google::protobuf::MessageLite> record,
    Priority priority,
    ReportQueue::EnqueueCallback callback) const {
  AddProducedRecord(base::BindOnce(&ProtoToString, std::move(record)), priority,
                    base::BindOnce(&EnqueueResponded, std::move(callback)));
}

}  // namespace reporting
