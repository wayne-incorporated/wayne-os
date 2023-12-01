// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/metrics_writer.h"

#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/location.h>
#include <base/synchronization/waitable_event.h>

#include "metrics/serialization/serialization_utils.h"

SynchronousMetricsWriter::SynchronousMetricsWriter(
    base::FilePath uma_events_file)
    : uma_events_file_(std::move(uma_events_file)) {}

bool SynchronousMetricsWriter::WriteMetrics(
    std::vector<metrics::MetricSample> samples) {
  return metrics::SerializationUtils::WriteMetricsToFile(
      samples, uma_events_file_.value());
}

bool SynchronousMetricsWriter::SetOutputFile(const std::string& output_file) {
  uma_events_file_ = base::FilePath(output_file);
  return true;
}

AsynchronousMetricsWriter::AsynchronousMetricsWriter(
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    bool wait_on_destructor,
    base::FilePath uma_events_file)
    : task_runner_(std::move(task_runner)),
      wait_on_destructor_(wait_on_destructor),
      uma_events_file_(std::move(uma_events_file)) {}

AsynchronousMetricsWriter::~AsynchronousMetricsWriter() {
  if (wait_on_destructor_) {
    WaitUntilFlushed();
  }
}

bool AsynchronousMetricsWriter::WriteMetrics(
    std::vector<metrics::MetricSample> samples) {
  return task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&AsynchronousMetricsWriter::WriteMetricsOnThread,
                     weak_ptr_factory_.GetWeakPtr(), std::move(samples)));
}

bool AsynchronousMetricsWriter::SetOutputFile(const std::string& output_file) {
  return task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&AsynchronousMetricsWriter::SetOutputFileOnThread,
                     weak_ptr_factory_.GetWeakPtr(),
                     base::FilePath(output_file)));
}

void AsynchronousMetricsWriter::WaitUntilFlushed() {
  // If this is called on the SequencedTaskRunner thread, this will deadlock.
  CHECK(!task_runner_->RunsTasksInCurrentSequence());

  base::WaitableEvent flushed;
  CHECK(task_runner_->PostNonNestableTask(
      FROM_HERE,
      base::BindOnce(
          [](base::WaitableEvent& flushed_ref) { flushed_ref.Signal(); },
          std::ref(flushed))));
  flushed.Wait();
}

void AsynchronousMetricsWriter::WriteMetricsOnThread(
    std::vector<metrics::MetricSample> samples) {
  if (!metrics::SerializationUtils::WriteMetricsToFile(
          samples, uma_events_file_.value())) {
    LOG(ERROR) << "Failed to write metrics";
  }
}

void AsynchronousMetricsWriter::SetOutputFileOnThread(
    base::FilePath output_file) {
  uma_events_file_ = std::move(output_file);
}
