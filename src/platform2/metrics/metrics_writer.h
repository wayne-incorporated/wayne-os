// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_METRICS_WRITER_H_
#define METRICS_METRICS_WRITER_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/memory/ref_counted.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>

#include "metrics/serialization/metric_sample.h"

constexpr char kUMAEventsPath[] = "/var/lib/metrics/uma-events";

// Logs UMA metrics to metrics file.
class MetricsWriter : public base::RefCountedThreadSafe<MetricsWriter> {
 public:
  MetricsWriter() = default;
  MetricsWriter(const MetricsWriter&) = delete;
  MetricsWriter& operator=(const MetricsWriter&) = delete;

  // Write the metrics to the file.
  virtual bool WriteMetrics(std::vector<metrics::MetricSample> samples) = 0;
  // Change the output file path.
  virtual bool SetOutputFile(const std::string& output_file) = 0;

 protected:
  friend class base::RefCountedThreadSafe<MetricsWriter>;
  virtual ~MetricsWriter() = default;
};

// Write UMA metrics using `metrics::SerializationUtils::WriteMetricsToFile` on
// the caller thread.
//
// It acquires a file lock to write logs so that this may block the thread for
// non-trivial time.
//
// This class is not thread-safe.
class SynchronousMetricsWriter : public MetricsWriter {
 public:
  explicit SynchronousMetricsWriter(
      base::FilePath uma_events_file = base::FilePath(kUMAEventsPath));

  bool WriteMetrics(std::vector<metrics::MetricSample> samples) override;
  bool SetOutputFile(const std::string& output_file) override;

 private:
  friend class CMetricsLibraryTest;
  friend class MetricsLibraryTest;

  base::FilePath uma_events_file_;
};

// Write UMA metrics using `metrics::SerializationUtils::WriteMetricsToFile` on
// `base::SequencedTaskRunner` sequentially.
//
// The destructor waits until all metrics requested are written into the file by
// default. You can skip the waiting on the destructor by passing false
// `wait_on_destructor` at constructor and manually waits for all metrics
// flushed by `WaitUntilFlushed()`.
//
// This class is thread-safe.
class AsynchronousMetricsWriter : public MetricsWriter {
 public:
  // Creates AsynchronousMetricsWriter.
  //
  // `task_runner` should be passed to specify on which thread will the writer
  // be executed. The thread may be blocked for a long time by this writer.
  //
  // If you explicitly set false to `wait_on_destructor`, you should call
  // `WaitUntilFlushed()` after all write are requested. Otherwise enqueued
  // metrics can be lost.
  //
  // `uma_events_file` specifies the metrics output file path.
  explicit AsynchronousMetricsWriter(
      scoped_refptr<base::SequencedTaskRunner> task_runner,
      bool wait_on_destructor = true,
      base::FilePath uma_events_file = base::FilePath(kUMAEventsPath));

  // Dispatch a request to the background thread to log the metrics to the file.
  // Returns false if it fails to dispatch.
  bool WriteMetrics(std::vector<metrics::MetricSample> samples) override;
  // Change the output file path. Metrics requested before this call are
  // written into the previous output file.
  bool SetOutputFile(const std::string& output_file) override;
  // Wait until all metrics requested before this call are written into the
  // output file.
  void WaitUntilFlushed();

 private:
  ~AsynchronousMetricsWriter() override;

  void WriteMetricsOnThread(std::vector<metrics::MetricSample> samples);
  void SetOutputFileOnThread(base::FilePath output_file);

  scoped_refptr<base::SequencedTaskRunner> task_runner_;
  const bool wait_on_destructor_;
  base::FilePath uma_events_file_;
  base::WeakPtrFactory<AsynchronousMetricsWriter> weak_ptr_factory_{this};
};

#endif  // METRICS_METRICS_WRITER_H_
