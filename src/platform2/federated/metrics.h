// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_METRICS_H_
#define FEDERATED_METRICS_H_

#include <memory>
#include <string>

#include <base/no_destructor.h>
#include <metrics/metrics_library.h>

// Utilities for logging Federated daemon status to UMA.
namespace federated {

enum class ServiceEvent {
  kLibraryLoadingSuccess = 0,
  kDlcAlreadyInstalled = 1,  // When fcp library dlc is already installed.
  kDlcInstallTriggered = 2,  // When triggering the dlc service to install fcp.
  kDlcNewlyInstalled = 3,    // When the dlc is installed.
  kDlcKnownError = 4,        // Calls to dlc service fail with explicit errors.
  kDlcUnknownError = 5,  // Calls to dlc service fail without explicit errors.
  kInvalidLibraryError = 6,   // Fail to load the library.
  kFunctionMissingError = 7,  // Fail to look up key functions in the library.
  kTaskSkipped = 8,  // Skip scheduled task for !TrainingConditionsSatisfied.
  kMaxValue = kTaskSkipped,
};

enum class StorageEvent {
  kConnected = 0,
  kDisconnected = 1,
  kEmptyUsernameError = 2,
  kDbInitError = 3,
  kDbIntegrityCheckError = 4,
  kDbCleanOutdatedDataError = 5,
  kMaxValue = kDbCleanOutdatedDataError,
};

enum class ClientEvent {
  kExampleReceived = 0,
  kGetExampleIteratorError = 1,
  kGetNextExampleError = 2,
  kUnsatisfiedConditionAbort = 3,
  kContributed = 4,
  kRejected = 5,
  kTaskFailedUnknownError = 6,
  kTaskTimeoutAbort = 7,
  kMaxValue = kTaskTimeoutAbort,
};

// A scoped metrics recorder for a round of task. It collects metrics when the
// tasks starts and reports them if the task finishes successfully. Currently
// only cpu time, more metrics can be added when required.
class ScopedMetricsRecorder {
 public:
  ~ScopedMetricsRecorder();

  void MarkSuccess();

 private:
  friend class Metrics;
  // Use Metrics::GetInstance()->CreateScopedMetricsRecorder() instead.
  ScopedMetricsRecorder(const std::string& client_name,
                        MetricsLibraryInterface* metrics_library);

  const std::string& client_name_;
  const int64_t initial_cpu_clock_;
  // TODO(b/251378482): Also include the memory.
  bool success_;

  // Not owned:
  MetricsLibraryInterface* const metrics_library_;
};

class Metrics {
 public:
  // Logs federated service related events, mostly about the fcp library
  // loading.
  void LogServiceEvent(ServiceEvent event) const;
  // Logs storage related events, e.g. the database is connected/disconnected,
  // or errors happen when connecting to the database.
  void LogStorageEvent(StorageEvent event) const;
  // Logs events of the given client, mostly about the task execution status.
  void LogClientEvent(const std::string& client_name, ClientEvent event) const;
  // Alias of LogClientEvent(client_name, ClientEvent::kExampleReceived);
  void LogExampleReceived(const std::string& client_name) const;
  ScopedMetricsRecorder CreateScopedMetricsRecorder(
      const std::string& client_name);

  static Metrics* GetInstance();

 private:
  friend base::NoDestructor<Metrics>;
  Metrics();  // Use Metrics::GetInstance() instead.
  ~Metrics();

  const std::unique_ptr<MetricsLibraryInterface> metrics_library_;
};

}  // namespace federated

#endif  // FEDERATED_METRICS_H_
