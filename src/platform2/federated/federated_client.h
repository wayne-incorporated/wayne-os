// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_FEDERATED_CLIENT_H_
#define FEDERATED_FEDERATED_CLIENT_H_

#include <string>

#include <fcp/fcp.h>

#include "federated/device_status_monitor.h"
#include "federated/example_database.h"
#include "federated/federated_metadata.h"
#include "federated/storage_manager.h"

namespace federated {

// FederatedClient encapsulates essential elements for a client to run
// federated tasks, e.g. the function ptr from the library(`run_plan_`,
// `free_run_plan_result_`), the server config, the client_config.
class FederatedClient {
 public:
  // FederatedLibrary::CreateClient should be used instead of this constructor.
  FederatedClient(FlRunPlanFn run_plan,
                  FlFreeRunPlanResultFn free_run_plan_result,
                  const std::string& service_uri,
                  const std::string& api_key,
                  const std::string& brella_lib_version,
                  ClientConfigMetadata client_config,
                  const DeviceStatusMonitor* device_status_monitor);
  FederatedClient& operator=(const FederatedClient&) = delete;
  ~FederatedClient();

  // Tries to checkin and start a federated task with the server, then updates
  // the client config, such as retry_token and next_retry_delay. It is
  // scheduled recurrently by Scheduler, see scheduler.cc for more details.
  void RunPlan(const StorageManager* storage_manager);
  // Resets `next_retry_delay_` to default. Called when current
  // `next_retry_delay_` elapses and a federated task is about to run.
  void ResetRetryDelay();
  std::string GetClientName() const;

  base::TimeDelta next_retry_delay() const { return next_retry_delay_; }

 private:
  // Context provides several static functions used in constructing
  // FlTaskEnvironment that serves as hook for the library to e.g. request
  // examples.
  // All the methods on this are static and take a void* context because this is
  // meant to be passed across as a C ABI.
  class Context {
   public:
    Context(const std::string& client_name,
            const std::string& population_name,
            const DeviceStatusMonitor* device_status_monitor,
            const StorageManager* storage_manager);
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    ~Context();

    MetaRecord& new_meta_record() { return new_meta_record_; }

    // Called by the library to prepare examples according to the criteria.
    static bool PrepareExamples(const char* const criteria_data,
                                int criteria_data_size,
                                void* context);
    // Called by the library to get next example. `context` is effectively a
    // pointer to an Context instance, the same to the following methods.
    // Returns true if no errors, caller can construct a serialized example with
    // `data` and `size` if `end` is false, or it knows examples run out.
    // Returns false if any errors.
    static bool GetNextExample(const char** data,
                               int* const size,
                               bool* const end,
                               void* const context);
    // Called by the library to free the char* returned by GetNextExample.
    static void FreeExample(const char* const data, void* const context);
    // Called by the library to inquiry whether the current task should continue
    // or quit early.
    static bool TrainingConditionsSatisfied(void* const context);
    // Called by the library to publish event logs out to the daemon.
    static void PublishEvent(const char* const event,
                             const int size,
                             void* const context);

   private:
    // `client_name_` represents a federated client. It collects examples with
    // certain schema for its goal. `client_name_` is used as the table name in
    // example storage. e.g. client_name = "timezone_code_phh".
    const std::string client_name_;
    // `population_name_` on the other hand, is an identifier that can be
    // recognized by the server side when the device checks in. It consists of a
    // fixed prefix "chromeos", the client name, and the launch stage, separated
    // by "/". The launch stage can be "dev", "dogfood", "internal", "prod",
    // etc. e.g. population_name = "chromeos/timezone_code_phh/dev".
    const std::string population_name_;
    // New meta record that will be updated to Metatable if contribution
    // succeeds.
    MetaRecord new_meta_record_;
    // The time the context instance is created, used in
    // `TrainingConditionsSatisfied` to early stop if the task takes too long.
    const base::Time start_time_;
    // Not owned:
    const DeviceStatusMonitor* const device_status_monitor_;
    const StorageManager* const storage_manager_;

    ExampleDatabase::Iterator example_iterator_;
  };

  const FlRunPlanFn run_plan_;
  const FlFreeRunPlanResultFn free_run_plan_result_;

  const std::string service_uri_;
  const std::string api_key_;
  const std::string brella_lib_version_;

  ClientConfigMetadata client_config_;
  base::TimeDelta next_retry_delay_;

  // Not owned:
  const DeviceStatusMonitor* const device_status_monitor_;
};

}  // namespace federated

#endif  // FEDERATED_FEDERATED_CLIENT_H_
