// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/federated_client.h"

#include <string>
#include <utility>

#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>

#include "federated/device_status_monitor.h"
#include "federated/example_database.h"
#include "federated/federated_metadata.h"
#include "federated/metrics.h"
#include "federated/protos/cros_events.pb.h"
#include "federated/protos/cros_example_selector_criteria.pb.h"
#include "federated/utils.h"

namespace federated {

namespace {
#if USE_LOCAL_FEDERATED_SERVER
constexpr base::TimeDelta kInitialWaitingWindow = base::Seconds(30);
constexpr base::TimeDelta kDefaultRetryWindow = base::Seconds(30);
constexpr base::TimeDelta kMinimalRetryWindow = base::Seconds(10);
#else
// The first checkin happens kInitialWaitingWindow after the device startup to
// avoid resource competition.
constexpr base::TimeDelta kInitialWaitingWindow = base::Minutes(5);
// The default value is used when the server doesn't respond with a valid retry
// window.
constexpr base::TimeDelta kDefaultRetryWindow = base::Minutes(30);
// The retry window should not be shorter than kMinimalRetryWindow to avoid
// spam.
constexpr base::TimeDelta kMinimalRetryWindow = base::Minutes(1);
#endif

// Limits each round to 10 minutes.
constexpr base::TimeDelta kMaximalExecutionTime = base::Minutes(10);

// TODO(b/251378482): Just dummpy impl for now, might need to log to UMA.
void LogCrosEvent(const fcp::client::CrosEvent& cros_event) {
  LOG(INFO) << "In LogCrosEvent, model_id is " << cros_event.model_id()
            << ", event_type is "
            << fcp::client::CrosEvent::EventType_Name(cros_event.event_type());
  DVLOG(1) << "cros_event is " << cros_event.DebugString();
}

// TODO(b/251378482): Just dummpy impl for now, might need to log to UMA.
void LogCrosSecAggEvent(const fcp::client::CrosSecAggEvent& cros_secagg_event) {
  LOG(INFO) << "In LogCrosSecAggEvent, session_id is "
            << cros_secagg_event.execution_session_id();

  if (cros_secagg_event.has_state_transition())
    LOG(INFO) << "cros_secagg_event.has_state_transition";
  else if (cros_secagg_event.has_error())
    LOG(ERROR) << "cros_secagg_event.has_error";
  else if (cros_secagg_event.has_abort())
    LOG(INFO) << "cros_secagg_event.has_abort";
  else
    LOG(INFO) << "cros_secagg_event doesn't have any event log";
}

}  // namespace

FederatedClient::Context::Context(
    const std::string& client_name,
    const std::string& population_name,
    const DeviceStatusMonitor* const device_status_monitor,
    const StorageManager* const storage_manager)
    : client_name_(client_name),
      population_name_(population_name),
      start_time_(base::Time::Now()),
      device_status_monitor_(device_status_monitor),
      storage_manager_(storage_manager) {}

FederatedClient::Context::~Context() = default;

bool FederatedClient::Context::PrepareExamples(const char* const criteria_data,
                                               const int criteria_data_size,
                                               void* const context) {
  auto* typed_context = static_cast<FederatedClient::Context*>(context);
  const std::string& client_name = typed_context->client_name_;

  fcp::client::CrosExampleSelectorCriteria criteria;
  if (!criteria.ParseFromArray(criteria_data, criteria_data_size)) {
    LOG(ERROR) << "Failed to parse criteria.";
    Metrics::GetInstance()->LogClientEvent(
        client_name, ClientEvent::kGetExampleIteratorError);
    return false;
  }

  if (criteria.task_name().empty()) {
    LOG(ERROR) << "No valid task_name";
    Metrics::GetInstance()->LogClientEvent(
        client_name, ClientEvent::kGetExampleIteratorError);
    return false;
  }

  // Initializes `new_meta_record_`, if iterator is created successfully and the
  // task starts, it keeps the largest seen example id and the associated
  // example timestamp . If the task succeeds, metatable will be updated with
  // `new_meta_record_`.
  // Next time when running this task and if it prevents used examples, example
  // selection will start from last_used_example_timestamp not inclusive.
  // This is a precise breakpoint compared to last_contribution_time, because
  // there may be new examples received during a computation and with timestamp
  // in between last_used_example_timestamp and last_contribution_time. Such
  // examples will never be used.
  // Note: The identifier contains population_name instead of client name, so
  // that when a client's launch stage changes, e.g. from "dev" to "dogfood",
  // the examples in this client's table used in dev stage can be used in
  // dogfood again.
  typed_context->new_meta_record_.identifier =
      base::StringPrintf("%s#%s", typed_context->population_name_.c_str(),
                         criteria.task_name().c_str());
  typed_context->new_meta_record_.last_used_example_id = -1;
  typed_context->new_meta_record_.last_used_example_timestamp =
      base::Time::UnixEpoch();

  std::optional<ExampleDatabase::Iterator> example_iterator =
      typed_context->storage_manager_->GetExampleIterator(
          client_name, typed_context->new_meta_record_.identifier, criteria);
  if (!example_iterator.has_value()) {
    DVLOG(1) << "Client " << client_name << " failed to prepare examples.";
    Metrics::GetInstance()->LogClientEvent(
        client_name, ClientEvent::kGetExampleIteratorError);
    return false;
  }

  typed_context->example_iterator_ = std::move(example_iterator.value());
  return true;
}

bool FederatedClient::Context::GetNextExample(const char** const data,
                                              int* const size,
                                              bool* const end,
                                              void* const context) {
  if (context == nullptr)
    return false;

  auto* typed_context = static_cast<FederatedClient::Context*>(context);

  const absl::StatusOr<ExampleRecord> record =
      typed_context->example_iterator_.Next();

  if (absl::IsInvalidArgument(record.status())) {
    Metrics::GetInstance()->LogClientEvent(
        typed_context->client_name_, ClientEvent::kGetExampleIteratorError);
    return false;
  }

  if (record.ok()) {
    *end = false;
    *size = record->serialized_example.size();
    char* const str_data = new char[*size];
    record->serialized_example.copy(str_data, *size);
    *data = str_data;

    if (record->id > typed_context->new_meta_record_.last_used_example_id) {
      typed_context->new_meta_record_.last_used_example_id = record->id;
      typed_context->new_meta_record_.last_used_example_timestamp =
          record->timestamp;
    }
  } else {
    DCHECK(absl::IsOutOfRange(record.status()));
    *end = true;
  }

  return true;
}

void FederatedClient::Context::FreeExample(const char* const data,
                                           void* const context) {
  delete[] data;
}

bool FederatedClient::Context::TrainingConditionsSatisfied(
    void* const context) {
  if (context == nullptr)
    return false;

  auto* typed_context = static_cast<FederatedClient::Context*>(context);

  // If time cost exceeds the limit, return false to quit this round.
  base::TimeDelta time_cost = base::Time::Now() - typed_context->start_time_;
  if (time_cost > kMaximalExecutionTime) {
    Metrics::GetInstance()->LogClientEvent(typed_context->client_name_,
                                           ClientEvent::kTaskTimeoutAbort);
    return false;
  }

  const bool condition_satisfied =
      typed_context->device_status_monitor_->TrainingConditionsSatisfied();

  if (!condition_satisfied) {
    Metrics::GetInstance()->LogClientEvent(
        typed_context->client_name_, ClientEvent::kUnsatisfiedConditionAbort);
  }

  return condition_satisfied;
}

void FederatedClient::Context::PublishEvent(const char* const event,
                                            const int size,
                                            void* const context) {
  if (context == nullptr) {
    LOG(ERROR) << "PublishEvent gets nullptr context.";
    return;
  }

  fcp::client::CrosEventLog event_log;
  if (!event_log.ParseFromArray(event, size)) {
    LOG(ERROR) << "Failed to parse event_log.";
    return;
  }

  if (event_log.has_event()) {
    LogCrosEvent(event_log.event());
  } else if (event_log.has_secagg_event()) {
    LogCrosSecAggEvent(event_log.secagg_event());
  } else {
    LOG(ERROR) << "event_log has no content";
  }
}

FederatedClient::FederatedClient(
    const FlRunPlanFn run_plan,
    const FlFreeRunPlanResultFn free_run_plan_result,
    const std::string& service_uri,
    const std::string& api_key,
    const std::string& brella_lib_version,
    const ClientConfigMetadata client_config,
    const DeviceStatusMonitor* const device_status_monitor)
    : run_plan_(run_plan),
      free_run_plan_result_(free_run_plan_result),
      service_uri_(service_uri),
      api_key_(api_key),
      brella_lib_version_(brella_lib_version),
      client_config_(client_config),
      next_retry_delay_(kInitialWaitingWindow),
      device_status_monitor_(device_status_monitor) {}

FederatedClient::~FederatedClient() = default;

void FederatedClient::RunPlan(const StorageManager* const storage_manager) {
  if (!storage_manager->IsDatabaseConnected()) {
    next_retry_delay_ = kDefaultRetryWindow;
    DVLOG(1) << "StorageManager doesn't have a database connection, retry in "
             << next_retry_delay_;
    return;
  }

  DCHECK(!storage_manager->sanitized_username().empty())
      << "storage_manager->sanitized_username() is unexpectedly empty!";

  // Compose a unique population name from the client name and the launch stage.
  const std::string population_name =
      base::StringPrintf("chromeos/%s/%s", client_config_.name.c_str(),
                         client_config_.launch_stage.c_str());
  FederatedClient::Context context(client_config_.name, population_name,
                                   device_status_monitor_, storage_manager);

  const std::string base_dir_in_cryptohome =
      GetBaseDir(storage_manager->sanitized_username(), client_config_.name)
          .value();
  const FlTaskEnvironment env = {
      &FederatedClient::Context::PrepareExamples,
      &FederatedClient::Context::GetNextExample,
      &FederatedClient::Context::FreeExample,
      &FederatedClient::Context::TrainingConditionsSatisfied,
      &FederatedClient::Context::PublishEvent,
      base_dir_in_cryptohome.c_str(),
      &context};

  auto scoped_metrics_recorder =
      Metrics::GetInstance()->CreateScopedMetricsRecorder(client_config_.name);
  FlRunPlanResult result = (*run_plan_)(
      env, service_uri_.c_str(), api_key_.c_str(), brella_lib_version_.c_str(),
      population_name.c_str(), client_config_.retry_token.c_str());

  // TODO(b/251378482): maybe log the event to UMA
  if (result.status == CONTRIBUTED || result.status == REJECTED_BY_SERVER) {
    DVLOG(1) << "result.status = " << result.status;
    DVLOG(1) << "result.retry_token = " << result.retry_token;
    DVLOG(1) << "result.delay_usecs = " << result.delay_usecs;
    client_config_.retry_token = std::string(result.retry_token);
    next_retry_delay_ = base::Microseconds(result.delay_usecs);

    // TODO(b/239623649): result.delay_usecs may be 0 when setup is wrong, now I
    // set next_retry_delay_ to kMinimalRetryWindow to avoid spam, consider
    // stopping retry in this case because it's very likely to fail again.
    if (next_retry_delay_ < kMinimalRetryWindow)
      next_retry_delay_ = kMinimalRetryWindow;

    if (result.status == CONTRIBUTED) {
      scoped_metrics_recorder.MarkSuccess();
      Metrics::GetInstance()->LogClientEvent(client_config_.name,
                                             ClientEvent::kContributed);
      context.new_meta_record().timestamp = base::Time::Now();
      storage_manager->UpdateMetaRecord(context.new_meta_record());
    } else {
      Metrics::GetInstance()->LogClientEvent(client_config_.name,
                                             ClientEvent::kRejected);
    }
  } else {
    DVLOG(1) << "Failed to checkin with the servce, result.status = "
             << result.status;
    Metrics::GetInstance()->LogClientEvent(
        client_config_.name, ClientEvent::kTaskFailedUnknownError);
    next_retry_delay_ = kDefaultRetryWindow;
  }

  (*free_run_plan_result_)(result);
}

void FederatedClient::ResetRetryDelay() {
  next_retry_delay_ = kDefaultRetryWindow;
}

std::string FederatedClient::GetClientName() const {
  return client_config_.name;
}

}  // namespace federated
