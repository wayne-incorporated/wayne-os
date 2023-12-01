// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/storage_manager.h"

#include <cstddef>
#include <memory>
#include <optional>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <google/protobuf/util/time_util.h>

#include "federated/federated_metadata.h"
#include "federated/metrics.h"
#include "federated/session_manager_proxy.h"
#include "federated/utils.h"

#if USE_LOCAL_FEDERATED_SERVER
#include <vector>
#include "federated/mojom/example.mojom.h"
#endif

namespace federated {
namespace {
const base::TimeDelta kExampleTtl = base::Days(10);

#if USE_LOCAL_FEDERATED_SERVER
// When we are testing against a local federated server, we want to populate
// the test server with generic test data
using ::chromeos::federated::mojom::Example;
using ::chromeos::federated::mojom::ExamplePtr;
using ::chromeos::federated::mojom::Features;
using ::chromeos::federated::mojom::FloatList;
using ::chromeos::federated::mojom::Int64List;
using ::chromeos::federated::mojom::StringList;
using ::chromeos::federated::mojom::ValueList;
using ::chromeos::federated::mojom::ValueListPtr;

ValueListPtr CreateStringList(const std::vector<std::string>& values) {
  ValueListPtr value_list = ValueList::NewStringList(StringList::New());
  value_list->get_string_list()->value = values;
  return value_list;
}

ExamplePtr CreateExamplePtr(const std::string& query) {
  ExamplePtr example = Example::New();
  example->features = Features::New();
  auto& feature_map = example->features->feature;
  feature_map["query"] = CreateStringList({query});

  return example;
}
#endif

}  // namespace

StorageManager::StorageManager() = default;
StorageManager::~StorageManager() = default;

void StorageManager::InitializeSessionManagerProxy(dbus::Bus* const bus) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(session_manager_proxy_, nullptr)
      << "session_manager_proxy is already initialized!";
  DCHECK_NE(bus, nullptr);
  session_manager_proxy_ = std::make_unique<SessionManagerProxy>(
      std::make_unique<org::chromium::SessionManagerInterfaceProxy>(bus));

  session_manager_proxy_->AddObserver(this);
  // If session already started, connect to database.
  if (session_manager_proxy_->RetrieveSessionState() == kSessionStartedState) {
    ConnectToDatabaseIfNecessary();
  }
}

bool StorageManager::IsDatabaseConnected() const {
  return example_database_ != nullptr && example_database_->IsOpen();
}

bool StorageManager::OnExampleReceived(const std::string& client_name,
                                       const std::string& serialized_example) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!IsDatabaseConnected()) {
    VLOG(1) << "No database connection";
    return false;
  }

  Metrics::GetInstance()->LogExampleReceived(client_name);

  ExampleRecord example_record;
  example_record.serialized_example = serialized_example;
  example_record.timestamp = base::Time::Now();

  return example_database_->InsertExample(client_name, example_record);
}

std::optional<ExampleDatabase::Iterator> StorageManager::GetExampleIterator(
    const std::string& client_name,
    const std::string& task_identifier,
    const fcp::client::CrosExampleSelectorCriteria& criteria) const {
  DCHECK(!criteria.task_name().empty());

  // This method may be called from different sequence but ExampleDatabase are
  // threadsafe.
  if (!IsDatabaseConnected()) {
    VLOG(1) << "No database connection";
    return std::nullopt;
  }

  bool descending =
      criteria.order() ==
      fcp::client::CrosExampleSelectorCriteria::INSERTION_DESCENDING;
  size_t limit = criteria.max_examples() > 0 ? criteria.max_examples() : 0;

  // Time range default to a {ancient_enough_start, now};
  base::Time end_timestamp = base::Time::Now();
  base::Time start_timestamp = end_timestamp - 2 * kExampleTtl;

  if (criteria.reject_used_examples()) {
    // If descending & limit examples, last_used_example_timestamp may prevent
    // unused examples.
    DCHECK(!descending || limit == 0);

    auto meta_record = example_database_->GetMetaRecord(task_identifier);
    if (meta_record.has_value()) {
      start_timestamp = meta_record.value().last_used_example_timestamp;
    } else if (criteria.has_last_successful_contribution_time()) {
      // This is an approximate and only works when there's no limit.
      DCHECK_EQ(limit, 0);
      start_timestamp = base::Time::FromJavaTime(
          ::google::protobuf::util::TimeUtil::TimestampToMilliseconds(
              criteria.last_successful_contribution_time()));
    } else {
      DVLOG(1) << "No valid start_timestamp to rule out used examples, use the "
                  "default one";
    }
  }

  const size_t min_example_count =
      criteria.min_examples() > 0 ? criteria.min_examples() : kMinExampleCount;
  const size_t example_count = example_database_->ExampleCount(
      client_name, start_timestamp, end_timestamp);

  DVLOG(1) << "For task_identifier = " << task_identifier
           << ", got valid example_count = " << example_count;

  if (example_count < min_example_count) {
    DVLOG(1) << "Client " << client_name << " "
             << "doesn't meet the minimum example count requirement";
    return std::nullopt;
  }

  return example_database_->GetIterator(client_name, start_timestamp,
                                        end_timestamp, descending, limit);
}

bool StorageManager::UpdateMetaRecord(const MetaRecord& meta_record) const {
  if (!IsDatabaseConnected()) {
    VLOG(1) << "No database connection";
    return false;
  }
  DCHECK(!meta_record.identifier.empty());
  DVLOG(1) << "UpdateMetaRecord: identifier = " << meta_record.identifier
           << ", last_used_example_id = " << meta_record.last_used_example_id
           << ", last_used_example_timestamp is "
           << meta_record.last_used_example_timestamp;
  return example_database_->UpdateMetaRecord(meta_record.identifier,
                                             meta_record);
}

void StorageManager::OnSessionStarted() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ConnectToDatabaseIfNecessary();
}

void StorageManager::OnSessionStopped() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  Metrics::GetInstance()->LogStorageEvent(StorageEvent::kDisconnected);
  example_database_.reset();
}

void StorageManager::ConnectToDatabaseIfNecessary() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  std::string new_sanitized_username =
      session_manager_proxy_->GetSanitizedUsername();
  if (new_sanitized_username.empty()) {
    VLOG(1) << "Sanitized_username is empty, disconnect the database";
    example_database_.reset();
    sanitized_username_ = "";
    Metrics::GetInstance()->LogStorageEvent(StorageEvent::kEmptyUsernameError);
    return;
  }

  if (IsDatabaseConnected() && new_sanitized_username == sanitized_username_) {
    VLOG(1) << "Database for user " << sanitized_username_
            << " is already connected, nothing changed";
    return;
  }

  sanitized_username_ = new_sanitized_username;
  const auto db_path = GetDatabasePath(sanitized_username_);
  example_database_ = std::make_unique<ExampleDatabase>(db_path);

  if (!example_database_->Init(GetClientNames())) {
    LOG(ERROR) << "Failed to connect to database for user "
               << sanitized_username_;
    Metrics::GetInstance()->LogStorageEvent(StorageEvent::kDbInitError);
    example_database_.reset();
  } else if (!example_database_->CheckIntegrity()) {
    LOG(ERROR) << "Failed to verify the database integrity for user "
               << sanitized_username_ << ", delete the existing db file";
    if (!base::DeleteFile(db_path)) {
      LOG(ERROR) << "Failed to delete corrupted db file " << db_path.value();
    }
    Metrics::GetInstance()->LogStorageEvent(
        StorageEvent::kDbIntegrityCheckError);
    example_database_.reset();
  } else if (!example_database_->DeleteOutdatedExamples(kExampleTtl)) {
    LOG(ERROR) << "Failed to delete outdated examples for user "
               << sanitized_username_;
    Metrics::GetInstance()->LogStorageEvent(
        StorageEvent::kDbCleanOutdatedDataError);
    example_database_.reset();
  } else {
    Metrics::GetInstance()->LogStorageEvent(StorageEvent::kConnected);
#if USE_LOCAL_FEDERATED_SERVER
    DVLOG(1) << "Successfully connect to database, inserts examples for test.";
    std::vector<std::string> queries = {"hey", "hey", "hey", "wow", "wow",
                                        "yay", "yay", "yay", "yay", "aha"};
    std::for_each(queries.begin(), queries.end(), [this](auto& query) {
      OnExampleReceived("analytics_test_population",
                        ConvertToTensorFlowExampleProto(CreateExamplePtr(query))
                            .SerializeAsString());
    });
#endif
  }
}

StorageManager* StorageManager::GetInstance() {
  static base::NoDestructor<StorageManager> storage_manager;
  return storage_manager.get();
}
}  // namespace federated
