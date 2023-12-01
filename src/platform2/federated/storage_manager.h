// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_STORAGE_MANAGER_H_
#define FEDERATED_STORAGE_MANAGER_H_

#include <memory>
#include <optional>
#include <string>

#include <base/no_destructor.h>
#include <base/sequence_checker.h>

#include "federated/example_database.h"
#include "federated/protos/cros_example_selector_criteria.pb.h"
#include "federated/session_manager_observer_interface.h"
#include "federated/session_manager_proxy.h"

namespace dbus {
class Bus;
}  // namespace dbus

namespace federated {

class SessionManagerProxy;

// Singleton class providing storage to satisfy federated service interface
// which receives new examples and federated computation interface which
// consumes examples for training/analytics.
class StorageManager : public SessionManagerObserverInterface {
 public:
  // Constructor is protected to disallow direct instantiation.
  ~StorageManager() override;

  static StorageManager* GetInstance();

  // Virtual for mocking:
  // Observes session status to connect/disconnect example database.
  virtual void InitializeSessionManagerProxy(dbus::Bus* bus);
  // Inserts the received example to `client_name`'s table, returns true if no
  // error occurs.
  virtual bool OnExampleReceived(const std::string& client_name,
                                 const std::string& serialized_example);
  // Generates a iterator through examples in `client_name` table that meet the
  // `criteria`.
  virtual std::optional<ExampleDatabase::Iterator> GetExampleIterator(
      const std::string& client_name,
      const std::string& task_identifier,
      const fcp::client::CrosExampleSelectorCriteria& criteria) const;
  // Updates the new meta_record into meta table, called when a task finishes
  // successfully.
  virtual bool UpdateMetaRecord(const MetaRecord& meta_record) const;

  // Returns true if the `example_database_` is connected.
  bool IsDatabaseConnected() const;

  // Returns current logged-in user hash to generate the current accessible
  // sub_path in the daemon store (powered by cryptohome).
  // StorageManager uses this sub_path for example database, other parties (e.g.
  // the fcp library) uses it to store data that needs to outlive user sessions,
  // e.g. the opstats db.
  std::string sanitized_username() const { return sanitized_username_; }

 protected:
  // NoDestructor needs access to constructor.
  friend class base::NoDestructor<StorageManager>;

  StorageManager();
  StorageManager(const StorageManager&) = delete;
  StorageManager& operator=(const StorageManager&) = delete;

 private:
  friend class StorageManagerTest;

  void set_example_database_for_testing(ExampleDatabase* example_database) {
    example_database_.reset(example_database);
  }

  // SessionManagerObserverInterface:
  void OnSessionStarted() override;
  void OnSessionStopped() override;

  void ConnectToDatabaseIfNecessary();

  // Session manager that notifies session state changes.
  std::unique_ptr<SessionManagerProxy> session_manager_proxy_;

  // The database connection.
  std::unique_ptr<ExampleDatabase> example_database_;

  // Current login user hash. The database is connected to
  // /run/daemon-store/federated/<sanitized_username_>/examples.db.
  std::string sanitized_username_;

  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace federated

#endif  // FEDERATED_STORAGE_MANAGER_H_
