// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>
#include <libhwsec/factory/factory_impl.h>
#include <libhwsec/frontend/local_data_migration/frontend.h>
#include <libhwsec-foundation/tpm/tpm_version.h>
#include <tpm_manager-client/tpm_manager/dbus-constants.h>
#include "tpm_manager/proto_bindings/tpm_manager.pb.h"
#include "tpm_manager/server/local_data_migration.h"
#include "tpm_manager/server/local_data_store_impl.h"

namespace {

constexpr char kLogToStderrSwitch[] = "log_to_stderr";
constexpr char kDatabasePathSwitch[] = "database_path";
constexpr char kTpmStatusPathSwitch[] = "tpm_status_path";
constexpr char kLocalDataPathSwitch[] = "local_data_path";

constexpr char kDefaultDatabasePath[] =
    "/mnt/stateful_partition/unencrypted/preserve/attestation.epb";
constexpr char kDefaultTpmStatusPath[] = "/mnt/stateful_partition/.tpm_status";
constexpr char kDefaultLocalDataPath[] = "/var/lib/tpm_manager/local_tpm_data";

bool ShallTryMigrateLocalData() {
  TPM_SELECT_BEGIN;
  TPM1_SECTION({ return true; });
  TPM2_SECTION({ return false; });
  OTHER_TPM_SECTION();
  TPM_SELECT_END;
  return false;
}

}  // namespace

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  int flags = brillo::kLogToSyslog;
  if (cl->HasSwitch(kLogToStderrSwitch)) {
    flags |= brillo::kLogToStderr;
  }
  brillo::InitLog(flags);

  if (!ShallTryMigrateLocalData()) {
    LOG(INFO) << "local data migration is non-applicable and performs no-ops.";
    return 0;
  }

  // Determines if we are using the default file paths, respectively.
  std::string database_path_str = cl->GetSwitchValueASCII(kDatabasePathSwitch);
  std::string tpm_status_path_str =
      cl->GetSwitchValueASCII(kTpmStatusPathSwitch);
  std::string local_data_path_str =
      cl->GetSwitchValueASCII(kLocalDataPathSwitch);
  if (database_path_str.empty()) {
    database_path_str = kDefaultDatabasePath;
  }
  if (tpm_status_path_str.empty()) {
    tpm_status_path_str = kDefaultTpmStatusPath;
  }
  if (local_data_path_str.empty()) {
    local_data_path_str = kDefaultLocalDataPath;
  }

  base::FilePath database_path(database_path_str);
  base::FilePath tpm_status_path(tpm_status_path_str);

  tpm_manager::LocalData local_data;
  tpm_manager::LocalDataStoreImpl local_data_store(local_data_path_str);

  if (!local_data_store.Read(&local_data)) {
    LOG(ERROR) << "Failed to read local data from store.";
    return 1;
  }
  bool has_delegates_before = !local_data.owner_delegate().blob().empty() &&
                              !local_data.owner_delegate().secret().empty();
  bool has_owner_password_before = !local_data.owner_password().empty();

  if (has_delegates_before && has_owner_password_before) {
    LOG(INFO) << "No need to migrate local data.";
    return 0;
  }

  tpm_manager::LocalDataMigrator migrator;
  bool has_migrated;
  hwsec::FactoryImpl factory;
  std::unique_ptr<const hwsec::LocalDataMigrationFrontend> hwsec =
      factory.GetLocalDataMigrationFrontend();
  if (!migrator.MigrateOwnerPasswordIfNeeded(tpm_status_path, hwsec.get(),
                                             &local_data, &has_migrated)) {
    LOG(ERROR) << "Failed to migrate owner password.";
    return 1;
  }
  if (has_migrated) {
    for (auto value : tpm_manager::kInitialTpmOwnerDependencies) {
      local_data.add_owner_dependency(value);
    }
  }
  bool is_local_data_updated = has_migrated;
  // Migrates the delegate only when the owner password is absent; tpm_managerd
  // will re-create the delegate in this case.
  if (local_data.owner_password().empty() &&
      !migrator.MigrateAuthDelegateIfNeeded(database_path, hwsec.get(),
                                            &local_data, &has_migrated)) {
    LOG(WARNING) << "Failed to migrate owner delegate.";
  }
  is_local_data_updated |= has_migrated;

  if (is_local_data_updated && !local_data_store.Write(local_data)) {
    LOG(ERROR) << "Failed to strore the migrated local data.";
    return 1;
  }
  LOG(INFO) << "Finished local data migration process successfully.";
  return 0;
}
