// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_LOCAL_DATA_MIGRATION_H_
#define TPM_MANAGER_SERVER_LOCAL_DATA_MIGRATION_H_

#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/local_data_migration/frontend.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "tpm_manager/proto_bindings/tpm_manager.pb.h"
#include "tpm_manager/server/legacy_local_data.pb.h"

// This header defines the utilities to migrate the database from
// |cryptohome| to |tpm_manager|. In principle, the normal functions here don't
// handle the file access but only deal with the operations on in-memory
// protobuf messages, while the file I/O operations are included as member
// functions of |LocalDataMigrator|.
//
// Though the migration logic is TPM-version independent, it is meant to be
// used for TPM1.2 device.
//
// See b/131645437.

namespace tpm_manager {

// Unseals, parses, and then migrates delegate information from
// |sealed_database| and stores into |delegate|.
// Returns |true| iff the operation succeeds. Requires non-null |hwsec| to
// unseal |sealed_database| and non-null |delegate| to store the output.
bool MigrateAuthDelegate(const brillo::SecureBlob& sealed_database,
                         const hwsec::LocalDataMigrationFrontend* hwsec,
                         AuthDelegate* delegate);

// Parses a |LegacyTpmStatus| from |serialized_tpm_status| and then stores owner
// password inside into |owner_password|. Returns |true| iff the operation
// succeeds. Requires non-null |owner_password| to store the output and non-null
// |hwsec| to unseal the owner password.
bool UnsealOwnerPasswordFromSerializedTpmStatus(
    const brillo::SecureBlob& serialized_tpm_status,
    const hwsec::LocalDataMigrationFrontend* hwsec,
    brillo::SecureBlob* owner_password);

// |LocalDataMigrator| performs the high-level operations with virtualized file
// operations.
class LocalDataMigrator {
 public:
  LocalDataMigrator() = default;
  virtual ~LocalDataMigrator() = default;

  // Reads the sealed database from |database_path| and migrates the auth
  // delegate into |local_data|. It uses |hwsec| to perform unsealing operation.
  // Failure of reading content from |database_path| or any error during the
  // migration casues it to return |false|. Performs no-ops and returns |true|
  // if the database doesn't have the auth delegate, |database_path| doesn't
  // exists, or |local_data| has the auth delegate already. Upon returning
  // |true|, |has_migrated| indicates if the legacy data has been migrated to
  // |local_data|.
  bool MigrateAuthDelegateIfNeeded(
      const base::FilePath& database_path,
      const hwsec::LocalDataMigrationFrontend* hwsec,
      LocalData* local_data,
      bool* has_migrated);

  // Reads the tpm status from |tpm_status_path| and migrates the owner password
  // into |local_data|. Failure of reading content from |tpm_status_path| or any
  // error during the migration casues it to return |false|. Performs no-ops and
  // returns |true| if the tpm status doesn't have the owner password,
  // |tpm_status_path| doesn't exists, or |local_data| has owner password
  // already. Upon returning |true|, |has_migrated| indicates if the legacy data
  // has been migrated to |local_data|.
  bool MigrateOwnerPasswordIfNeeded(
      const base::FilePath& tpm_status_path,
      const hwsec::LocalDataMigrationFrontend* hwsec,
      LocalData* local_data,
      bool* has_migrated);

 protected:
  // The set of functions below performs file-related operations. They are
  // protected so they can hide from users of this class, and virtualized so
  // they are able to be overriden for testing purpose.

  // Checks if the file at |path| exists.
  virtual bool PathExists(const base::FilePath& path);

  // Reads the file content from |path| and stores to |content|.
  virtual bool ReadFileToString(const base::FilePath& path,
                                std::string* content);
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_LOCAL_DATA_MIGRATION_H_
