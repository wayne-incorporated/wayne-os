// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_DATA_MIGRATOR_FAKE_MIGRATION_HELPER_DELEGATE_H_
#define CRYPTOHOME_DATA_MIGRATOR_FAKE_MIGRATION_HELPER_DELEGATE_H_

#include <sys/stat.h>

#include <map>
#include <optional>
#include <string>
#include <unordered_set>

#include <base/files/file.h>
#include <base/files/file_path.h>

#include "cryptohome/data_migrator/migration_helper_delegate.h"
#include "cryptohome/platform.h"

namespace cryptohome::data_migrator {

class FakeMigrationHelperDelegate : public MigrationHelperDelegate {
 public:
  FakeMigrationHelperDelegate(Platform* platform, const base::FilePath& to_dir);
  ~FakeMigrationHelperDelegate() override;

  FakeMigrationHelperDelegate(const FakeMigrationHelperDelegate&) = delete;
  FakeMigrationHelperDelegate& operator=(const FakeMigrationHelperDelegate&) =
      delete;

  // Adds a path to the migration denylist. The |path| should be a relative path
  // of a file or a directory to the migration source. Adding the path to the
  // denylist makes the file or the directory (including its contents) not
  // migrated to the migration destination.
  void AddDenylistedPath(const base::FilePath& path);

  // Adds a rule to convert xattr that exactly matches |name_from| to |name_to|.
  void AddXattrMapping(const std::string& name_from,
                       const std::string& name_to);

  // Adds a rule to convert UID |uid_from| to |uid_to|. If |uid_to| is null, it
  // means that we fail to convert |uid_from|.
  void AddUidMapping(uid_t uid_from, const std::optional<uid_t>& uid_to);

  // Sets the value to be returned by FreeSpaceForMigrator(). When the return
  // value of FreeSpaceForMigrator() has not been set, it falls back to the
  // result of |platform_.AmountOfFreeDiskSpace(to_dir_)|.
  void SetFreeDiskSpaceForMigrator(int64_t free_disk_space_for_migrator);

  // MigrationHelperDelegate overrides:
  bool ShouldMigrateFile(const base::FilePath& child) override;
  bool ShouldCopyQuotaProjectId() override;
  bool ShouldSkipFileOnIOErrors() override;
  std::string GetMtimeXattrName() override;
  std::string GetAtimeXattrName() override;
  bool ConvertFileMetadata(base::stat_wrapper_t* stat) override;
  std::string ConvertXattrName(const std::string& name) override;
  int64_t FreeSpaceForMigrator() override;

 private:
  std::unordered_set<base::FilePath> denylisted_paths_;
  std::map<std::string, std::string> xattr_mappings_;
  std::map<uid_t, std::optional<uid_t>> uid_mappings_;
  std::optional<int64_t> free_disk_space_for_migrator_;
  const Platform* platform_;
  const base::FilePath to_dir_;
};

}  // namespace cryptohome::data_migrator

#endif  // CRYPTOHOME_DATA_MIGRATOR_FAKE_MIGRATION_HELPER_DELEGATE_H_
