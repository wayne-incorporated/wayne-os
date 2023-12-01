// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_FILE_PREFS_STORE_H_
#define POWER_MANAGER_COMMON_FILE_PREFS_STORE_H_

#include <map>
#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_path_watcher.h>

#include "power_manager/common/prefs.h"

namespace power_manager {

// PrefsStoreInterface implementation that uses files to store preferences.
class FilePrefsStore : public PrefsStoreInterface {
 public:
  explicit FilePrefsStore(const base::FilePath& pref_path);
  FilePrefsStore(const FilePrefsStore&) = delete;
  FilePrefsStore& operator=(const FilePrefsStore&) = delete;

  ~FilePrefsStore() override = default;

  // PrefsStoreInterface:
  std::string GetDescription() const override;
  bool ReadPrefString(const std::string& name, std::string* value_out) override;
  bool ReadExternalString(const std::string& path,
                          const std::string& name,
                          std::string* value_out) override;
  bool WritePrefString(const std::string& name,
                       const std::string& value) override;
  bool Watch(const PrefsStoreInterface::ChangeCallback& callback) override;

 private:
  using FileWatcherMap =
      std::map<std::string, std::unique_ptr<base::FilePathWatcher>>;

  // Called by |dir_watcher_| and |file_watchers_|. Calls UpdateFileWatchers()
  // for directory changes or notifies |callback_| for pref file changes.
  void HandlePathChanged(const base::FilePath& dir, bool error);

  void UpdateFileWatchers();

  // Path to a directory containing pref files.
  const base::FilePath pref_path_;

  // The callback passed to Watch(). Called when preference files change.
  PrefsStoreInterface::ChangeCallback callback_;

  // Watches |pref_path_| for changes, calling HandleDirChanged().
  std::unique_ptr<base::FilePathWatcher> dir_watcher_;

  // Watches files in |pref_path_| for changes, calling HandleFileChanged().
  FileWatcherMap file_watchers_;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_FILE_PREFS_STORE_H_
