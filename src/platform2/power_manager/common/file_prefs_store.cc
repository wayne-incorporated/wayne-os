// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "power_manager/common/file_prefs_store.h"
#include "power_manager/common/tracing.h"
#include "power_manager/common/util.h"

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

namespace power_manager {

FilePrefsStore::FilePrefsStore(const base::FilePath& pref_path)
    : pref_path_(pref_path) {}

std::string FilePrefsStore::GetDescription() const {
  return pref_path_.value();
}

bool FilePrefsStore::ReadPrefString(const std::string& name,
                                    std::string* value_out) {
  base::FilePath path = pref_path_.Append(name);
  return util::MaybeReadStringFile(path, value_out);
}

bool FilePrefsStore::ReadExternalString(const std::string& path,
                                        const std::string& name,
                                        std::string* value_out) {
  // Not currently implemented since there's no non-powerd setting we need to
  // read from a directory, such as /usr/share/<non-power_manager directory>/
  return false;
}

bool FilePrefsStore::WritePrefString(const std::string& name,
                                     const std::string& value) {
  base::FilePath path = pref_path_.Append(name);
  return base::WriteFile(path, value.data(), value.size()) != -1;
}

bool FilePrefsStore::Watch(
    const PrefsStoreInterface::ChangeCallback& callback) {
  callback_ = callback;
  dir_watcher_ = std::make_unique<base::FilePathWatcher>();
  return dir_watcher_->Watch(
      pref_path_, base::FilePathWatcher::Type::kNonRecursive,
      base::BindRepeating(&FilePrefsStore::HandlePathChanged,
                          base::Unretained(this)));
}

void FilePrefsStore::HandlePathChanged(const base::FilePath& path, bool error) {
  TRACE_EVENT("power", "FilePrefsStore::HandlePathChanged", "path",
              path.value(), "error", error, "pref_path", pref_path_.value());
  if (error) {
    LOG(ERROR) << "Got error while hearing about change to " << path.value();
    return;
  }

  if (path == pref_path_) {
    UpdateFileWatchers();
    return;
  }

  callback_.Run(path.BaseName().value());
  return;
}

void FilePrefsStore::UpdateFileWatchers() {
  // Look for files that have been created or unlinked.
  base::FileEnumerator enumerator(pref_path_, false,
                                  base::FileEnumerator::FILES);
  std::set<std::string> current_prefs;
  for (base::FilePath path = enumerator.Next(); !path.empty();
       path = enumerator.Next()) {
    current_prefs.insert(path.BaseName().value());
  }
  std::vector<std::string> added_prefs;
  for (const auto& name : current_prefs) {
    if (file_watchers_.find(name) == file_watchers_.end())
      added_prefs.push_back(name);
  }
  std::vector<std::string> removed_prefs;
  for (const auto& watcher_pair : file_watchers_) {
    if (current_prefs.find(watcher_pair.first) == current_prefs.end())
      removed_prefs.push_back(watcher_pair.first);
  }

  // Start watching new files.
  for (const auto& name : added_prefs) {
    const base::FilePath path = pref_path_.Append(name);
    std::unique_ptr<base::FilePathWatcher> watcher =
        std::make_unique<base::FilePathWatcher>();
    if (watcher->Watch(path, base::FilePathWatcher::Type::kNonRecursive,
                       base::BindRepeating(&FilePrefsStore::HandlePathChanged,
                                           base::Unretained(this)))) {
      file_watchers_.insert(std::make_pair(name, std::move(watcher)));
    } else {
      LOG(ERROR) << "Unable to watch " << path.value() << " for changes";
    }
    callback_.Run(name);
  }

  // Stop watching old files.
  for (const auto& name : removed_prefs) {
    file_watchers_.erase(name);
    callback_.Run(name);
  }
}

}  // namespace power_manager
