// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_FILE_CHANGE_WATCHER_H_
#define CROSLOG_FILE_CHANGE_WATCHER_H_

#include "base/files/file_path.h"
#include "base/functional/callback.h"
#include "base/memory/singleton.h"
#include "base/observer_list_types.h"
namespace croslog {

class InotifyReader;

class FileChangeWatcher {
 public:
  static FileChangeWatcher* GetInstance();

  class Observer : public base::CheckedObserver {
   public:
    virtual void OnFileContentMaybeChanged() = 0;
    virtual void OnFileNameMaybeChanged() = 0;
  };

  // Add a handler to retrieve file change events.
  virtual bool AddWatch(const base::FilePath& path, Observer* observer) = 0;
  // Remove a handler to retrieve file change events.
  virtual void RemoveWatch(const base::FilePath& path) = 0;

 protected:
  FileChangeWatcher();
  FileChangeWatcher(const FileChangeWatcher&) = delete;
  FileChangeWatcher& operator=(const FileChangeWatcher&) = delete;
};

}  // namespace croslog

#endif  // CROSLOG_FILE_CHANGE_WATCHER_H_
