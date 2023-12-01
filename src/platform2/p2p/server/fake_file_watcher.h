// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_SERVER_FAKE_FILE_WATCHER_H_
#define P2P_SERVER_FAKE_FILE_WATCHER_H_

#include <glib.h>

#include <queue>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>

#include "p2p/server/file_watcher.h"

namespace p2p {

namespace server {

// A FileWatcher that doesn't really do anything.
class FakeFileWatcher : public FileWatcher {
 public:
  FakeFileWatcher(const base::FilePath& dir, const std::string& file_extension)
      : dir_(dir), file_extension_(file_extension), source_id_(0) {}
  FakeFileWatcher(const FakeFileWatcher&) = delete;
  FakeFileWatcher& operator=(const FakeFileWatcher&) = delete;

  ~FakeFileWatcher() override {
    if (source_id_ != 0)
      g_source_remove(source_id_);
  }

  const std::vector<base::FilePath>& files() const override {
    return exposed_files_;
  }

  void SetChangedCallback(
      FileWatcher::FileWatcherCallback changed_callback) override {
    changed_callback_ = changed_callback;
  }

  const base::FilePath& dir() const override { return dir_; }

  const std::string& file_extension() const override { return file_extension_; }

  // Fake methods.

  // Add, Remove or Touch a file in the watched directory. Since those
  // functions are intended to be called by a test, the file extension is not
  // checked. This will make the watched directory to emit a call to the
  // provided callback with the appropriate arguments in each case from the main
  // loop.
  bool AddFile(const base::FilePath& filename, size_t file_size) {
    if (files_.find(filename) != files_.end())
      return false;
    files_.insert(filename);

    // Schedule the action.
    if (pending_actions_.empty())
      source_id_ = g_idle_add(OnFileChanged, this);
    pending_actions_.push((FileEvent){.filename = filename,
                                      .event_type = kFileAdded,
                                      .file_size = file_size});
    return true;
  }

  bool RemoveFile(const base::FilePath& filename) {
    if (files_.find(filename) == files_.end())
      return false;
    files_.erase(filename);

    // Schedule the action.
    if (pending_actions_.empty())
      source_id_ = g_idle_add(OnFileChanged, this);
    pending_actions_.push((FileEvent){
        .filename = filename, .event_type = kFileRemoved, .file_size = 0});
    return true;
  }

  bool TouchFile(const base::FilePath& filename, size_t file_size) {
    if (files_.find(filename) != files_.end())
      return false;

    // Schedule the action.
    if (pending_actions_.empty())
      source_id_ = g_idle_add(OnFileChanged, this);
    pending_actions_.push((FileEvent){.filename = filename,
                                      .event_type = kFileChanged,
                                      .file_size = file_size});
    return true;
  }

 private:
  static gboolean OnFileChanged(gpointer user_data) {
    FakeFileWatcher* watcher = reinterpret_cast<FakeFileWatcher*>(user_data);
    const FileEvent& event = watcher->pending_actions_.front();
    char* buf = NULL;

    switch (event.event_type) {
      case kFileAdded:
        watcher->exposed_files_.push_back(event.filename);
        // Create the file on disk to allow the consumer get its file size.
        [[fallthrough]];
      case kFileChanged:
        // Both kFileAdded and kFileChanged execute this part:
        buf = static_cast<char*>(malloc(event.file_size));
        base::WriteFile(event.filename, buf, event.file_size);
        free(buf);
        break;
      case kFileRemoved:
        watcher->exposed_files_.erase(find(watcher->exposed_files_.begin(),
                                           watcher->exposed_files_.end(),
                                           event.filename));
        unlink(event.filename.value().c_str());
        break;
    }

    // Dispatch the callback. This could add more events to the queue, so we
    // keep the processed event until the callback returns and check empty()
    // later on this function.
    if (!watcher->changed_callback_.is_null())
      watcher->changed_callback_.Run(event.filename, event.event_type);

    watcher->pending_actions_.pop();
    return !watcher->pending_actions_.empty();
  }

  base::FilePath dir_;
  std::string file_extension_;
  FileWatcher::FileWatcherCallback changed_callback_;

  // The list of files in the watched directory once the Add/Remove event was
  // processed. This is what a call to files() will return.
  std::vector<base::FilePath> exposed_files_;

  // The set of files added by the test, used to ensure proper call arguments
  // (i.e. fail when the test attempts to add twice the same file).
  std::set<base::FilePath> files_;

  // The list of pending actions (Add/Remove/Touch) to be processed.
  struct FileEvent {
    base::FilePath filename;
    EventType event_type;
    size_t file_size;
  };
  std::queue<FileEvent> pending_actions_;

  // The source_id used to dispatch file events.
  guint source_id_;
};

}  // namespace server

}  // namespace p2p

#endif  // P2P_SERVER_FAKE_FILE_WATCHER_H_
