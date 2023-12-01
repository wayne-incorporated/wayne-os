// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_SERVER_FILE_WATCHER_H_
#define P2P_SERVER_FILE_WATCHER_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback.h>

namespace p2p {

namespace server {

// Interface for watching a given directory for files with a given
// file extension.
class FileWatcher {
 public:
  // The type of event used in FileWatchedCallback.
  //
  // kFileAdded
  //  A file has been added.
  //
  // kFileRemoved
  //  A file has been removed.
  //
  // kFileChanged
  //  A file has changed.
  //
  enum EventType { kFileAdded, kFileRemoved, kFileChanged };

  // Type for a callback that is called when a file matching the given
  // extension in the given directory has been added, removed or changed.
  typedef base::RepeatingCallback<void(const base::FilePath& file,
                                       EventType event_type)>
      FileWatcherCallback;

  virtual ~FileWatcher() = default;

  // Gets all files currently matching the given extension.
  virtual const std::vector<base::FilePath>& files() const = 0;

  // Sets the callback function to use for reporting when files
  // matching the given extension has been added, removed or changed.
  // In order to receive callbacks, you need to run the default
  // GLib main-loop.
  virtual void SetChangedCallback(FileWatcherCallback changed_callback) = 0;

  // Gets the directory being monitored.
  virtual const base::FilePath& dir() const = 0;

  // Gets the file extension used for matching files.
  virtual const std::string& file_extension() const = 0;

  // Factory method to get a FileWatcher for watching files in |dir|
  // with the file extension |file_extension|. Returns NULL if
  // initialization fails.
  static FileWatcher* Construct(const base::FilePath& dir,
                                const std::string& file_extension);
};

}  // namespace server

}  // namespace p2p

#endif  // P2P_SERVER_FILE_WATCHER_H_
