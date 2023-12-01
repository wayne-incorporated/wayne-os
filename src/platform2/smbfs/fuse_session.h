// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_FUSE_SESSION_H_
#define SMBFS_FUSE_SESSION_H_

#include <fuse_lowlevel.h>

#include <memory>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/callback.h>
#include <base/sequence_checker.h>

namespace smbfs {

class Filesystem;

class FuseSession {
 public:
  FuseSession(std::unique_ptr<Filesystem> fs, fuse_chan* chan);
  FuseSession(const FuseSession&) = delete;
  FuseSession& operator=(const FuseSession&) = delete;

  ~FuseSession();

  // Start processing FUSE requests. |stop_callback| is run if the filesystem is
  // disconnected by the kernel.
  bool Start(base::OnceClosure stop_callback);

 private:
  class Impl;

  // Callback for channel FD read watcher.
  void OnChannelReadable();

  // Stops processing FUSE requests and runs the |stop_callback_| provided by
  // Start(). May be be called multiple times, but will only run
  // |stop_callback_| on the first call.
  void RequestStop();

  std::unique_ptr<Impl> impl_;
  fuse_chan* const chan_;
  fuse_session* session_ = nullptr;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> read_watcher_;
  base::OnceClosure stop_callback_;

  // Buffer used for reading and processing fuse requests.
  std::vector<char> read_buffer_;

  base::SequenceChecker sequence_checker_;
};

}  // namespace smbfs

#endif  // SMBFS_FUSE_SESSION_H_
