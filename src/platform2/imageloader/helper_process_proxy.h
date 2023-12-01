// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGELOADER_HELPER_PROCESS_PROXY_H_
#define IMAGELOADER_HELPER_PROCESS_PROXY_H_

#include <sys/types.h>

#include <memory>
#include <string>
#include <vector>

#include <base/files/scoped_file.h>

#include "imageloader/manifest.h"

// Forward declare classes in sys/socket.h
struct msghdr;

namespace imageloader {

// Forward declare classes in ipc.pb.h
class ImageCommand;
class CommandResponse;

// Tracks a helper subprocess. Handles forking, cleaning up on termination, and
// IPC.
class HelperProcessProxy {
 public:
  HelperProcessProxy() = default;
  HelperProcessProxy(const HelperProcessProxy&) = delete;
  HelperProcessProxy& operator=(const HelperProcessProxy&) = delete;

  virtual ~HelperProcessProxy() = default;

  // Re-execs imageloader with a new argument: "|fd_arg|=N", where N is the side
  // of |control_fd|. This tells the subprocess to start up a different
  // mainloop.
  void Start(int argc, char* argv[], const std::string& fd_arg);

  // Sends a message telling the helper process to mount the file backed by |fd|
  // at the |path|.
  virtual bool SendMountCommand(int fd,
                                const std::string& path,
                                FileSystem fs_type,
                                const std::string& table);

  // Sends a message telling the helper process to enumerate all mount point
  // paths with prefix of |rootpath| and returns them with |paths|. If
  // |dry_run| is true, no mount points are unmounted. If |dry_run| is false,
  // all mount points returned in |paths| are unmounted.
  virtual bool SendUnmountAllCommand(bool dry_run,
                                     const std::string& rootpath,
                                     std::vector<std::string>* paths);

  // Sends a message telling the helper process to umount mount point at
  // |path|.
  virtual bool SendUnmountCommand(const std::string& path);

  const pid_t pid() { return pid_; }

 protected:
  // Waits for a reply from the helper process indicating if the mount succeeded
  // or failed.
  virtual std::unique_ptr<CommandResponse> WaitForResponse();

  pid_t pid_{0};
  base::ScopedFD control_fd_;

 private:
  // Constructs msghdr and sends it.
  virtual std::unique_ptr<CommandResponse> SendCommand(
      const ImageCommand& msg_proto, struct msghdr* msg);
};

}  // namespace imageloader

#endif  // IMAGELOADER_HELPER_PROCESS_PROXY_H_
