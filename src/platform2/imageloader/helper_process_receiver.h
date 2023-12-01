// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGELOADER_HELPER_PROCESS_RECEIVER_H_
#define IMAGELOADER_HELPER_PROCESS_RECEIVER_H_

#include <memory>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <brillo/daemons/daemon.h>

#include "imageloader/ipc.pb.h"
#include "imageloader/verity_mounter.h"

struct cmsghdr;

namespace imageloader {

// Main loop for the Mount helper process.
// This object is used in the subprocess.
class HelperProcessReceiver : public brillo::Daemon {
 public:
  explicit HelperProcessReceiver(base::ScopedFD control_fd);
  HelperProcessReceiver(const HelperProcessReceiver&) = delete;
  HelperProcessReceiver& operator=(const HelperProcessReceiver&) = delete;

  // Helper function defined in helper_process_receiver_fuzzer.cc.
  friend void helper_process_receiver_fuzzer_run(const char*, size_t);

 protected:
  // Overrides Daemon init callback.
  int OnInit() override;

 private:
  void OnCommandReady();
  CommandResponse HandleCommand(const ImageCommand& image_command,
                                struct cmsghdr* cmsg);
  void SendResponse(const CommandResponse& response);

  base::ScopedFD control_fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> controller_;
  int pending_fd_;
  VerityMounter mounter_;
};

}  // namespace imageloader

#endif  // IMAGELOADER_HELPER_PROCESS_RECEIVER_H_
