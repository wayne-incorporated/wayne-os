// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_PACKET_CAPTURE_TOOL_H_
#define DEBUGD_SRC_PACKET_CAPTURE_TOOL_H_

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_util.h>
#include <brillo/errors/error.h>
#include <brillo/variant_dictionary.h>

#include "debugd/src/subprocess_tool.h"

namespace debugd {

class PacketCaptureTool : public SubprocessTool {
 public:
  PacketCaptureTool() = default;
  PacketCaptureTool(const PacketCaptureTool&) = delete;
  PacketCaptureTool& operator=(const PacketCaptureTool&) = delete;

  ~PacketCaptureTool() override = default;

  // Starts packet capture if the given options are valid. Runs
  // `on_packet_capture_stopped` when the started packet capture process is
  // stopped or terminated.
  bool Start(bool is_dev_mode,
             const base::ScopedFD& status_fd,
             const base::ScopedFD& output_fd,
             const brillo::VariantDictionary& options,
             std::string* out_id,
             base::OnceClosure on_packet_capture_stopped,
             brillo::ErrorPtr* error);

  // Returns false if there are no ongoing packet capture processes.
  bool HasActivePacketCaptureProcess();

 private:
  struct ChildProcessInfo {
    ChildProcessInfo(base::ScopedFD pipe_read_fd_in,
                     std::unique_ptr<base::FileDescriptorWatcher::Controller>
                         pipe_read_watcher_in,
                     base::OnceClosure on_stopped_callback_in)
        : pipe_read_fd(std::move(pipe_read_fd_in)),
          pipe_read_watcher(std::move(pipe_read_watcher_in)),
          on_stopped_callback(std::move(on_stopped_callback_in)) {}
    ~ChildProcessInfo() = default;

    // Move constructor.
    ChildProcessInfo(ChildProcessInfo&& info) {
      pipe_read_fd = std::move(info.pipe_read_fd);
      pipe_read_watcher = std::move(info.pipe_read_watcher);
      on_stopped_callback = std::move(info.on_stopped_callback);
    }

    // Delete the copy constructor.
    ChildProcessInfo(const ChildProcessInfo& child) = delete;

    // The pipe that'll be used to read the status update of the child process.
    base::ScopedFD pipe_read_fd;
    // FileDescriptorWatcher will watch the readable state of the pipe to detect
    // when the child process has ended.
    std::unique_ptr<base::FileDescriptorWatcher::Controller> pipe_read_watcher;
    // The callback that will be run the packet capture process terminates.
    base::OnceClosure on_stopped_callback;
  };

  debugd::ProcessWithId* CreateCaptureProcessForFrequencyBasedCapture(
      const brillo::VariantDictionary& options,
      int output_fd,
      int status_fd,
      brillo::ErrorPtr* error);
  debugd::ProcessWithId* CreateCaptureProcessForDeviceBasedCapture(
      const brillo::VariantDictionary& options,
      int output_fd,
      int status_fd,
      brillo::ErrorPtr* error);

  // Is called when a packet capture helper process has terminated. Checks the
  // ChildProcessInfo of the process with pid `process_handle` and runs
  // `on_packet_capture_stopped_callback`. Sets `hasPacketCaptureRunning_` to
  // false if there are no packet capture processes left running.
  void OnPacketCaptureStopped(std::string process_handle);

  // ProcessWithId::id() -> ChildProcessInfo.
  std::map<std::string, ChildProcessInfo> helper_processes_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_PACKET_CAPTURE_TOOL_H_
