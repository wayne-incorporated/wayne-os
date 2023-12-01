// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_CONTAINER_APPFUSE_DATA_FILTER_H_
#define ARC_CONTAINER_APPFUSE_DATA_FILTER_H_

#include <stdint.h>

#include <deque>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/task/task_runner.h>
#include <base/threading/thread.h>

namespace arc {
namespace appfuse {

// DataFilter verifies input from /dev/fuse and reject unexpected data.
class DataFilter {
 public:
  DataFilter();
  DataFilter(const DataFilter&) = delete;
  DataFilter& operator=(const DataFilter&) = delete;

  ~DataFilter();

  // The given callback will be run when this filter stops.
  void set_on_stopped_callback(base::OnceClosure callback) {
    on_stopped_callback_ = std::move(callback);
  }

  // Starts watching the given /dev/fuse FD and returns a filtered FD.
  base::ScopedFD Start(base::ScopedFD fd_dev);

 private:
  // Starts watching the file descriptors on the watch thread.
  void StartWatching();

  // Aborts watching the file descriptors.
  void AbortWatching();

  // Called when |fd_dev_| gets readable.
  void OnDevReadable();

  // Called when |fd_dev_| gets writable.
  void OnDevWritable();

  // Maybe start or stop watching writable state of |fd_dev_| depending
  // on |pending_data_to_dev_|.
  void UpdateDevWritableWatcher();

  // Called when |fd_socket_| gets readable.
  void OnSocketReadable();

  // Called when |fd_socket_| gets writable.
  void OnSocketWritable();

  // Maybe start or stop watching writable state of |fd_socket_| depending
  // on |pending_data_to_socket_|.
  void UpdateSocketWritableWatcher();

  // Filters data from /dev/fuse and forwards it to the socket.
  bool FilterDataFromDev(std::vector<char>* data);

  // Filters data from the socket and forwards it to /dev/fuse.
  bool FilterDataFromSocket(std::vector<char>* data);

  base::Thread watch_thread_;
  base::ScopedFD fd_dev_;
  base::ScopedFD fd_socket_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller>
      dev_readable_watcher_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller>
      dev_writable_watcher_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller>
      socket_readable_watcher_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller>
      socket_writable_watcher_;

  std::deque<std::vector<char>> pending_data_to_dev_;
  std::deque<std::vector<char>> pending_data_to_socket_;

  std::map<uint64_t, uint32_t> unique_to_opcode_;

  scoped_refptr<base::TaskRunner> origin_task_runner_;
  base::OnceClosure on_stopped_callback_;
};

}  // namespace appfuse
}  // namespace arc

#endif  // ARC_CONTAINER_APPFUSE_DATA_FILTER_H_
