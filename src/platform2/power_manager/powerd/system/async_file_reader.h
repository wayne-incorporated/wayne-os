// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_ASYNC_FILE_READER_H_
#define POWER_MANAGER_POWERD_SYSTEM_ASYNC_FILE_READER_H_

#include <aio.h>
#include <unistd.h>

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/timer/timer.h>

namespace power_manager::system {

class AsyncFileReader {
 public:
  AsyncFileReader();
  AsyncFileReader(const AsyncFileReader&) = delete;
  AsyncFileReader& operator=(const AsyncFileReader&) = delete;

  ~AsyncFileReader();

  const base::FilePath& path() const { return path_; }

  void set_initial_read_size_for_testing(size_t size) {
    initial_read_size_ = size;
  }

  // Read file asynchronously, passing its contents to |read_cb| when done.
  // Invokes |error_cb| on failure. If a read is already in progress, abort it
  // first.  Note that |error_cb| may be invoked synchronously.
  void StartRead(base::OnceCallback<void(const std::string&)> read_cb,
                 base::OnceCallback<void()> error_cb);

  // The file reader will open a file handle and keep it open even over
  // repeated reads.
  bool Init(const base::FilePath& path);

  // Indicates whether a file handle has been opened.
  bool HasOpenedFile() const;

 private:
  friend class AsyncFileReaderTest;

  // Updates the state based on whether there is an ongoing file I/O.
  void UpdateState();

  // Goes back to the idle state, cleans up allocated resources.
  void Reset();

  // Initiates an AIO read operation.  This is a helper function for
  // StartRead().  Returns true if the AIO read was successfully enqueued.
  bool AsyncRead(int size, int offset);

  // Deletes |update_state_timeout_id_|'s timeout and resets it to 0 if set.
  void CancelUpdateStateTimeout();

  // Flag indicating whether there is an active AIO read.
  bool read_in_progress_ = false;

  // AIO control object.
  aiocb aio_control_;

  // Path to file to read.
  base::FilePath path_;

  // File for AIO reads.
  int fd_ = -1;

  // Buffer for AIO reads.
  std::unique_ptr<char[]> aio_buffer_;

  // Number of bytes to be read for the first chunk.  This is a variable instead
  // of a constant so unit tests can modify it.
  size_t initial_read_size_;

  // Accumulator for data read by AIO.
  std::string stored_data_;

  // Unique identifier for this object for joining async operations with trace
  // flow events.
  uint64_t trace_id_ = 0;

  // Callbacks invoked when the read completes or encounters an error.
  base::OnceCallback<void(const std::string&)> read_cb_;
  base::OnceCallback<void()> error_cb_;

  // Runs UpdateState().
  base::RepeatingTimer update_state_timer_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_ASYNC_FILE_READER_H_
