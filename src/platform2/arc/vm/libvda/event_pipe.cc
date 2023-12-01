// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/event_pipe.h"

#include <utility>

#include <fcntl.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>

#include "arc/vm/libvda/libvda_decode.h"
#include "arc/vm/libvda/libvda_encode.h"

namespace arc {

namespace {
// This method should only be called on the |event_write_thread| in order to
// write |event|. This is done so that all events are sent in sequence
// (important for PICTURE_READY events), and to ensure that a full write of
// |event| is always done as a single operation. Using the IPC thread was
// considered, but then in cases where the pipe buffer is close to being full,
// write() could block, which would not be acceptable to the IPC thread.
// Setting the pipe to non-blocking mode was also considered, but then
// we would have to re-post a new task to complete the write which could
// cause ordering issues.
template <class T>
void WriteToFd(int fd, const T event) {
  CHECK(base::WriteFileDescriptor(fd,
                                  base::as_bytes(base::make_span(&event, 1u))));
}
}  // namespace

EventPipe::EventPipe() : event_write_thread_("EventWriteThread") {
  int pipe_fds[2];
  CHECK_EQ(pipe2(pipe_fds, O_CLOEXEC), 0);

  event_read_fd_.reset(pipe_fds[0]);
  event_write_fd_.reset(pipe_fds[1]);

  // Start the dedicated event write thread for this session context.
  CHECK(event_write_thread_.Start());
}

EventPipe::~EventPipe() = default;

int EventPipe::GetReadFd() const {
  return event_read_fd_.get();
}

void EventPipe::WriteVdaEvent(const vda_event_t& event) {
  event_write_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&WriteToFd<vda_event_t>, event_write_fd_.get(), event));
}

void EventPipe::WriteVeaEvent(const vea_event_t& event) {
  event_write_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&WriteToFd<vea_event_t>, event_write_fd_.get(), event));
}

}  // namespace arc
