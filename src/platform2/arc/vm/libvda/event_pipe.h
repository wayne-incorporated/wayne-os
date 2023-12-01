// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_EVENT_PIPE_H_
#define ARC_VM_LIBVDA_EVENT_PIPE_H_

#include <base/files/scoped_file.h>
#include <base/threading/thread.h>

typedef struct vda_event vda_event_t;
typedef struct vea_event vea_event_t;

namespace arc {

// EventPipe is responsible for creating a pipe and a corresponding
// thread for atomic writes.
class EventPipe {
 public:
  EventPipe();
  EventPipe(const EventPipe&) = delete;
  EventPipe& operator=(const EventPipe&) = delete;

  ~EventPipe();

  // Returns the read-only endpoint of the event pipe file descriptor.
  int GetReadFd() const;

  // Writes a VDA event to the event pipe. Atomic writes are
  // guaranteed as writes are marshalled onto its own thread.
  void WriteVdaEvent(const vda_event_t& event);

  // Writes a VEA event to the event pipe. Atomic writes are
  // guaranteed as writes are marshalled onto its own thread.
  void WriteVeaEvent(const vea_event_t& event);

 private:
  base::ScopedFD event_read_fd_;
  base::ScopedFD event_write_fd_;

  base::Thread event_write_thread_;
};

}  // namespace arc

#endif  // ARC_VM_LIBVDA_EVENT_PIPE_H_
