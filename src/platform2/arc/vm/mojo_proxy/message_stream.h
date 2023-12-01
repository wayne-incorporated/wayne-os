// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_MOJO_PROXY_MESSAGE_STREAM_H_
#define ARC_VM_MOJO_PROXY_MESSAGE_STREAM_H_

#include <vector>

#include <base/files/scoped_file.h>

#include "arc/vm/mojo_proxy/message.pb.h"

namespace arc {

// MessageStream exchanges messages with the other proxy process.
class MessageStream {
 public:
  explicit MessageStream(base::ScopedFD fd);
  MessageStream(const MessageStream&) = delete;
  MessageStream& operator=(const MessageStream&) = delete;

  ~MessageStream();

  // Returns the raw file descriptor.
  int Get() const { return fd_.get(); }

  // Reads the message from the socket. Returns true and stores the read
  // message and FDs into |message| and |fds| on success. Otherwise false.
  bool Read(arc_proxy::MojoMessage* message, std::vector<base::ScopedFD>* fds);

  // Writes the serialized |message| to the socket.
  // Returns true iff the whole message is written.
  bool Write(const arc_proxy::MojoMessage& message,
             const std::vector<base::ScopedFD>& fds);

 private:
  base::ScopedFD fd_;
  std::vector<char> buf_;
};

}  // namespace arc

#endif  // ARC_VM_MOJO_PROXY_MESSAGE_STREAM_H_
