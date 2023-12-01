// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_PROTOBUF_LITE_STREAMS_H_
#define SHILL_PROTOBUF_LITE_STREAMS_H_

#include <string>

#include <base/files/scoped_file.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

// Some basic input/output streams are not implemented for protobuf-lite.

namespace shill {

// Attempts to create a |google::protobuf::io::CopyingInputStreamAdaptor| using
// a |shill::ProtobufLiteCopyingFileInputStream|. Returns a new instance on
// success. The caller owns the new instance, and must free it when done.
// Returns nullptr on failure.
google::protobuf::io::CopyingInputStreamAdaptor*
protobuf_lite_file_input_stream(const std::string& file_path);

class ProtobufLiteCopyingFileInputStream
    : public google::protobuf::io::CopyingInputStream {
 public:
  // Takes ownership of |fd| and closes it when the object is deleted.
  explicit ProtobufLiteCopyingFileInputStream(int fd);
  ProtobufLiteCopyingFileInputStream(
      const ProtobufLiteCopyingFileInputStream&) = delete;
  ProtobufLiteCopyingFileInputStream& operator=(
      const ProtobufLiteCopyingFileInputStream&) = delete;

  ~ProtobufLiteCopyingFileInputStream() override;
  int Read(void* buffer, int size) override;
  int Skip(int count) override;

 private:
  int fd_;
  base::ScopedFD scoped_fd_closer_;
  bool previous_seek_failed_;
};

}  // namespace shill

#endif  // SHILL_PROTOBUF_LITE_STREAMS_H_
