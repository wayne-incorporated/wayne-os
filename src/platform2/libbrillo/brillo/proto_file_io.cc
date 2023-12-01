// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/proto_file_io.h"

#include <utility>

#include <base/check.h>
#include <base/files/file.h>
#include <base/logging.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

namespace brillo {

bool ReadTextProtobuf(const base::FilePath& proto_file,
                      google::protobuf::Message* out_proto) {
  DCHECK(out_proto);

  base::File file(proto_file, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!file.IsValid()) {
    DLOG(ERROR) << "Could not open \"" << proto_file.value()
                << "\": " << base::File::ErrorToString(file.error_details());
    return false;
  }

  return ReadTextProtobuf(file.GetPlatformFile(), out_proto);
}

bool ReadTextProtobuf(int fd, google::protobuf::Message* out_proto) {
  google::protobuf::io::FileInputStream input_stream(fd);
  return google::protobuf::TextFormat::Parse(&input_stream, out_proto);
}

bool WriteTextProtobuf(int fd, const google::protobuf::Message& proto) {
  google::protobuf::io::FileOutputStream output_stream(fd);
  return google::protobuf::TextFormat::Print(proto, &output_stream);
}

}  // namespace brillo
