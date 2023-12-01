// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_PROTO_FILE_IO_H_
#define LIBBRILLO_BRILLO_PROTO_FILE_IO_H_

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>
#include <google/protobuf/message.h>

namespace brillo {

// Simple utilities for serializing and deserializing protobufs in
// text format. For an example of the format, see the docs at
// https://developers.google.com/protocol-buffers/docs/overview#whynotxml

BRILLO_EXPORT bool ReadTextProtobuf(const base::FilePath& proto_file,
                                    google::protobuf::Message* out_proto);

BRILLO_EXPORT bool ReadTextProtobuf(int fd,
                                    google::protobuf::Message* out_proto);

BRILLO_EXPORT bool WriteTextProtobuf(int fd,
                                     const google::protobuf::Message& proto);

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_PROTO_FILE_IO_H_
