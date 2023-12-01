// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/helper_process_receiver.h"

#include <sys/socket.h>
#include <sys/types.h>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/posix/unix_domain_socket.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

#include "imageloader/ipc.pb.h"

namespace imageloader {

void helper_process_receiver_fuzzer_run(const char* data, size_t size) {
  int socket_pair[2];
  socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, socket_pair);
  base::ScopedFD reader_fd(socket_pair[0]);
  base::ScopedFD writer_fd(socket_pair[1]);

  imageloader::HelperProcessReceiver helper_process_receiver(
      std::move(reader_fd));

  if (size == 0) {
    // Per recvmsg(2), the return value will be 0 when the peer has performed an
    // orderly shutdown.
    // This causes current fuzzer process to exit permanently.
    return;
  }

  base::ScopedTempDir temp_dir;
  if (!temp_dir.CreateUniqueTempDir()) {
    LOG(ERROR) << "Failed to create temporary directory.";
    return;
  }

  // Create temporary file to ingest as payload into control message.
  base::FilePath temp_file;
  base::ScopedFD fd =
      CreateAndOpenFdForTemporaryFileInDir(temp_dir.GetPath(), &temp_file);
  if (!fd.is_valid()) {
    LOG(ERROR) << "Failed to create temporary file.";
    return;
  }

  if (!base::UnixDomainSocket::SendMsg(writer_fd.get(), data, size,
                                       {fd.get()})) {
    LOG(ERROR) << "Failed to send all data over socket.";
    return;
  }
  helper_process_receiver.OnCommandReady();
}

}  // namespace imageloader

DEFINE_PROTO_FUZZER(const imageloader::ImageCommand& input) {
  std::vector<char> msg_buf(input.ByteSizeLong());
  if (!input.SerializeToArray(msg_buf.data(), msg_buf.size()))
    LOG(FATAL) << "error serializing protobuf";
  imageloader::helper_process_receiver_fuzzer_run(msg_buf.data(),
                                                  msg_buf.size());
}
