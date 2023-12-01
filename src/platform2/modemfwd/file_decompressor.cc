// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/file_decompressor.h"

#include <lzma.h>
#include <stdint.h>
#include <stdio.h>

#include <memory>

#include <base/files/file.h>
#include <base/logging.h>

namespace modemfwd {

bool DecompressXzFile(const base::FilePath& in_file_path,
                      const base::FilePath& out_file_path) {
  base::File in_file(in_file_path,
                     base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!in_file.IsValid()) {
    PLOG(ERROR) << "Failed to open '" << in_file_path.value() << "' for read";
    return false;
  }

  base::File out_file(out_file_path,
                      base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  if (!out_file.IsValid()) {
    PLOG(ERROR) << "Failed to open '" << out_file_path.value() << "' for write";
    return false;
  }

  lzma_stream stream = LZMA_STREAM_INIT;
  lzma_ret ret = lzma_stream_decoder(&stream, UINT64_MAX, 0);
  if (ret != LZMA_OK) {
    LOG(ERROR) << "Failed initialize LZMA decoder, error=" << ret;
    return false;
  }

  std::unique_ptr<lzma_stream, decltype(&lzma_end)> auto_stream_deleter(
      &stream, &lzma_end);

  lzma_action action = LZMA_RUN;
  const size_t in_buffer_size = BUFSIZ;
  const size_t out_buffer_size = BUFSIZ;
  auto in_buffer = std::make_unique<uint8_t[]>(in_buffer_size);
  auto out_buffer = std::make_unique<uint8_t[]>(out_buffer_size);

  stream.next_in = nullptr;
  stream.avail_in = 0;
  stream.next_out = out_buffer.get();
  stream.avail_out = out_buffer_size;

  for (;;) {
    if (stream.avail_in == 0) {
      int read_ret = in_file.ReadAtCurrentPos(
          reinterpret_cast<char*>(in_buffer.get()), in_buffer_size);
      if (read_ret < 0) {
        PLOG(ERROR) << "Failed to read from '" << out_file_path.value() << "'";
        return false;
      }

      if (read_ret == 0)
        action = LZMA_FINISH;

      stream.next_in = in_buffer.get();
      stream.avail_in = read_ret;
    }

    ret = lzma_code(&stream, action);

    // Flushes the decoded data from the output buffer to the output file.
    if (stream.avail_out == 0 || ret == LZMA_STREAM_END) {
      size_t write_size = out_buffer_size - stream.avail_out;
      if (out_file.WriteAtCurrentPos(reinterpret_cast<char*>(out_buffer.get()),
                                     write_size) !=
          static_cast<int>(write_size)) {
        PLOG(ERROR) << "Failed to write to '" << out_file_path.value() << "'";
        return false;
      }

      stream.next_out = out_buffer.get();
      stream.avail_out = out_buffer_size;
    }

    // A LZMA_STREAM_END return value indicates that the stream has been
    // decoded successfully.
    if (ret == LZMA_STREAM_END)
      break;

    // Otherwise, a return value other than LZMA_OK indicates an error.
    if (ret != LZMA_OK) {
      LOG(ERROR) << "Failed to decompress '" << in_file_path.value()
                 << "', error=" << ret;
      return false;
    }
  }

  return true;
}

}  // namespace modemfwd
