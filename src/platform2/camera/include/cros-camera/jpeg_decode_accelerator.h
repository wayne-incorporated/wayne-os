/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_JPEG_DECODE_ACCELERATOR_H_
#define CAMERA_INCLUDE_CROS_CAMERA_JPEG_DECODE_ACCELERATOR_H_

#include <stdint.h>
#include <memory>

#include <base/functional/bind.h>

#include <cutils/native_handle.h>

#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "cros-camera/export.h"

namespace cros {

using DecodeCallback = base::OnceCallback<void(int buffer_id, int error)>;

// Encapsulates a converter from JPEG to YU12 format. This class is not
// thread-safe.
// Before using this class, make sure mojo is initialized first.
class CROS_CAMERA_EXPORT JpegDecodeAccelerator {
 public:
  // Enumeration of decode errors.
  enum class Error {
    // No error. Decode succeeded.
    NO_ERRORS,
    // Invalid argument was passed to an API method, e.g. the output buffer is
    // too small, JPEG width/height are too big for JDA.
    INVALID_ARGUMENT,
    // Encoded input is unreadable, e.g. failed to map on another process.
    UNREADABLE_INPUT,
    // Failed to parse compressed JPEG picture.
    PARSE_JPEG_FAILED,
    // Failed to decode JPEG due to unsupported JPEG features, such as
    // profiles, coding mode, or color formats.
    UNSUPPORTED_JPEG,
    // A fatal failure occurred in the GPU process layer or one of its
    // dependencies. Examples of such failures include hardware failures,
    // driver failures, library failures, browser programming errors, and so
    // on. Client is responsible for destroying JDA after receiving this.
    PLATFORM_FAILURE,
    // Largest used enum. This should be adjusted when new errors are added.
    LARGEST_MOJO_ERROR_ENUM = PLATFORM_FAILURE,
    // The Mojo channel is corrupted. User can call Start() again to establish
    // the channel.
    TRY_START_AGAIN,
    // Create shared memory for input buffer failed.
    CREATE_SHARED_MEMORY_FAILED,
    // mmap() for input failed.
    MMAP_FAILED,
    // No decode response from Mojo channel after timeout.
    NO_DECODE_RESPONSE,
  };

  // [Deprecated]
  static std::unique_ptr<JpegDecodeAccelerator> CreateInstance();

  static std::unique_ptr<JpegDecodeAccelerator> CreateInstance(
      CameraMojoChannelManagerToken* token);

  virtual ~JpegDecodeAccelerator() {}

  // Starts the Jpeg decoder.
  // This method must be called before all the other methods are called.
  //
  // Returns:
  //    Returns true on success otherwise false.
  virtual bool Start() = 0;

  // Decodes |input_fd| that contains a JPEG image of size |input_buffer_size|
  // into |output_buffer|. This API doesn't take ownership of |input_fd| and
  // |output_buffer|.
  //
  // Args:
  //    |input_fd|: Input DMA buffer file descriptor.
  //    |input_buffer_size|: Size of input buffer.
  //    |input_buffer_offset|: Offset of input buffer.
  //    |output_buffer|: Output buffer handle.
  //
  // Returns:
  //    Returns enum Error to notify the decode status.
  //    If the return code is TRY_START_AGAIN, user can call Start() again and
  //    use this API.
  virtual Error DecodeSync(int input_fd,
                           uint32_t input_buffer_size,
                           uint32_t input_buffer_offset,
                           buffer_handle_t output_buffer) = 0;

  // Asynchronous version of DecodeSync.
  //
  // Args:
  //    |input_fd|: Input DMA buffer file descriptor.
  //    |input_buffer_size|: Size of input buffer.
  //    |input_buffer_offset|: Offset of input buffer.
  //    |output_buffer|: Output buffer handle.
  //    |callback|: callback function after finish decoding.
  //
  // Returns:
  //    Returns buffer_id of this Decode.
  virtual int32_t Decode(int input_fd,
                         uint32_t input_buffer_size,
                         uint32_t input_buffer_offset,
                         buffer_handle_t output_buffer,
                         DecodeCallback callback) = 0;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_JPEG_DECODE_ACCELERATOR_H_
