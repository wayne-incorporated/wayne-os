/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_Y4M_FAKE_STREAM_H_
#define CAMERA_HAL_FAKE_Y4M_FAKE_STREAM_H_

#include <memory>
#include <string>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/strings/string_piece.h>

#include "cros-camera/common_types.h"
#include "hal/fake/fake_stream.h"

namespace cros {

// Y4mFakeStream reads a y4m video file and loop the frames from the video as
// camera frames.
class Y4mFakeStream : public FakeStream {
 protected:
  friend class FakeStream;
  explicit Y4mFakeStream(const base::FilePath& file_path, ScaleMode scale_mode);

  [[nodiscard]] bool Initialize(Size size, const FramesSpec& spec) override;

  [[nodiscard]] bool FillBuffer(buffer_handle_t buffer) override;

 private:
  // Parse the Y4M header, verify the format is supported and fill
  // |video_size_|.
  [[nodiscard]] bool ParseY4mHeader(const std::string& header);

  // Read the next frame in I420 format.
  std::unique_ptr<FrameBuffer> ReadNextFrameI420();

  // Path of the Y4M video.
  base::FilePath file_path_;

  // Opened file handle of the Y4M video.
  base::File file_;

  // Frame size of the Y4M video.
  Size video_size_;

  // How each frame should be scaled to the output size.
  ScaleMode scale_mode_;

  // The byte offset in the video file of the first frame.
  size_t first_frame_byte_index_;
};

}  // namespace cros

#endif  // CAMERA_HAL_FAKE_Y4M_FAKE_STREAM_H_
