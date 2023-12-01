/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_SCREEN_SPACE_RECT_H_
#define CAMERA_GPU_GLES_SCREEN_SPACE_RECT_H_

#include "gpu/gles/buffer.h"
#include "gpu/gles/vertex_array.h"

namespace cros {

// Helper class for drawing a 2D rectangle. Coordinates used in this class is in
// clip space, with default [-1.0, -1.0] to [1.0, 1.0].
class ScreenSpaceRect {
 public:
  explicit ScreenSpaceRect(float x = -1.0,
                           float y = -1.0,
                           float width = 2.0,
                           float height = 2.0);
  ScreenSpaceRect(const ScreenSpaceRect& other) = delete;
  ScreenSpaceRect(ScreenSpaceRect&& other) = default;
  ScreenSpaceRect& operator=(const ScreenSpaceRect& other) = delete;
  ScreenSpaceRect& operator=(ScreenSpaceRect&& other) = default;
  ~ScreenSpaceRect() = default;

  bool IsValid() const;

  // Sets the rectangle points as the drawing vertices.
  void SetAsVertexInput() const;

  // Draw triangle strips from the vertices.
  void Draw() const;

 private:
  Buffer vertex_buffer_;
  VertexArray vertex_array_;
};

}  // namespace cros

#endif  // CAMERA_GPU_GLES_SCREEN_SPACE_RECT_H_
