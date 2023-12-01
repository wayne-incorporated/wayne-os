/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/screen_space_rect.h"

#include <vector>

#include "cros-camera/common.h"
#include "gpu/gles/utils.h"

namespace cros {

namespace {

constexpr size_t kComponentSize = sizeof(float);
constexpr int kNumComponentsPerVertex = 2;
constexpr int kNumVertices = 4;
constexpr GLsizeiptr kBufferSizeBytes =
    kComponentSize * kNumComponentsPerVertex * kNumVertices;

std::vector<float> CreateRawVextexBuffer(float x,
                                         float y,
                                         float width,
                                         float height) {
  std::vector<float> buffer_data(kNumComponentsPerVertex * kNumVertices);
  const float x0 = x, y0 = y, x1 = x + width, y1 = y + height;

  buffer_data[0] = x0;
  buffer_data[1] = y0;

  buffer_data[2] = x0;
  buffer_data[3] = y1;

  buffer_data[4] = x1;
  buffer_data[5] = y0;

  buffer_data[6] = x1;
  buffer_data[7] = y1;

  return buffer_data;
}

Buffer CreateVertexBuffer(float x, float y, float width, float height) {
  std::vector<float> raw_buffer = CreateRawVextexBuffer(x, y, width, height);
  const uint8_t* buffer_as_bytes =
      reinterpret_cast<const uint8_t*>(raw_buffer.data());
  Buffer buffer(kBufferSizeBytes, GL_STATIC_DRAW);
  buffer.Set({buffer_as_bytes, static_cast<size_t>(kBufferSizeBytes)});
  return buffer;
}

}  // namespace

ScreenSpaceRect::ScreenSpaceRect(float x, float y, float width, float height)
    : vertex_buffer_(CreateVertexBuffer(x, y, width, height)),
      vertex_array_({{.index = 0,
                      .num_components = kNumComponentsPerVertex,
                      .type = GL_FLOAT,
                      .normalized = false,
                      .buffer = &vertex_buffer_,
                      .buffer_stride = kComponentSize * kNumComponentsPerVertex,
                      .relative_offset = 0}}) {}

bool ScreenSpaceRect::IsValid() const {
  return vertex_buffer_.IsValid() && vertex_array_.IsValid();
}

void ScreenSpaceRect::SetAsVertexInput() const {
  vertex_array_.Bind();
}

void ScreenSpaceRect::Draw() const {
  glDrawArrays(GL_TRIANGLE_STRIP, 0, kNumVertices);
  GLenum error = glGetError();
  if (error != GL_NO_ERROR) {
    LOGF(ERROR) << "Failed to draw vertex arrays: " << GlGetErrorString(error);
  }
}

}  // namespace cros
