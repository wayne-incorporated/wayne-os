/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_VERTEX_ARRAY_H_
#define CAMERA_GPU_GLES_VERTEX_ARRAY_H_

#include <vector>

#include <GLES3/gl3.h>

#include <base/containers/span.h>

#include "gpu/gles/buffer.h"

namespace cros {

// A RAII helper class that encapsulates a GL vertex array object.
class VertexArray {
 public:
  struct BindingAttribs {
    GLuint index = 0;
    GLint num_components = 0;
    GLenum type = GL_FLOAT;
    bool normalized = false;
    const Buffer* buffer = nullptr;
    GLsizei buffer_stride = 0;
    GLuint relative_offset = 0;
  };

  // Creates a VertexArray with attributes specified in |binding_attribs|.
  explicit VertexArray(const std::vector<BindingAttribs>& binding_attribs);

  VertexArray(const VertexArray& other) = delete;
  VertexArray(VertexArray&& other);
  VertexArray& operator=(const VertexArray& other) = delete;
  VertexArray& operator=(VertexArray&& other);
  ~VertexArray();

  GLuint handle() const { return id_; }
  bool IsValid() const { return id_ != 0; }

  // Binds the VertexArray.
  void Bind() const;
  // Unbinds whatever was bound as the current vertex array.
  static void UnbindAll();

 private:
  void Invalidate();

  GLuint id_;
};

}  // namespace cros

#endif  // CAMERA_GPU_GLES_VERTEX_ARRAY_H_
