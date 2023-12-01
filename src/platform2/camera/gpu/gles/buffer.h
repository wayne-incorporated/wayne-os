/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_BUFFER_H_
#define CAMERA_GPU_GLES_BUFFER_H_

#include <array>

#include <GLES3/gl3.h>

#include <base/containers/span.h>

namespace cros {

// A RAII helper class that encapsulates a GL buffer object.
class Buffer {
 public:
  enum class Target : GLenum {
    kArrayBuffer = GL_ARRAY_BUFFER,
    // TODO(jcliang): add more buffer targets when needed.
  };

  // Creates an empty buffer object with size |size| and usage hint |usage|.  To
  // set data into the buffer object, use Set() below.
  explicit Buffer(GLsizeiptr size, GLenum usage = 0);

  Buffer(const Buffer& other) = delete;
  Buffer(Buffer&& other);
  Buffer& operator=(const Buffer& other) = delete;
  Buffer& operator=(Buffer&& other);
  ~Buffer();

  GLuint handle() const { return id_; }
  bool IsValid() const { return id_ != 0; }

  // Binds the buffer to the buffer target |target|.
  void Bind(Target target) const;

  // Unbinds all buffer object on buffer target |target|.
  static void UnbindAll(Target target);

  // Sets the buffer contents with data of |size| bytes from |src|.  The data is
  // copied into the buffer object with |dst_offset| bytes offset.
  bool Set(base::span<const uint8_t> src, GLintptr dst_offset = 0) const;

 private:
  void Invalidate();

  GLuint id_ = 0;
  GLsizeiptr size_ = 0;
};

}  // namespace cros

#endif  // CAMERA_GPU_GLES_BUFFER_H_
