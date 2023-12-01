/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/buffer.h"

#include <utility>

#include "cros-camera/common.h"
#include "gpu/gles/get.h"

namespace cros {

Buffer::Buffer(GLsizeiptr size, GLenum usage) : size_(size) {
  glGenBuffers(1, &id_);
  if (id_ == 0) {
    LOGF(ERROR) << "Failed to generate buffer";
    return;
  }
  // Randomly picks GL_COPY_READ_BUFFER.
  const GLuint old_id = Get<GLuint>(GL_COPY_READ_BUFFER);
  glBindBuffer(GL_COPY_READ_BUFFER, id_);
  glBufferData(GL_COPY_READ_BUFFER, size, /*data=*/nullptr, usage);
  glBindBuffer(GL_COPY_READ_BUFFER, old_id);
}

Buffer::Buffer(Buffer&& other) {
  *this = std::move(other);
}

Buffer& Buffer::operator=(Buffer&& other) {
  if (this != &other) {
    Invalidate();
    id_ = other.id_;
    size_ = other.size_;
    other.id_ = 0;
    other.size_ = 0;
  }
  return *this;
}

Buffer::~Buffer() {
  Invalidate();
}

void Buffer::Bind(Target target) const {
  glBindBuffer(static_cast<GLenum>(target), id_);
}

// static
void Buffer::UnbindAll(Target target) {
  glBindBuffer(static_cast<GLenum>(target), 0);
}

bool Buffer::Set(base::span<const uint8_t> src, GLintptr dst_offset) const {
  if (!IsValid()) {
    LOGF(ERROR) << "Can't set data to invalid buffer object";
    return false;
  }
  if (dst_offset + src.size() > size_) {
    LOGF(ERROR) << "Data has larger size than the internal buffer";
    return false;
  }
  const GLuint old_id = Get<GLuint>(GL_COPY_READ_BUFFER);
  glBindBuffer(GL_COPY_READ_BUFFER, id_);
  glBufferSubData(GL_COPY_READ_BUFFER, dst_offset, src.size(), src.data());
  glBindBuffer(GL_COPY_READ_BUFFER, old_id);
  return true;
}

void Buffer::Invalidate() {
  if (IsValid()) {
    glDeleteBuffers(1, &id_);
    id_ = 0;
    size_ = 0;
  }
}

}  // namespace cros
