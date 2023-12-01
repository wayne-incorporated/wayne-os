/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/vertex_array.h"

#include <utility>

#include "cros-camera/common.h"
#include "gpu/gles/state_guard.h"

namespace cros {

VertexArray::VertexArray(const std::vector<BindingAttribs>& binding_attribs) {
  glGenVertexArrays(1, &id_);
  if (id_ == 0) {
    LOGF(ERROR) << "Failed to generate vertex array object";
  }

  VertexArrayGuard vertex_array_guard;
  Bind();
  for (const auto& attrib : binding_attribs) {
    attrib.buffer->Bind(Buffer::Target::kArrayBuffer);
    glEnableVertexAttribArray(attrib.index);
    glVertexAttribPointer(attrib.index, attrib.num_components, attrib.type,
                          attrib.normalized, attrib.buffer_stride,
                          reinterpret_cast<void*>(attrib.relative_offset));
  }
}

VertexArray::VertexArray(VertexArray&& other) {
  *this = std::move(other);
}

VertexArray& VertexArray::operator=(VertexArray&& other) {
  if (this != &other) {
    Invalidate();
    id_ = other.id_;
    other.id_ = 0;
  }
  return *this;
}

VertexArray::~VertexArray() {
  Invalidate();
}

void VertexArray::Bind() const {
  glBindVertexArray(id_);
}

// static
void VertexArray::UnbindAll() {
  glBindVertexArray(0);
}

void VertexArray::Invalidate() {
  if (IsValid()) {
    glDeleteVertexArrays(1, &id_);
    id_ = 0;
  }
}

}  // namespace cros
