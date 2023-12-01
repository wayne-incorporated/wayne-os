/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_GET_H_
#define CAMERA_GPU_GLES_GET_H_

#include <array>
#include <cstddef>

#include <GLES3/gl3.h>

namespace cros {

// Utility template function to get GL parameters that are known to have a
// single value.
//
// The template has specialization for the following types:
//  - GLboolean
//  - GLfloat
//  - GLint
//  - GLuint
//
// TODO(jcliang): add more type specialization when needed.
template <typename T>
T Get(GLenum pname);

// Utility template function to get GL parameters as an array of GLint.
//
// TODO(jcliang): add more template functions for other GL data types when
// needed (e.g. glGet{Boolean|Float|Integer64}array).
template <typename T, std::size_t N>
std::array<T, N> GetIntArray(GLenum pname);

// Implementation of template functions.

template <std::size_t N>
std::array<GLint, N> GetIntArray(GLenum pname) {
  std::array<GLint, N> result;
  glGetIntegerv(pname, result.data());
  return result;
}

}  // namespace cros

#endif  // CAMERA_GPU_GLES_GET_H_
