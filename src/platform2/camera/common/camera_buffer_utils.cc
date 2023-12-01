/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "cros-camera/camera_buffer_utils.h"

#include <fstream>
#include <iostream>

#include <base/files/file_util.h>
#include <base/files/memory_mapped_file.h>
#include <drm_fourcc.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/common.h"

namespace cros {

bool ReadFileIntoBuffer(buffer_handle_t buffer, base::FilePath file_to_read) {
  if (!base::PathExists(file_to_read)) {
    LOGF(ERROR) << "File " << file_to_read << " does not exist";
    return false;
  }

  std::ifstream input_file;
  input_file.open(file_to_read.value());
  if (!input_file.is_open()) {
    LOGF(ERROR) << "Failed to load from file: " << file_to_read;
    return false;
  }

  ScopedMapping mapping(buffer);
  if (!mapping.is_valid()) {
    LOGF(ERROR) << "Failed to mmap buffer";
    input_file.close();
    return false;
  }
  size_t total_plane_size = 0;
  for (size_t p = 0; p < mapping.num_planes(); ++p) {
    total_plane_size += mapping.plane(p).size;
  }
  input_file.seekg(0, input_file.end);
  size_t length = input_file.tellg();
  if (length < total_plane_size) {
    LOGF(ERROR) << "File " << file_to_read
                << " does not have enough data to fill the buffer";
    input_file.close();
    return false;
  }

  size_t offset = 0;
  for (size_t p = 0; p < mapping.num_planes(); ++p) {
    input_file.seekg(offset, input_file.beg);
    auto plane = mapping.plane(p);
    input_file.read(reinterpret_cast<char*>(plane.addr), plane.size);
    offset += plane.size;
  }
  input_file.close();

  return true;
}

bool WriteBufferIntoFile(buffer_handle_t buffer, base::FilePath file_to_write) {
  std::ofstream output_file;
  output_file.open(file_to_write.value(), std::ios::binary | std::ios::out);
  if (!output_file.is_open()) {
    LOGF(ERROR) << "Failed to open output file " << file_to_write;
    return false;
  }

  ScopedMapping mapping(buffer);
  if (!mapping.is_valid()) {
    LOGF(ERROR) << "Failed to mmap buffer";
    output_file.close();
    return false;
  }

  for (size_t p = 0; p < mapping.num_planes(); ++p) {
    auto plane = mapping.plane(p);
    output_file.write(reinterpret_cast<char*>(plane.addr), plane.size);
  }
  output_file.close();

  return true;
}

}  // namespace cros
