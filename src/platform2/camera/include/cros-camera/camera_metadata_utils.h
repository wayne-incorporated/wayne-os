/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CAMERA_METADATA_UTILS_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CAMERA_METADATA_UTILS_H_

#include <base/containers/span.h>
#include <base/numerics/safe_conversions.h>
#include <optional>
#include <system/camera_metadata.h>

// Utility template functions for accessing and modifying the contents of a
// camera_metadata_t object.

namespace cros {

struct Rational : public camera_metadata_rational_t {
  // Members inherited from camera_metadata_rational_t:
  //
  // int32_t numerator;
  // int32_t denominator;

  float AsFloat() { return base::checked_cast<float>(numerator) / denominator; }
  double AsDouble() {
    return base::checked_cast<double>(numerator) / denominator;
  }
};

// Gets the address of a single data element for |tag| in |metadata|.  Returns
// std::nullopt if |metadata| does not store any data for |tag|.
template <typename T>
std::optional<T*> GetMetadata(camera_metadata_t* metadata, uint32_t tag) {
  camera_metadata_entry_t entry;
  int ret = find_camera_metadata_entry(metadata, tag, &entry);
  if (ret != 0 || entry.count == 0) {
    return std::nullopt;
  }
  CHECK_EQ(camera_metadata_type_size[entry.type], sizeof(T));
  return reinterpret_cast<T*>(entry.data.u8);
}

// Gets a read-write view of the data array of |tag| in |metadata|.  Returns an
// empty base::span<T> if |metadata| does not have a data array for |tag|.
template <typename T>
base::span<T> GetMetadataAsSpan(camera_metadata_t* metadata, uint32_t tag) {
  camera_metadata_entry_t entry;
  int ret = find_camera_metadata_entry(metadata, tag, &entry);
  if (ret != 0 || entry.count == 0) {
    return base::span<T>();
  }
  CHECK_EQ(camera_metadata_type_size[entry.type], sizeof(T));
  return {reinterpret_cast<T*>(entry.data.u8), entry.count};
}

// Gets the value of |tag| data in |metadata|.  Returns std::nullopt if
// |metadata| does not store any data for |tag|.
template <typename T>
std::optional<T> GetRoMetadata(const camera_metadata_t* metadata,
                               uint32_t tag) {
  camera_metadata_ro_entry_t ro_entry;
  int ret = find_camera_metadata_ro_entry(metadata, tag, &ro_entry);
  if (ret != 0 || ro_entry.count == 0) {
    return std::nullopt;
  }
  CHECK_EQ(camera_metadata_type_size[ro_entry.type], sizeof(T));
  return *(reinterpret_cast<const T*>(ro_entry.data.u8));
}

// Gets a read-only view of the data array of |tag| in |metadata|.  Returns an
// empty base::span<const T> if |metadata| does not have a data array for |tag|.
template <typename T>
base::span<const T> GetRoMetadataAsSpan(const camera_metadata_t* metadata,
                                        uint32_t tag) {
  camera_metadata_ro_entry_t ro_entry;
  int ret = find_camera_metadata_ro_entry(metadata, tag, &ro_entry);
  if (ret != 0 || ro_entry.count == 0) {
    return base::span<const T>();
  }
  CHECK_EQ(camera_metadata_type_size[ro_entry.type], sizeof(T));
  return {reinterpret_cast<const T*>(ro_entry.data.u8), ro_entry.count};
}

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_CAMERA_METADATA_UTILS_H_
