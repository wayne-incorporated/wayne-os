/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_LIBCAMERA_CONNECTOR_CAMERA_METADATA_UTILS_H_
#define CAMERA_COMMON_LIBCAMERA_CONNECTOR_CAMERA_METADATA_UTILS_H_

#include <base/check_op.h>
#include <base/containers/span.h>

#include "camera/mojo/camera3.mojom.h"
#include "cros-camera/export.h"

namespace cros {

CROS_CAMERA_EXPORT mojom::CameraMetadataEntryPtr* GetMetadataEntry(
    const mojom::CameraMetadataPtr& camera_metadata,
    mojom::CameraMetadataTag tag);

CROS_CAMERA_EXPORT void AddOrUpdateMetadataEntry(
    mojom::CameraMetadataPtr* to, mojom::CameraMetadataEntryPtr entry);

CROS_CAMERA_EXPORT void SetFpsRangeInMetadata(
    mojom::CameraMetadataPtr* settings, int32_t frame_rate);

template <typename T>
CROS_CAMERA_EXPORT base::span<T> GetMetadataEntryAsSpan(
    const mojom::CameraMetadataPtr& camera_metadata,
    mojom::CameraMetadataTag tag) {
  auto* entry = GetMetadataEntry(camera_metadata, tag);
  if (!entry) {
    return {};
  }
  auto& data = (*entry)->data;
  CHECK_EQ(data.size() % sizeof(T), 0u);
  return {reinterpret_cast<T*>(data.data()), data.size() / sizeof(T)};
}

}  // namespace cros

#endif  // CAMERA_COMMON_LIBCAMERA_CONNECTOR_CAMERA_METADATA_UTILS_H_
