/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_IP_METADATA_HANDLER_H_
#define CAMERA_HAL_IP_METADATA_HANDLER_H_

#include <string>
#include <vector>

#include <camera/camera_metadata.h>

#include "camera/mojo/ip/ip_camera.mojom.h"

namespace cros {

class MetadataHandler {
 public:
  MetadataHandler();
  MetadataHandler(const MetadataHandler&) = delete;
  MetadataHandler& operator=(const MetadataHandler&) = delete;

  ~MetadataHandler();

  // The caller is responsible for freeing the memory returned
  static android::CameraMetadata CreateStaticMetadata(
      const std::string& ip,
      const std::string& name,
      int format,
      double fps,
      const std::vector<mojom::IpCameraStreamPtr>& streams);

  static camera_metadata_t* GetDefaultRequestSettings();
  static void AddResultMetadata(android::CameraMetadata* metadata);
};

}  // namespace cros

#endif  // CAMERA_HAL_IP_METADATA_HANDLER_H_
