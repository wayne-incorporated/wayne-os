// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_capabilities/camera.h"

#include <fcntl.h>
#include <linux/media.h>
#include <linux/videodev2.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>

#include "media_capabilities/common.h"

namespace {

enum class CameraType {
  kUnknown,
  kUVC,
  kVivid,
};

CameraType GetCameraType(int device_fd) {
  struct v4l2_capability cap;
  memset(&cap, 0, sizeof(cap));

  if (Ioctl(device_fd, VIDIOC_QUERYCAP, &cap))
    return CameraType::kUnknown;
  if (strcmp((const char*)cap.driver, "uvcvideo") == 0)
    return CameraType::kUVC;
  if (strcmp((const char*)cap.driver, "vivid") == 0)
    return CameraType::kVivid;

  return CameraType::kUnknown;
}

bool IsBuiltinMipiCamera(int device_fd) {
  struct media_entity_desc desc;
  memset(&desc, 0, sizeof(desc));

  for (desc.id = MEDIA_ENT_ID_FLAG_NEXT;
       !Ioctl(device_fd, MEDIA_IOC_ENUM_ENTITIES, &desc);
       desc.id |= MEDIA_ENT_ID_FLAG_NEXT) {
    if (desc.type == MEDIA_ENT_T_V4L2_SUBDEV_SENSOR)
      return true;
  }
  return false;
}

bool IsBuiltinUSBCamera(int device_fd, const base::FilePath& device_path) {
  if (GetCameraType(device_fd) != CameraType::kUVC)
    return false;
  const base::FilePath base_name = device_path.BaseName();
  if (base_name.empty()) {
    LOG(ERROR) << "base file is empty, path=" << device_path;
    return false;
  }

  const base::FilePath vendorid_path = base::FilePath("/sys/class/video4linux/")
                                           .Append(base_name)
                                           .Append("device/../idVendor");
  base::FilePath normalized_vendorid_path;
  if (!base::NormalizeFilePath(vendorid_path, &normalized_vendorid_path)) {
    LOG(ERROR) << "Failed to normalize vendor id path: " << vendorid_path;
    return false;
  }
  std::string vendor_id;
  if (!base::ReadFileToString(normalized_vendorid_path, &vendor_id)) {
    LOG(ERROR) << "Failed to read vendor id file: " << normalized_vendorid_path;
    return false;
  }

  // Check if the camera is not an external one. The vendor IDs of external
  // cameras used in the lab need to be listed here. If there are many kinds of
  // external cameras, we might want to have a list of vid:pid of builtin
  // cameras instead.
  const char* kExternalCameraVendorIds[] = {
      "046d",  // Logitech
      "2bd9",  // Huddly GO
  };

  for (const char* external_vendor_id : kExternalCameraVendorIds) {
    if (vendor_id == external_vendor_id)
      return false;
  }

  return true;
}

bool IsVividCamera(int device_fd) {
  if (GetCameraType(device_fd) != CameraType::kVivid)
    return false;

  struct v4l2_capability cap;
  memset(&cap, 0, sizeof(cap));
  if (Ioctl(device_fd, VIDIOC_QUERYCAP, &cap)) {
    PLOG(FATAL) << "VIDIOC_QUERYCAP failed: ";
    return false;
  }

  // Check if vivid is emulating a video capture device.
  const uint32_t mask = cap.capabilities;
  constexpr uint32_t kCaptureMask =
      V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_VIDEO_CAPTURE_MPLANE;
  constexpr uint32_t kOutputMask =
      V4L2_CAP_VIDEO_OUTPUT | V4L2_CAP_VIDEO_OUTPUT_MPLANE;
  constexpr uint32_t kM2mMask = V4L2_CAP_VIDEO_M2M | V4L2_CAP_VIDEO_M2M_MPLANE;

  return (mask & kCaptureMask) && !(mask & kOutputMask) && !(mask & kM2mMask);
}
}  // namespace

std::vector<Capability> DetectCameraCapabilities() {
  const base::FilePath kVideoDeviceName("/dev/video");
  bool has_builtin_usb_camera = false;
  bool has_vivid_camera = false;
  for (const base::FilePath& path : GetAllFilesWithPrefix(kVideoDeviceName)) {
    base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ |
                              base::File::FLAG_WRITE);
    if (!file.IsValid())
      continue;
    const int fd = file.GetPlatformFile();
    has_builtin_usb_camera |= IsBuiltinUSBCamera(fd, path);
    has_vivid_camera |= IsVividCamera(fd);
  }

  const base::FilePath kMediaDeviceName("/dev/media");
  bool has_builtin_mipi_camera = false;
  for (const base::FilePath& path : GetAllFilesWithPrefix(kMediaDeviceName)) {
    base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ |
                              base::File::FLAG_WRITE);
    if (!file.IsValid())
      continue;
    const int fd = file.GetPlatformFile();
    has_builtin_mipi_camera |= IsBuiltinMipiCamera(fd);
  }

  std::vector<Capability> capabilities;
  if (has_builtin_usb_camera)
    capabilities.push_back(Capability(CameraDescription::kBuiltinUSBCamera));
  if (has_builtin_mipi_camera)
    capabilities.push_back(Capability(CameraDescription::kBuiltinMIPICamera));
  if (has_vivid_camera)
    capabilities.push_back(Capability(CameraDescription::kVividCamera));
  if (has_builtin_mipi_camera || has_builtin_usb_camera)
    capabilities.push_back(Capability(CameraDescription::kBuiltinCamera));
  if (has_builtin_mipi_camera || has_builtin_usb_camera || has_vivid_camera) {
    capabilities.push_back(
        Capability(CameraDescription::kBuiltinOrVividCamera));
  }
  return capabilities;
}
