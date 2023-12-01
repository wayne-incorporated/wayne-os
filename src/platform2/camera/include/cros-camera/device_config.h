/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_DEVICE_CONFIG_H_
#define CAMERA_INCLUDE_CROS_CAMERA_DEVICE_CONFIG_H_

#include <linux/media.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/containers/span.h>
#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>

#include "cros-camera/export.h"

namespace cros {

// The physical transmission interface, or bus, of a camera.
enum class Interface {
  kUsb,
  kMipi,
};

// The direction a camera faces. The definition should match
// camera_metadata_enum_android_lens_facing_t in camera_metadata_tags.h.
enum class LensFacing {
  kFront,
  kBack,
  kExternal,
};

struct EepromIdBlock {
  char os[4];
  uint16_t crc;
  uint8_t version;
  uint8_t length;
  uint16_t data_format;
  uint16_t module_pid;
  char module_vid[2];
  char sensor_vid[2];
  uint16_t sensor_pid;
};

struct EepromInfo {
  EepromIdBlock id_block;
  base::FilePath nvmem_path;
};

struct V4L2SensorInfo {
  std::string name;
  std::string vendor_id;
  base::FilePath subdev_path;
};

struct CrosConfigCameraInfo {
  Interface interface;
  LensFacing facing;
  int orientation;
  bool detachable;
  bool has_privacy_switch;
};

struct PlatformCameraInfo {
  std::optional<EepromInfo> eeprom;
  std::optional<V4L2SensorInfo> v4l2_sensor;
  std::string sysfs_name;

  std::string module_id() const {
    if (!eeprom.has_value()) {
      return "";
    }
    return base::StringPrintf("%c%c%04x", eeprom->id_block.module_vid[0],
                              eeprom->id_block.module_vid[1],
                              eeprom->id_block.module_pid);
  }

  std::string sensor_id() const {
    if (!eeprom.has_value()) {
      return "";
    }
    return base::StringPrintf("%c%c%04x", eeprom->id_block.sensor_vid[0],
                              eeprom->id_block.sensor_vid[1],
                              eeprom->id_block.sensor_pid);
  }
};

// This class wraps the brillo::CrosConfig and stores the required values.
class CROS_CAMERA_EXPORT DeviceConfig {
 public:
  static std::optional<DeviceConfig> Create();

  bool IsV1Device() const { return is_v1_device_; }

  // Gets the model name of the device.
  const std::string& GetModelName() const { return model_name_; }

  // Gets the total number of built-in cameras on the device, or nullopt if the
  // information is not available.
  std::optional<int> GetBuiltInCameraCount() const { return count_; }

  // Gets the total number of cameras on the given |interface|, and is
  // |detachable| if provided. Returns nullopt if the information is not
  // available.
  std::optional<int> GetCameraCount(
      Interface interface, std::optional<bool> detachable = std::nullopt) const;

  // Gets cros_config information from the facing of camera.  Returns null if
  // there's no camera with the facing or the config is not available.
  const CrosConfigCameraInfo* GetCrosConfigInfoFromFacing(
      LensFacing facing) const;

  base::span<const PlatformCameraInfo> GetPlatformCameraInfo();

 private:
  DeviceConfig() = default;

  void ProbeSensorSubdev(struct media_entity_desc* desc,
                         const base::FilePath& path);
  base::FilePath FindSubdevSysfsByDevId(int major, int minor);
  void ProbeMediaController(int media_fd);
  void AddV4L2Sensors();
  void AddCameraEeproms();
  void PopulatePlatformCameraInfo();

  static bool PopulateCrosConfigCameraInfo(DeviceConfig* dev_conf);

  bool is_v1_device_;
  std::string model_name_;

  // The number of built-in cameras, or |std::nullopt| when this information is
  // not available.
  std::optional<int> count_;

  // Detailed topology of the camera devices, or empty when this information is
  // not available. |count_| has value |cros_config_cameras_.size()| if
  // |cros_config_cameras_| is not empty.
  std::vector<CrosConfigCameraInfo> cros_config_cameras_;

  std::optional<std::vector<PlatformCameraInfo>> platform_cameras_;
  std::vector<EepromInfo> eeproms_;
  std::vector<V4L2SensorInfo> v4l2_sensors_;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_DEVICE_CONFIG_H_
