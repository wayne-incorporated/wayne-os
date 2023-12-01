/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "cros-camera/device_config.h"

#include <sys/ioctl.h>

#include <algorithm>
#include <optional>

#include <base/containers/span.h>
#include <base/files/file_util.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <chromeos-config/libcros_config/cros_config.h>

#include "base/containers/contains.h"
#include "cros-camera/common.h"

namespace cros {

namespace {

uint16_t const kCrc16CcittFalseTable[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108,
    0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF, 0x1231, 0x0210,
    0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6, 0x9339, 0x8318, 0xB37B,
    0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE, 0x2462, 0x3443, 0x0420, 0x1401,
    0x64E6, 0x74C7, 0x44A4, 0x5485, 0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE,
    0xF5CF, 0xC5AC, 0xD58D, 0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6,
    0x5695, 0x46B4, 0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D,
    0xC7BC, 0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B, 0x5AF5,
    0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12, 0xDBFD, 0xCBDC,
    0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A, 0x6CA6, 0x7C87, 0x4CE4,
    0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41, 0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD,
    0xAD2A, 0xBD0B, 0x8D68, 0x9D49, 0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13,
    0x2E32, 0x1E51, 0x0E70, 0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A,
    0x9F59, 0x8F78, 0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E,
    0xE16F, 0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E, 0x02B1,
    0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256, 0xB5EA, 0xA5CB,
    0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D, 0x34E2, 0x24C3, 0x14A0,
    0x0481, 0x7466, 0x6447, 0x5424, 0x4405, 0xA7DB, 0xB7FA, 0x8799, 0x97B8,
    0xE75F, 0xF77E, 0xC71D, 0xD73C, 0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657,
    0x7676, 0x4615, 0x5634, 0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9,
    0xB98A, 0xA9AB, 0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882,
    0x28A3, 0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92, 0xFD2E,
    0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9, 0x7C26, 0x6C07,
    0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1, 0xEF1F, 0xFF3E, 0xCF5D,
    0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8, 0x6E17, 0x7E36, 0x4E55, 0x5E74,
    0x2E93, 0x3EB2, 0x0ED1, 0x1EF0,
};

uint16_t Crc16CcittFalse(base::span<const uint8_t> buf, uint16_t init) {
  uint16_t crc = init;
  for (uint8_t b : buf) {
    crc = (crc << 8) ^ kCrc16CcittFalseTable[(crc >> 8) ^ b];
  }
  return crc;
}

constexpr char kCrosConfigCameraPath[] = "/camera";
constexpr char kCrosConfigLegacyUsbKey[] = "legacy-usb";

constexpr char kSysfsV4lClassRoot[] = "/sys/class/video4linux";
constexpr char kSysfsNvmemDevicesRoot[] = "/sys/bus/nvmem/devices";
constexpr char kSysfsI2cDevicesRoot[] = "/sys/bus/i2c/devices";
constexpr char kVendorIdPath[] = "device/vendor_id";
constexpr size_t kEepromIdBlockAlignment = 32u;

bool ValidateCameraModuleInfo(base::span<const uint8_t> section) {
  if (section.size() < sizeof(EepromIdBlock)) {
    return false;
  }
  auto* info = reinterpret_cast<const EepromIdBlock*>(section.data());
  const uint16_t crc =
      Crc16CcittFalse(section.subspan(offsetof(EepromIdBlock, version)), 0u);
  return strncmp(info->os, "CrOS", 4) == 0 && info->crc == crc &&
         info->version == 1u;
}

std::optional<EepromIdBlock> FindCameraEepromIdBlock(const std::string& mem) {
  static_assert(sizeof(EepromIdBlock) <= kEepromIdBlockAlignment);
  const size_t alignment = kEepromIdBlockAlignment;
  const uint8_t* data_end =
      reinterpret_cast<const uint8_t*>(mem.data()) + mem.size();
  for (size_t offset_from_end = alignment + mem.size() % alignment;
       offset_from_end <= mem.size(); offset_from_end += alignment) {
    base::span<const uint8_t> section =
        base::make_span(data_end - offset_from_end, sizeof(EepromIdBlock));
    if (ValidateCameraModuleInfo(section)) {
      return *reinterpret_cast<const EepromIdBlock*>(section.data());
    }
  }
  return std::nullopt;
}

}  // namespace

std::optional<DeviceConfig> DeviceConfig::Create() {
  DeviceConfig res = {};

  if (!PopulateCrosConfigCameraInfo(&res)) {
    return std::nullopt;
  }

  return std::make_optional<DeviceConfig>(res);
}

std::optional<int> DeviceConfig::GetCameraCount(
    Interface interface, std::optional<bool> detachable) const {
  if (!count_.has_value())
    return std::nullopt;
  // |count_| includes both MIPI and USB cameras. If |count_| is not 0, we need
  // the |cros_config_camera_devices_| information to determine the numbers.
  if (*count_ == 0)
    return 0;
  if (cros_config_cameras_.empty())
    return std::nullopt;
  return std::count_if(
      cros_config_cameras_.begin(), cros_config_cameras_.end(),
      [=](const CrosConfigCameraInfo& d) {
        return d.interface == interface &&
               (!detachable.has_value() || d.detachable == *detachable);
      });
}

const CrosConfigCameraInfo* DeviceConfig::GetCrosConfigInfoFromFacing(
    LensFacing facing) const {
  auto iter = std::find_if(
      cros_config_cameras_.begin(), cros_config_cameras_.end(),
      [=](const CrosConfigCameraInfo& d) { return d.facing == facing; });
  return iter != cros_config_cameras_.end() ? &*iter : nullptr;
}

base::span<const PlatformCameraInfo> DeviceConfig::GetPlatformCameraInfo() {
  if (!platform_cameras_.has_value()) {
    platform_cameras_.emplace();
    PopulatePlatformCameraInfo();
  }
  return *platform_cameras_;
}

void DeviceConfig::ProbeSensorSubdev(struct media_entity_desc* desc,
                                     const base::FilePath& path) {
  V4L2SensorInfo sensor{.name = desc->name};
  std::string vendor_id;
  const base::FilePath& vendor_id_path = path.Append(kVendorIdPath);
  if (base::ReadFileToStringWithMaxSize(vendor_id_path, &vendor_id, 64)) {
    base::TrimWhitespaceASCII(vendor_id, base::TRIM_ALL, &sensor.vendor_id);
  }
  sensor.subdev_path = base::MakeAbsoluteFilePath(path);
  LOG(INFO) << "Found V4L2 sensor subdev on " << sensor.subdev_path;

  v4l2_sensors_.emplace_back(std::move(sensor));
}

base::FilePath DeviceConfig::FindSubdevSysfsByDevId(int major, int minor) {
  base::FileEnumerator dev_enum(base::FilePath(kSysfsV4lClassRoot), false,
                                base::FileEnumerator::DIRECTORIES,
                                "v4l-subdev*");
  for (base::FilePath name = dev_enum.Next(); !name.empty();
       name = dev_enum.Next()) {
    base::FilePath dev_path = name.Append("dev");
    std::string dev_id("255:255");
    if (!base::ReadFileToStringWithMaxSize(dev_path, &dev_id, dev_id.size())) {
      LOG(ERROR) << "Failed to read device ID of '" << dev_path.value()
                 << "' from sysfs";
      continue;
    }
    base::TrimWhitespaceASCII(dev_id, base::TRIM_ALL, &dev_id);

    std::ostringstream stream;
    stream << major << ":" << minor;
    if (dev_id == stream.str())
      return name;
  }

  return base::FilePath();
}

void DeviceConfig::ProbeMediaController(int media_fd) {
  struct media_entity_desc desc;

  for (desc.id = MEDIA_ENT_ID_FLAG_NEXT;
       !ioctl(media_fd, MEDIA_IOC_ENUM_ENTITIES, &desc);
       desc.id |= MEDIA_ENT_ID_FLAG_NEXT) {
    if (desc.type != MEDIA_ENT_T_V4L2_SUBDEV_SENSOR)
      continue;

    const base::FilePath& path =
        FindSubdevSysfsByDevId(desc.dev.major, desc.dev.minor);
    if (path.empty()) {
      LOG(ERROR) << "v4l-subdev node for sensor '" << desc.name
                 << "' not found";
      continue;
    }

    LOG(INFO) << "Probing sensor '" << desc.name << "' ("
              << path.BaseName().value() << ")";
    ProbeSensorSubdev(&desc, path);
  }
}

void DeviceConfig::AddV4L2Sensors() {
  base::FileEnumerator dev_enum(base::FilePath("/dev"), false,
                                base::FileEnumerator::FILES, "media*");
  for (base::FilePath name = dev_enum.Next(); !name.empty();
       name = dev_enum.Next()) {
    auto fd = base::ScopedFD(open(name.value().c_str(), O_RDWR));
    if (!fd.is_valid()) {
      LOG(ERROR) << "Failed to open '" << name.value() << "'";
      continue;
    }

    media_device_info info = {};
    if (ioctl(fd.get(), MEDIA_IOC_DEVICE_INFO, &info) != 0) {
      PLOG(ERROR) << "Failed to get media device info on " << name;
      continue;
    }
    if (strcmp(info.driver, "uvcvideo") == 0) {
      continue;
    }

    LOG(INFO) << "Probing media device '" << name.value() << "'";
    ProbeMediaController(fd.get());
  }
}

void DeviceConfig::AddCameraEeproms() {
  auto read_eeprom =
      [&](base::FilePath from_path) -> std::optional<EepromIdBlock> {
    std::string content;
    if (!base::ReadFileToString(from_path, &content)) {
      return std::nullopt;
    }
    std::optional<EepromIdBlock> id_block = FindCameraEepromIdBlock(content);
    if (!id_block.has_value()) {
      // Not a camera EEPROM. Ignore the device.
      return std::nullopt;
    }
    LOG(INFO) << "Read camera eeprom from " << from_path;
    return id_block;
  };

  // Try finding the EEPROM file corresponding to the given |nvmem_path| by
  // matching the devname.
  auto locate_eeprom_file =
      [](base::FilePath nvmem_path) -> std::optional<base::FilePath> {
    // sysfs device name is of the form "<major devname>:<minor devname>". We
    // only want to match the major devname because the minor devname can be
    // different on the nvmem and i2c buses.
    auto get_major_name = [](std::string bus_device_name) -> std::string {
      return base::SplitString(bus_device_name, ":", base::TRIM_WHITESPACE,
                               base::SPLIT_WANT_NONEMPTY)[0];
    };
    std::string devname = get_major_name(nvmem_path.BaseName().value());
    base::FileEnumerator dev_enum(base::FilePath(kSysfsI2cDevicesRoot), false,
                                  base::FileEnumerator::DIRECTORIES);
    for (base::FilePath dev_path = dev_enum.Next(); !dev_path.empty();
         dev_path = dev_enum.Next()) {
      if (get_major_name(dev_path.BaseName().value()) == devname) {
        base::FilePath eeprom_path = dev_path.Append("eeprom");
        if (base::PathExists(eeprom_path)) {
          return eeprom_path;
        }
      }
    }
    return std::nullopt;
  };

  base::FileEnumerator dev_enum(base::FilePath(kSysfsNvmemDevicesRoot), false,
                                base::FileEnumerator::DIRECTORIES);
  for (base::FilePath dev_path = dev_enum.Next(); !dev_path.empty();
       dev_path = dev_enum.Next()) {
    // Some Thunderbolt nvmem devices can take multiple minutes to be read.
    // Avoid reading them, as the camera eeprom will not be sitting there
    // anyway (b/213525227).
    if (dev_path.BaseName().value().find("nvm_active") == 0) {
      LOGF(INFO) << "Ignoring nvmem at " << dev_path;
      continue;
    }
    const base::FilePath nvmem_path =
        base::MakeAbsoluteFilePath(dev_path.Append("nvmem"));
    if (nvmem_path.empty()) {
      LOG(ERROR) << "Failed to resolve absolute nvmem path from " << dev_path;
      continue;
    }
    std::optional<EepromIdBlock> id_block = read_eeprom(nvmem_path);
    if (!id_block.has_value()) {
      // User 'arc-camera' does not have the permission to read the EEPROM file
      // on the nvmem bus (/sys/bus/nvmem/devices/*/nvmem). Fallback to reading
      // the EEPROM file on the i2c bus (/sys/bus/i2c/devices/*/eeprom).
      std::optional<base::FilePath> eeprom_path = locate_eeprom_file(dev_path);
      if (eeprom_path.has_value()) {
        id_block = read_eeprom(eeprom_path.value());
      }
    }
    if (!id_block.has_value())
      continue;
    eeproms_.push_back(EepromInfo{
        .id_block = *id_block,
        .nvmem_path = std::move(nvmem_path),
    });
  }
}

void DeviceConfig::PopulatePlatformCameraInfo() {
  AddCameraEeproms();
  AddV4L2Sensors();

  // Associate probed nvmems and v4l-subdevs by their absolute sysfs device
  // paths. When both devices exist, they are expected to locate on the same
  // I2C bus. For example:
  //   /path/to/i2c/sysfs - i2c-2 - 2-0010 - video4linux - v4l-subdev6
  //                             \- 2-0058 - 2-00580 - nvmem
  std::set<const V4L2SensorInfo*> associated_sensors;
  for (const EepromInfo& eeprom : eeproms_) {
    std::vector<std::string> path = eeprom.nvmem_path.GetComponents();
    CHECK_GE(path.size(), 4u);
    auto iter = std::find_if(v4l2_sensors_.begin(), v4l2_sensors_.end(),
                             [&](const V4L2SensorInfo& sensor) {
                               std::vector<std::string> p =
                                   sensor.subdev_path.GetComponents();
                               return std::equal(path.begin(), path.end() - 3,
                                                 p.begin());
                             });
    auto info = PlatformCameraInfo{
        .eeprom = eeprom,
        .sysfs_name = path[path.size() - 4] + '/' + path[path.size() - 3],
    };
    if (iter != v4l2_sensors_.end()) {
      info.v4l2_sensor = *iter;
      associated_sensors.insert(&*iter);
    }
    platform_cameras_->push_back(std::move(info));
  }
  for (const V4L2SensorInfo& sensor : v4l2_sensors_) {
    if (!base::Contains(associated_sensors, &sensor)) {
      platform_cameras_->push_back(PlatformCameraInfo{
          .v4l2_sensor = sensor,
      });
    }
  }
}

// static
bool DeviceConfig::PopulateCrosConfigCameraInfo(DeviceConfig* dev_conf) {
  CHECK(dev_conf);
  brillo::CrosConfig cros_config;

  if (!cros_config.GetString("/", "name", &dev_conf->model_name_)) {
    LOGF(ERROR) << "Failed to get model name of CrOS device";
    return false;
  }

  std::string use_legacy_usb;
  if (cros_config.GetString(kCrosConfigCameraPath, kCrosConfigLegacyUsbKey,
                            &use_legacy_usb)) {
    if (use_legacy_usb == "true") {
      LOGF(INFO) << "The CrOS device is marked to have v1 camera devices";
    }
    dev_conf->is_v1_device_ = use_legacy_usb == "true";
  } else {
    dev_conf->is_v1_device_ = false;
  }

  std::string count_str;
  if (cros_config.GetString("/camera", "count", &count_str)) {
    dev_conf->count_ = std::stoi(count_str);
  }

  for (int i = 0;; ++i) {
    const std::string device_path = base::StringPrintf("/camera/devices/%i", i);
    std::string interface;
    if (!cros_config.GetString(device_path, "interface", &interface)) {
      break;
    }
    std::string facing, orientation, detachable, has_privacy_switch;
    CHECK(cros_config.GetString(device_path, "facing", &facing));
    CHECK(cros_config.GetString(device_path, "orientation", &orientation));
    // Assume non-detachable if the key doesn't exist.
    cros_config.GetString(device_path, "detachable", &detachable);
    // Assume no privacy switch if the key doesn't exist.
    cros_config.GetString(device_path, "has-privacy-switch",
                          &has_privacy_switch);
    dev_conf->cros_config_cameras_.push_back(CrosConfigCameraInfo{
        .interface = interface == "usb" ? Interface::kUsb : Interface::kMipi,
        .facing = facing == "front" ? LensFacing::kFront : LensFacing::kBack,
        .orientation = std::stoi(orientation),
        .detachable = detachable == "true",
        .has_privacy_switch = has_privacy_switch == "true",
    });
  }
  if (!dev_conf->cros_config_cameras_.empty()) {
    CHECK(dev_conf->count_.has_value());
    CHECK_EQ(static_cast<size_t>(*dev_conf->count_),
             dev_conf->cros_config_cameras_.size());
  }

  return true;
}

}  // namespace cros
