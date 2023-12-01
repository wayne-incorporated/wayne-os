// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/pci_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <filesystem>
#include <memory>
#include <optional>

#include <base/base64.h>
#include <base/containers/cxx20_erase.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/format_macros.h>
#include <base/logging.h>
#include <base/strings/safe_sprintf.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include <chromeos-config/libcros_config/cros_config.h>

#include "vm_tools/concierge/crosvm_control.h"

namespace vm_tools::concierge {
namespace pci_utils {

// Name of the file within the PCI device directory which contains a device's
// vendor ID.
constexpr char kPciVendorIdFileName[] = "vendor";

// Name of the file within the PCI device directory which contains a device's
// dwvicw ID.
constexpr char kPciDeviceIdFileName[] = "device";

// Name of the file within the PCI device directory which contains a device's
// class.
constexpr char kPciClassFileName[] = "class";

// Name of the file within the PCI device directory which contains a device's
// boot_vga flag.
constexpr char kPciBootVgaFileName[] = "boot_vga";

// Name of the file within the PCI device directory which contains a device's
// driver.
constexpr char kPciDriverFileName[] = "driver";

// The Vendor Id for NVIDIA devices.
constexpr uint16_t kNvidiaVendorId = 0x10de;

// The class number for VGA devices.
constexpr uint32_t kVgaDeviceClass = 0x030000;

// The class number for 3D Controller devices.
constexpr uint32_t k3DControllerDeviceClass = 0x030200;

// Path where all PCI devices reside.
constexpr char kPciDevicesPath[] = "/sys/bus/pci/devices";

// This pattern is to search for "0000:02:00.0" directory within
// /sys/bus/pci/devices/
constexpr char kPciDevicePattern[] = "0000:*";

// Returns the vendor ID for the PCI device at |pci_device|. Returns
// std::nullopt in case of any parsing errors.
std::optional<uint32_t> GetPciDeviceNodeValue(const base::FilePath& pci_device,
                                              std::string file_name) {
  base::FilePath file_path = pci_device.Append(file_name);

  std::string data;
  if (!base::ReadFileToString(file_path, &data)) {
    LOG(ERROR) << "Failed to read  file " << pci_device << file_name;
    return std::nullopt;
  }

  // sysfs adds a newline to this value. Remove it.
  base::TrimString(data, "\n", &data);

  uint32_t parsed_data;
  if (!base::HexStringToUInt(data, &parsed_data)) {
    LOG(ERROR) << "Failed to parse vendor id for: " << pci_device;
    return std::nullopt;
  }

  return parsed_data;
}

// Returns the vendor ID for the PCI device at |pci_device|. Returns
// std::nullopt in case of any parsing errors.
std::optional<uint32_t> GetPciDeviceVendorId(const base::FilePath& pci_device) {
  return GetPciDeviceNodeValue(pci_device, kPciVendorIdFileName);
}

// Returns the device ID for the PCI device at |pci_device|. Returns
// std::nullopt in case of any parsing errors.
std::optional<uint32_t> GetPciDeviceDeviceId(const base::FilePath& pci_device) {
  return GetPciDeviceNodeValue(pci_device, kPciDeviceIdFileName);
}

// Returns the device class for the PCI device at |pci_device|. Returns
// std::nullopt in case of any parsing errors.
std::optional<uint32_t> GetPciDeviceClass(const base::FilePath& pci_device) {
  return GetPciDeviceNodeValue(pci_device, kPciClassFileName);
}

// Returns the device boot_vga file content for the PCI device at |pci_device|.
// Returns std::nullopt in case of any parsing errors.
std::optional<uint32_t> GetPciDeviceBootVga(const base::FilePath& pci_device) {
  return GetPciDeviceNodeValue(pci_device, kPciBootVgaFileName);
}

// Returns the device driver name for the PCI device at |pci_device|. Returns
// empty string in case if the driver doesn't exist.
std::string GetPciDeviceDriverName(const base::FilePath& pci_device) {
  base::FilePath driver_dir_path = pci_device.Append(kPciDriverFileName);
  std::filesystem::path fp =
      std::filesystem::path(driver_dir_path.value().c_str());
  std::string driver_name = "";

  if (std::filesystem::exists(fp) && std::filesystem::is_symlink(fp)) {
    // Follow the symlink for driver node to determine the driver name.
    std::string symlink_path = std::filesystem::read_symlink(fp);
    driver_name = base::FilePath(symlink_path).BaseName().value();

    LOG(INFO) << " Found driver name: " << driver_name
              << " for driver node: " << driver_dir_path.value()
              << " having symlink: " << symlink_path;
  }

  return driver_name;
}

// Returns true iff |pci_device| is a dGPU device by comparing it's
// class number.
bool IsDGpuPassthroughDevice(const base::FilePath& pci_device) {
  // Check device class to ensure it's a dGPU device.
  std::optional<uint32_t> device_class_num = GetPciDeviceClass(pci_device);
  if (!device_class_num) {
    return false;
  }
  if ((device_class_num.value() != k3DControllerDeviceClass) &&
      (device_class_num.value() != kVgaDeviceClass)) {
    return false;
  }

  // Ensure VGA dGPU is not a boot device.
  if (device_class_num.value() == kVgaDeviceClass) {
    std::optional<uint32_t> boot_vga = GetPciDeviceBootVga(pci_device);
    if (!boot_vga) {
      return false;
    }
    if (boot_vga.value()) {
      return false;
    }
  }

  // Check if the device is bound to vfio-pci module as --vfio argument
  // needs a valid vfio-pci device.
  if (GetPciDeviceDriverName(pci_device).compare("vfio-pci") != 0) {
    return false;
  }

  // Check if it's a supported vendor dGPU device.
  std::optional<uint32_t> vendor_id = GetPciDeviceVendorId(pci_device);
  if (!vendor_id) {
    return false;
  }
  if (vendor_id.value() != kNvidiaVendorId) {
    return false;
  }

  return true;
}

std::vector<base::FilePath> GetPciDevicesList(PciDeviceType device_type) {
  // PCI devices have paths like these /sys/bus/pci/devices/0000:02:00.0.
  base::FileEnumerator pci_devices = base::FileEnumerator(
      base::FilePath(kPciDevicesPath), false /* recursive */,
      base::FileEnumerator::FileType::DIRECTORIES, kPciDevicePattern);
  std::vector<base::FilePath> pci_devices_info;
  std::string dev_name = "";

  for (base::FilePath pci_device = pci_devices.Next(); !pci_device.empty();
       pci_device = pci_devices.Next()) {
    switch (device_type) {
      case PciDeviceType::PCI_DEVICE_TYPE_DGPU_PASSTHROUGH:
        // Check if this is a dGPU passthough device.
        if (!IsDGpuPassthroughDevice(pci_device))
          continue;
        dev_name = "DGPU passthrough";
        break;
      default:
        LOG(ERROR) << "Invalid PciDeviceType specified";
        return pci_devices_info;
    }
    LOG(INFO) << "Found " << dev_name << " device at path: " << pci_device;
    pci_devices_info.push_back(pci_device);
  }

  return pci_devices_info;
}

}  // namespace pci_utils
}  // namespace vm_tools::concierge
