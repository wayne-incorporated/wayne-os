// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_PCI_UTILS_H_
#define VM_TOOLS_CONCIERGE_PCI_UTILS_H_

#include <sys/types.h>

#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_enumerator.h>
#include <base/strings/string_split.h>
#include <base/strings/string_piece.h>
#include <base/values.h>

namespace base {
class FilePath;
}  // namespace base

namespace vm_tools {
namespace concierge {
namespace pci_utils {

enum class PciDeviceType : uint8_t {
  // Discrete GPU.
  PCI_DEVICE_TYPE_DGPU_PASSTHROUGH = 1
};

// Returns the vendor ID for the PCI device at |pci_device|. Returns
// std::nullopt in case of any parsing errors.
std::optional<uint32_t> GetPciDeviceNodeValue(const base::FilePath& pci_device,
                                              std::string file_name);

// Returns the vendor ID for the PCI device at |pci_device|. Returns
// std::nullopt in case of any parsing errors.
std::optional<uint32_t> GetPciDeviceVendorId(const base::FilePath& pci_device);

// Returns the device ID for the PCI device at |pci_device|. Returns
// std::nullopt in case of any parsing errors.
std::optional<uint32_t> GetPciDeviceDeviceId(const base::FilePath& pci_device);

// Returns the device class for the PCI device at |pci_device|. Returns
// std::nullopt in case of any parsing errors.
std::optional<uint32_t> GetPciDeviceClass(const base::FilePath& pci_device);

// Returns the boot_vga value for the PCI device at |pci_device|. Returns
// std::nullopt in case of any parsing errors or if boot_vga file is missing.
std::optional<uint32_t> GetPciDeviceBootVga(const base::FilePath& pci_device);

// Returns the device driver name for the PCI device at |pci_device|. Returns
// std::nullopt in case of any parsing errors or if no driver is loaded.
std::string GetPciDeviceDriverName(const base::FilePath& pci_device);

// Returns true iff |pci_device| is a dGPU device available for passthough
// by comparing it's class number, ensuring it's a non boot_vga device and
// it's bound to vfio-pci module.
bool IsDGpuPassthroughDevice(const base::FilePath& pci_device);

std::vector<base::FilePath> GetPciDevicesList(PciDeviceType device_type);

}  // namespace pci_utils
}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_PCI_UTILS_H_
