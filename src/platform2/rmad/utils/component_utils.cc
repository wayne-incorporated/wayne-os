// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/component_utils.h"

#include <iomanip>
#include <sstream>
#include <string>

#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

namespace {

std::string Uint32ToHexString(uint32_t v, int width) {
  std::ostringstream ss;
  ss << std::hex << std::setfill('0') << std::setw(width) << v;
  return ss.str();
}

}  // namespace

namespace rmad {

// Implementation for each component fields defined by runtime_probe.
// See platform2/system_api/dbus/runtime_probe/runtime_probe.proto for type and
// bit length for each fields.
std::string GetComponentFieldsIdentifier(
    const runtime_probe::Battery_Fields& fields) {
  // Battery. Identifier is "battery_<manufacturer name>_<model name>".
  return "battery_" + fields.manufacturer() + "_" + fields.model_name();
}

std::string GetComponentFieldsIdentifier(
    const runtime_probe::Storage_Fields& fields) {
  // Storage. Identifier depends on storage type.
  if (fields.type() == "MMC") {
    // eMMC storage. Identifier is "storage(eMMC)_<manufacturer id>_<name>".
    return "storage(eMMC)_" + Uint32ToHexString(fields.mmc_manfid(), 2) + "_" +
           fields.mmc_name();
  } else if (fields.type() == "NVMe") {
    // NVMe storage. Identifier is "storage(NVMe)_<vendor id>_<device id>".
    return "storage(NVMe)_" + Uint32ToHexString(fields.pci_vendor(), 4) + "_" +
           Uint32ToHexString(fields.pci_device(), 4);
  } else if (fields.type() == "ATA") {
    // SATA storage. Identifier is
    // "storage(SATA)_<vendor name>_<model name>".
    return "storage(SATA)_" + fields.ata_vendor() + "_" + fields.ata_model();
  }
  return "storage(unknown)";
}

std::string GetComponentFieldsIdentifier(
    const runtime_probe::Camera_Fields& fields) {
  // Camera. Identifier is "camera_<vendor id>_<product id>".
  return "camera_" + Uint32ToHexString(fields.usb_vendor_id(), 4) + "_" +
         Uint32ToHexString(fields.usb_product_id(), 4);
}

std::string GetComponentFieldsIdentifier(
    const runtime_probe::InputDevice_Fields& fields) {
  // Input device. Identifier is "<type>_<vendor id>_<product_id>".
  if (fields.device_type() == runtime_probe::InputDevice::TYPE_STYLUS) {
    return "stylus_" + Uint32ToHexString(fields.vendor(), 4) + "_" +
           Uint32ToHexString(fields.product(), 4);
  } else if (fields.device_type() ==
             runtime_probe::InputDevice::TYPE_TOUCHPAD) {
    return "touchpad_" + Uint32ToHexString(fields.vendor(), 4) + "_" +
           Uint32ToHexString(fields.product(), 4);
  } else if (fields.device_type() ==
             runtime_probe::InputDevice::TYPE_TOUCHSCREEN) {
    return "touchscreen_" + Uint32ToHexString(fields.vendor(), 4) + "_" +
           Uint32ToHexString(fields.product(), 4);
  }
  return "input_device(unknown)";
}

std::string GetComponentFieldsIdentifier(
    const runtime_probe::Memory_Fields& fields) {
  // Memory. Identifier is "dram_<part number>".
  return "dram_" + fields.part();
}

std::string GetComponentFieldsIdentifier(
    const runtime_probe::Edid_Fields& fields) {
  // Display panel. Identifier is "display_<vendor code>_<product_id>".
  return "display_" + fields.vendor() + "_" +
         Uint32ToHexString(fields.product_id(), 4);
}

std::string GetComponentFieldsIdentifier(
    const runtime_probe::Network_Fields& fields) {
  // network (wireless/ethernet/cellular). Identifier depends on bus type.
  if (fields.bus_type() == "pci") {
    // PCI. Identifier is "network(<type>:pci)_<vendor id>_<device_id>".
    return "network(" + fields.type() + ":pci)_" +
           Uint32ToHexString(fields.pci_vendor_id(), 4) + "_" +
           Uint32ToHexString(fields.pci_device_id(), 4);
  } else if (fields.bus_type() == "usb") {
    // USB. Identifier is "network(<type>:usb)_<vendor id>_<product_id>".
    return "network(" + fields.type() + ":usb)_" +
           Uint32ToHexString(fields.usb_vendor_id(), 4) + "_" +
           Uint32ToHexString(fields.usb_product_id(), 4);
  } else if (fields.bus_type() == "sdio") {
    // SDIO. |identifier| is "network(<type>:sdio)_<vendor id>_<device_id>".
    return "network(" + fields.type() + ":sdio)_" +
           Uint32ToHexString(fields.sdio_vendor_id(), 4) + "_" +
           Uint32ToHexString(fields.sdio_device_id(), 4);
  }
  return "network(" + fields.type() + ":unknown)";
}

std::string GetComponentFieldsIdentifier(
    const runtime_probe::ApI2c_Fields& fields) {
  return "api2c_" + Uint32ToHexString(fields.data(), 4);
}

std::string GetComponentFieldsIdentifier(
    const runtime_probe::EcI2c_Fields& fields) {
  return "eci2c_" + Uint32ToHexString(fields.data(), 4);
}

std::string GetComponentFieldsIdentifier(
    const runtime_probe::Tcpc_Fields& fields) {
  return "tcpc_" + Uint32ToHexString(fields.vendor_id(), 4) + "_" +
         Uint32ToHexString(fields.product_id(), 4) + "_" +
         Uint32ToHexString(fields.device_id(), 4);
}

// Extension for |runtime_probe::ComponentFields|.
std::string GetComponentFieldsIdentifier(
    const runtime_probe::ComponentFields& component_fields) {
  if (component_fields.has_battery()) {
    return GetComponentFieldsIdentifier(component_fields.battery());
  } else if (component_fields.has_storage()) {
    return GetComponentFieldsIdentifier(component_fields.storage());
  } else if (component_fields.has_camera()) {
    return GetComponentFieldsIdentifier(component_fields.camera());
  } else if (component_fields.has_stylus()) {
    return GetComponentFieldsIdentifier(component_fields.stylus());
  } else if (component_fields.has_touchpad()) {
    return GetComponentFieldsIdentifier(component_fields.touchpad());
  } else if (component_fields.has_touchscreen()) {
    return GetComponentFieldsIdentifier(component_fields.touchscreen());
  } else if (component_fields.has_dram()) {
    return GetComponentFieldsIdentifier(component_fields.dram());
  } else if (component_fields.has_display_panel()) {
    return GetComponentFieldsIdentifier(component_fields.display_panel());
  } else if (component_fields.has_cellular()) {
    return GetComponentFieldsIdentifier(component_fields.cellular());
  } else if (component_fields.has_ethernet()) {
    return GetComponentFieldsIdentifier(component_fields.ethernet());
  } else if (component_fields.has_wireless()) {
    return GetComponentFieldsIdentifier(component_fields.wireless());
  }
  return "unknown_component";
}

}  // namespace rmad
