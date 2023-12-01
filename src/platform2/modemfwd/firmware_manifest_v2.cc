// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/firmware_manifest.h"

#include <optional>
#include <utility>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/proto_file_io.h>

#include "modemfwd/firmware_directory.h"

#include "modemfwd/proto_bindings/firmware_manifest_v2.pb.h"

namespace modemfwd {

namespace {

bool ParseDevice(const Device& device,
                 DeviceFirmwareCache* out_cache,
                 std::map<std::string, Dlc>* dlc_per_variant) {
  if (!device.variant().empty() && device.has_dlc())
    dlc_per_variant->emplace(device.variant(), device.dlc());
  // Sort main firmware entries by version. Ensure the versions are
  // all separate.
  std::map<std::string, std::unique_ptr<FirmwareFileInfo>> main_firmware_infos;
  for (const MainFirmwareV2& main_firmware : device.main_firmware()) {
    if (main_firmware.filename().empty() || main_firmware.version().empty() ||
        !Compression_IsValid(main_firmware.compression())) {
      LOG(ERROR) << "Found malformed main firmware manifest entry";
      return false;
    }
    if (main_firmware_infos.count(main_firmware.version()) > 0) {
      LOG(ERROR) << "Found multiple main firmware with the same version for "
                 << "device " << device.device_id()
                 << (device.variant().empty()
                         ? ""
                         : "(variant " + device.variant() + ")");
      return false;
    }

    auto compression =
        ToFirmwareFileInfoCompression(main_firmware.compression());
    if (!compression.has_value())
      return false;

    // Use relative paths since DLCs have no predefined path
    if (base::FilePath(main_firmware.filename()).IsAbsolute()) {
      LOG(ERROR) << "Main firmware should use relative path ("
                 << main_firmware.filename() << ").";
      return false;
    }

    auto main_info = std::make_unique<FirmwareFileInfo>(
        main_firmware.filename(), main_firmware.version(), compression.value());

    // Add associated firmware for this main firmware, if it exists.
    for (const AssociatedFirmware& assoc_firmware :
         main_firmware.assoc_firmware()) {
      if (assoc_firmware.filename().empty() || assoc_firmware.tag().empty() ||
          assoc_firmware.version().empty() ||
          !Compression_IsValid(assoc_firmware.compression())) {
        LOG(ERROR) << "Found malformed associated firmware manifest entry";
        return false;
      }
      auto assoc_compression =
          ToFirmwareFileInfoCompression(assoc_firmware.compression());
      if (!assoc_compression.has_value()) {
        LOG(ERROR) << "Firmware entry " << assoc_firmware.tag()
                   << " does not specify compression";
        return false;
      }

      if (base::FilePath(assoc_firmware.filename()).IsAbsolute()) {
        LOG(ERROR) << "Associated firmware should use relative path ("
                   << assoc_firmware.filename() << ").";
        return false;
      }

      auto assoc_info = std::make_unique<FirmwareFileInfo>(
          assoc_firmware.filename(), assoc_firmware.version(),
          assoc_compression.value());
      out_cache->assoc_firmware[main_info.get()][assoc_firmware.tag()] =
          assoc_info.get();
      out_cache->all_files.push_back(std::move(assoc_info));
    }

    main_firmware_infos.emplace(main_firmware.version(), std::move(main_info));
  }

  // Main firmware is default for a device if:
  // * It is explicitly specified as default in the Device entry.
  // * It is the only main firmware.
  FirmwareFileInfo* default_main_entry = nullptr;
  if (!device.default_main_firmware_version().empty()) {
    if (main_firmware_infos.count(device.default_main_firmware_version()) ==
        0) {
      LOG(ERROR) << "Firmware manifest specified invalid default main firmware "
                    "version";
      return false;
    }

    default_main_entry =
        main_firmware_infos[device.default_main_firmware_version()].get();
  } else if (main_firmware_infos.size() == 1) {
    default_main_entry = main_firmware_infos.begin()->second.get();
  }

  std::map<std::string, FirmwareFileInfo*> oem_firmware_infos;
  for (const OemFirmwareV2& oem_firmware : device.oem_firmware()) {
    if (oem_firmware.filename().empty() || oem_firmware.version().empty() ||
        !Compression_IsValid(oem_firmware.compression())) {
      LOG(ERROR) << "Found malformed OEM firmware manifest entry";
      return false;
    }

    auto compression =
        ToFirmwareFileInfoCompression(oem_firmware.compression());
    if (!compression.has_value())
      return false;

    if (base::FilePath(oem_firmware.filename()).IsAbsolute()) {
      LOG(ERROR) << "OEM firmware should use relative path ("
                 << oem_firmware.filename() << ").";
      return false;
    }

    auto oem_info = std::make_unique<FirmwareFileInfo>(
        oem_firmware.filename(), oem_firmware.version(), compression.value());
    if (oem_firmware.main_firmware_version_size() > 0) {
      for (const std::string& version : oem_firmware.main_firmware_version())
        oem_firmware_infos.emplace(version, oem_info.get());
    } else {
      if (default_main_entry)
        oem_firmware_infos.emplace(default_main_entry->version, oem_info.get());
    }
    out_cache->all_files.push_back(std::move(oem_info));
  }

  // If not, then each carrier firmware must specify a functional main firmware
  // version, and there must be a generic carrier firmware supplying the main
  // version if no explicitly supported carrier is found.

  for (const CarrierFirmwareV2& carrier_firmware : device.carrier_firmware()) {
    if (carrier_firmware.filename().empty() ||
        carrier_firmware.version().empty() ||
        carrier_firmware.carrier_id().empty() ||
        !Compression_IsValid(carrier_firmware.compression())) {
      LOG(ERROR) << "Found malformed carrier firmware manifest entry";
      return false;
    }

    // Convert the manifest entry into a FirmwareFileInfo.
    auto compression =
        ToFirmwareFileInfoCompression(carrier_firmware.compression());
    if (!compression.has_value())
      return false;

    // There must either be a default main firmware or an explicitly specified
    // one here.
    FirmwareFileInfo* main_firmware_for_carrier;
    FirmwareFileInfo* oem_firmware_for_carrier;
    if (!carrier_firmware.main_firmware_version().empty()) {
      if (main_firmware_infos.count(carrier_firmware.main_firmware_version()) ==
          0) {
        LOG(ERROR)
            << "Manifest specified invalid default main firmware version";
        return false;
      }
      main_firmware_for_carrier =
          main_firmware_infos[carrier_firmware.main_firmware_version()].get();
      oem_firmware_for_carrier =
          oem_firmware_infos[carrier_firmware.main_firmware_version()];
    } else if (default_main_entry) {
      main_firmware_for_carrier = default_main_entry;
      oem_firmware_for_carrier =
          oem_firmware_infos[default_main_entry->version];
    } else {
      LOG(ERROR) << "No main firmware specified for carrier firmware "
                 << carrier_firmware.filename();
      return false;
    }

    if (base::FilePath(carrier_firmware.filename()).IsAbsolute()) {
      LOG(ERROR) << "Carrier firmware should use relative path ("
                 << carrier_firmware.filename() << ").";
      return false;
    }

    auto carrier_info = std::make_unique<FirmwareFileInfo>(
        carrier_firmware.filename(), carrier_firmware.version(),
        compression.value());

    // Add the firmware to the cache under the carrier ID for this entry.
    for (const std::string& supported_carrier : carrier_firmware.carrier_id()) {
      if (out_cache->carrier_firmware.count(supported_carrier) > 0) {
        LOG(ERROR) << "Duplicate carrier firmware entry for carrier "
                   << supported_carrier;
        // We haven't inserted main firmware into the mapping yet. Clear all
        // the indices to prevent poorly-behaved users from getting dangling
        // pointers.
        out_cache->main_firmware.clear();
        out_cache->carrier_firmware.clear();
        out_cache->oem_firmware.clear();
        return false;
      }

      out_cache->main_firmware[supported_carrier] = main_firmware_for_carrier;
      if (oem_firmware_for_carrier)
        out_cache->oem_firmware[supported_carrier] = oem_firmware_for_carrier;
      out_cache->carrier_firmware[supported_carrier] = carrier_info.get();
    }
    out_cache->all_files.push_back(std::move(carrier_info));
  }

  // Now it's safe to move all of the main firmware file info pointers.
  for (auto& main_info : main_firmware_infos)
    out_cache->all_files.push_back(std::move(main_info.second));

  // If we have a default entry but didn't see any generic carrier firmware,
  // we put the default main firmware in the main index under generic.
  if (out_cache->main_firmware.count(FirmwareDirectory::kGenericCarrierId) ==
      0) {
    if (!default_main_entry) {
      LOG(ERROR) << "Manifest did not supply generic main firmware";
      return false;
    }
    out_cache->main_firmware[FirmwareDirectory::kGenericCarrierId] =
        default_main_entry;
    auto oem_info = oem_firmware_infos.find(default_main_entry->version);
    if (oem_info != oem_firmware_infos.end() && oem_info->second)
      out_cache->oem_firmware[FirmwareDirectory::kGenericCarrierId] =
          oem_info->second;
  }

  return true;
}

}  // namespace

std::unique_ptr<FirmwareIndex> ParseFirmwareManifestV2(
    const base::FilePath& manifest,
    std::map<std::string, Dlc>& dlc_per_variant) {
  FirmwareManifestV2 manifest_proto;
  if (!brillo::ReadTextProtobuf(manifest, &manifest_proto)) {
    PLOG(ERROR) << "Failed to read manifest file";
    return nullptr;
  }

  FirmwareIndex index;
  for (const Device& device : manifest_proto.device()) {
    if (device.device_id().empty()) {
      LOG(ERROR) << "Empty device ID in device entry";
      return nullptr;
    }

    DeviceType type{device.device_id(), device.variant()};
    if (index.count(type) > 0) {
      LOG(ERROR) << "Duplicate device entry in manifest";
      return nullptr;
    }

    DeviceFirmwareCache cache;
    if (!ParseDevice(device, &cache, &dlc_per_variant))
      return nullptr;

    index[type] = std::move(cache);
  }

  return std::make_unique<FirmwareIndex>(std::move(index));
}

std::optional<FirmwareFileInfo::Compression> ToFirmwareFileInfoCompression(
    Compression compression) {
  switch (compression) {
    case Compression::NONE:
      return FirmwareFileInfo::Compression::NONE;
    case Compression::XZ:
      return FirmwareFileInfo::Compression::XZ;
    default:
      std::string name = Compression_Name(compression);
      if (name.empty())
        name = base::NumberToString(compression);
      LOG(ERROR) << "Unsupported compression: " << name;
      return std::nullopt;
  }
}

}  // namespace modemfwd
