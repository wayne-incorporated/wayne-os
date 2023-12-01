// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/utils/bus_utils.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/fixed_flat_map.h>
#include <base/containers/span.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/values.h>

#include "runtime_probe/utils/file_utils.h"
#include "runtime_probe/utils/type_utils.h"
#include "runtime_probe/utils/value_utils.h"

namespace runtime_probe {
namespace {

constexpr auto kPciFields =
    base::MakeFixedFlatMap<base::StringPiece, base::StringPiece>(
        {{"vendor_id", "vendor"}, {"device_id", "device"}});
constexpr auto kPciOptionalFields =
    base::MakeFixedFlatMap<base::StringPiece, base::StringPiece>(
        {{"revision", "revision"}, {"subsystem", "subsystem_device"}});
constexpr auto kSdioFields =
    base::MakeFixedFlatMap<base::StringPiece, base::StringPiece>(
        {{"vendor_id", "vendor"}, {"device_id", "device"}});
constexpr auto kUsbFields =
    base::MakeFixedFlatMap<base::StringPiece, base::StringPiece>(
        {{"vendor_id", "idVendor"}, {"product_id", "idProduct"}});
constexpr auto kUsbOptionalFields =
    base::MakeFixedFlatMap<base::StringPiece, base::StringPiece>(
        {{"bcd_device", "bcdDevice"}});

constexpr int PCI_REVISION_ID_OFFSET = 0x08;

// For linux kernels of versions before 4.10-rc1, there is no standalone file
// `revision` describing the revision id of the PCI component. The revision is
// still available at offset 8 of the binary file `config`.
std::optional<uint8_t> GetPciRevisionIdFromConfig(base::FilePath node_path) {
  const auto file_path = node_path.Append("config");
  if (!base::PathExists(file_path)) {
    LOG(ERROR) << file_path.value() << " doesn't exist.";
    return std::nullopt;
  }
  base::File config{file_path, base::File::FLAG_OPEN | base::File::FLAG_READ};
  uint8_t revision_array[1];
  base::span<uint8_t> revision_span(revision_array);
  if (!config.ReadAndCheck(PCI_REVISION_ID_OFFSET, revision_span)) {
    LOG(ERROR) << "Cannot read file " << file_path << " at offset "
               << PCI_REVISION_ID_OFFSET;
    return std::nullopt;
  }
  return revision_array[0];
}

}  // namespace

std::optional<base::Value> GetDeviceBusDataFromSysfsNode(
    const base::FilePath& node_path) {
  const auto dev_path = node_path.Append("device");
  const auto dev_subsystem_path = dev_path.Append("subsystem");
  base::FilePath dev_subsystem_link_path;
  if (!base::ReadSymbolicLink(dev_subsystem_path, &dev_subsystem_link_path)) {
    VLOG(2) << "Cannot get real path of " << dev_subsystem_path;
    return std::nullopt;
  }
  std::string bus_type = dev_subsystem_link_path.BaseName().value();

  std::optional<base::Value> res;
  if (bus_type == "pci") {
    res = MapFilesToDict(dev_path, kPciFields, kPciOptionalFields);
    if (res && !res->GetDict().FindString("revision")) {
      auto revision_id = GetPciRevisionIdFromConfig(dev_path);
      if (revision_id) {
        res->GetDict().Set("revision", ByteToHexString(*revision_id));
      }
    }
  } else if (bus_type == "sdio") {
    res = MapFilesToDict(dev_path, kSdioFields);
  } else if (bus_type == "usb") {
    auto field_path = base::MakeAbsoluteFilePath(dev_path.Append(".."));
    res = MapFilesToDict(field_path, kUsbFields, kUsbOptionalFields);
  } else if (bus_type == "platform") {
    VLOG(2) << "Path " << node_path
            << " has bus type \"platform\", which usually means it is a device "
               "bound with SoC. Ignore it.";
    return std::nullopt;
  } else {
    LOG(ERROR) << "Unknown bus_type " << bus_type;
    return std::nullopt;
  }

  if (!res) {
    LOG(ERROR) << "Cannot find " << bus_type << "-specific fields from \""
               << dev_path << "\"";
    return std::nullopt;
  }
  PrependToDVKey(&*res, bus_type + "_");
  res->GetDict().Set("bus_type", bus_type);
  CHECK(!res->GetDict().FindString("path"));
  res->GetDict().Set("path", node_path.value());

  return res;
}

}  // namespace runtime_probe
