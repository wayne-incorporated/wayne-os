// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "flex_id/flex_id.h"

#include <iostream>
#include <map>
#include <optional>
#include <utility>

#include <base/containers/contains.h>
#include <base/files/file_enumerator.h>
#include <base/files/important_file_writer.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/process/process.h>

namespace flex_id {

namespace {

constexpr char kFlexIdPrefix[] = "Flex-";
constexpr char kFlexIdFile[] = "var/lib/flex_id/flex_id";
constexpr char kClientIdFile[] = "var/lib/client_id/client_id";
constexpr char kUuidPath[] = "proc/sys/kernel/random/uuid";
constexpr char kLegacyClientIdFile[] =
    "mnt/stateful_partition/cloudready/client_id";
constexpr char kDmiSerialPath[] = "sys/devices/virtual/dmi/id/product_serial";
constexpr char kNetworkInterfacesPath[] = "sys/class/net";
constexpr int kMinSerialLength = 2;
// Case of these values doesn't matter as they are compared case-insensitively.
const char* kBadSerials[] = {"to be filled by o.e.m.",
                             "to be filled by o.e.m",
                             "123456789",
                             "system serial number",
                             "system_serial_number",
                             "invalid",
                             "none",
                             "default string",
                             "not applicable",
                             "na",
                             "n/a",
                             "ssn12345678901234567",
                             "system serial#",
                             "1234567",
                             "systemserialnumb",
                             "serial#",
                             "oem",
                             "default_string",
                             "91.WTx00.xPxx",  // This is a device model number.
                             "$serialnumber$"};
constexpr char kInterfaceAddressFile[] = "address";
constexpr char kInterfaceModAliasFile[] = "device/modalias";
constexpr char kInterfaceUsbPrefix[] = "usb:";
const char* kPriorityInterfaces[] = {"eth0", "wlan0"};
const char* kBadInterfacePrefixes[] = {"arc", "docker"};
const char* kBadMacs[] = {"00:00:00:00:00:00"};

std::optional<std::string> ReadAndTrimFile(const base::FilePath& file_path) {
  std::string out;
  if (!base::ReadFileToString(file_path, &out))
    return std::nullopt;

  base::TrimWhitespaceASCII(out, base::TRIM_ALL, &out);

  return out;
}

bool InterfaceIsInteresting(const std::string& name,
                            const std::string& address) {
  // an interesting interface is one that is not in the list of bad
  // interface name prefixes or in the list of bad mac addresses.

  // compare the interface name with the list of bad names by prefix.
  for (std::size_t i = 0; i < std::size(kBadInterfacePrefixes); i++) {
    if (base::StartsWith(name, kBadInterfacePrefixes[i],
                         base::CompareCase::INSENSITIVE_ASCII))
      return false;
  }

  // compare the interface address with the list of bad addresses.
  if (base::Contains(kBadMacs, address))
    return false;

  return true;
}

bool InterfaceIsUsb(const base::FilePath& modalias_path) {
  // usb interfaces should not be relied on as they can be removable devices.
  // the bus is determined by reading the modalias for a given interface name.
  const auto modalias = ReadAndTrimFile(modalias_path);
  // if we can't read the interface, ignore it.
  if (!modalias)
    return true;

  // check for usb prefix in the modalias.
  if (base::StartsWith(modalias.value(), kInterfaceUsbPrefix,
                       base::CompareCase::INSENSITIVE_ASCII))
    return true;

  return false;
}

}  // namespace

FlexIdGenerator::FlexIdGenerator(const base::FilePath& base_path) {
  base_path_ = base_path;
}

std::optional<std::string> FlexIdGenerator::AddFlexIdPrefix(
    const std::string& flex_id) {
  return kFlexIdPrefix + flex_id;
}

std::optional<std::string> FlexIdGenerator::ReadFlexId() {
  std::optional<std::string> flex_id;
  const base::FilePath flex_id_path = base_path_.Append(kFlexIdFile);

  if (!(flex_id = ReadAndTrimFile(flex_id_path))) {
    LOG(WARNING) << "Couldn't read flex_id file.";
    return std::nullopt;
  }
  if (flex_id.value().empty()) {
    LOG(WARNING) << "Read a blank flex_id file.";
    return std::nullopt;
  }

  return flex_id;
}

std::optional<std::string> FlexIdGenerator::TryClientId() {
  std::optional<std::string> client_id;
  const base::FilePath client_id_path = base_path_.Append(kClientIdFile);

  if (!(client_id = ReadAndTrimFile(client_id_path)))
    return std::nullopt;
  if (client_id.value().empty())
    return std::nullopt;

  return client_id;
}

std::optional<std::string> FlexIdGenerator::TryLegacy() {
  std::optional<std::string> legacy;
  const base::FilePath legacy_path = base_path_.Append(kLegacyClientIdFile);

  if (!(legacy = ReadAndTrimFile(legacy_path)))
    return std::nullopt;
  if (legacy.value().empty())
    return std::nullopt;

  return legacy;
}

std::optional<std::string> FlexIdGenerator::TrySerial() {
  std::optional<std::string> serial;
  const base::FilePath serial_path = base_path_.Append(kDmiSerialPath);

  // check if serial is present.
  if (!(serial = ReadAndTrimFile(serial_path)))
    return std::nullopt;

  // check if the serial is long enough.
  if (serial.value().length() < kMinSerialLength)
    return std::nullopt;

  // check if the serial is not made up of a single repeated character.
  std::size_t found = serial.value().find_first_not_of(serial.value()[0]);
  if (found == std::string::npos)
    return std::nullopt;

  // check if the serial is in the bad serials list.
  for (const auto* badSerial : kBadSerials) {
    if (base::EqualsCaseInsensitiveASCII(badSerial, serial.value()))
      return std::nullopt;
  }

  return serial;
}

void WaitForNetwork() {
  // This udevadm command is required on some machines like VMs to ensure
  // the network interfaces are all ready prior to attempting to find a
  // mac address.
  brillo::ProcessImpl udevadm_process;
  udevadm_process.AddArg("/bin/udevadm");
  udevadm_process.AddArg("trigger");
  // -w flag waits for trigger to complete
  udevadm_process.AddArg("-w");
  udevadm_process.AddArg("--action=change");
  udevadm_process.SetCloseUnusedFileDescriptors(true);

  auto result = udevadm_process.Run();
  if (result != 0) {
    LOG(WARNING) << "Failed to wait for MAC address for flex id";
  }
}

std::optional<std::string> FlexIdGenerator::TryMac() {
  WaitForNetwork();

  std::map<std::string, std::string> interfaces;

  const base::FilePath interfaces_path =
      base_path_.Append(kNetworkInterfacesPath);

  // loop through sysfs network interfaces
  base::FileEnumerator interface_dirs(interfaces_path, false,
                                      base::FileEnumerator::DIRECTORIES);
  for (base::FilePath interface_dir = interface_dirs.Next();
       !interface_dir.empty(); interface_dir = interface_dirs.Next()) {
    std::string name = interface_dir.BaseName().value();
    base::FilePath address_file_path =
        interfaces_path.Append(name).Append(kInterfaceAddressFile);
    std::optional<std::string> address;

    // skip the interface if it has no address
    if (!(address = ReadAndTrimFile(address_file_path)))
      continue;

    // check if the interface qualifies as interesting
    if (InterfaceIsInteresting(name, address.value())) {
      interfaces.insert(
          std::pair<std::string, std::string>(name, address.value()));
    }
  }

  // try priority interfaces (usb is allowed for priority interfaces).
  for (std::size_t i = 0; i < std::size(kPriorityInterfaces); i++) {
    if (interfaces.count(kPriorityInterfaces[i])) {
      return interfaces[kPriorityInterfaces[i]];
    }
  }

  // try remaining interfaces
  for (const auto& interface : interfaces) {
    // skip usb interfaces
    base::FilePath modalias_path = base_path_.Append(kNetworkInterfacesPath)
                                       .Append(interface.first)
                                       .Append(kInterfaceModAliasFile);
    if (InterfaceIsUsb(modalias_path))
      continue;

    return interface.second;
  }

  return std::nullopt;
}

std::optional<std::string> FlexIdGenerator::TryUuid() {
  const base::FilePath uuid_path = base_path_.Append(kUuidPath);

  return ReadAndTrimFile(uuid_path);
}

bool FlexIdGenerator::WriteFlexId(const std::string& flex_id) {
  const base::FilePath flex_id_file_path = base_path_.Append(kFlexIdFile);
  if (base::CreateDirectory(flex_id_file_path.DirName())) {
    return base::ImportantFileWriter::WriteFileAtomically(flex_id_file_path,
                                                          flex_id + "\n");
  }
  return false;
}

std::optional<std::string> FlexIdGenerator::GenerateAndSaveFlexId() {
  std::optional<std::string> flex_id;

  // Check for existing flex_id and exit early.
  if ((flex_id = ReadFlexId())) {
    LOG(INFO) << "Found existing flex_id: " << flex_id.value();
    return flex_id;
  }

  if ((flex_id = TryClientId())) {
    LOG(INFO) << "Using client_id for flex_id: " << flex_id.value();
  } else if ((flex_id = TryLegacy())) {
    LOG(INFO) << "Using CloudReady legacy for flex_id: " << flex_id.value();
  } else if ((flex_id = TrySerial())) {
    LOG(INFO) << "Using DMI serial number for flex_id: " << flex_id.value();
  } else if ((flex_id = TryMac())) {
    flex_id = AddFlexIdPrefix(flex_id.value());
    LOG(INFO) << "Using MAC address for flex_id: " << flex_id.value();
  } else if ((flex_id = TryUuid())) {
    flex_id = AddFlexIdPrefix(flex_id.value());
    LOG(INFO) << "Using random UUID for flex_id: " << flex_id.value();
  } else {
    LOG(ERROR) << "No valid flex_id source was found";
    return std::nullopt;
  }

  // save result
  if (WriteFlexId(flex_id.value())) {
    LOG(INFO) << "Successfully wrote flex_id: " << flex_id.value();
    return flex_id;
  }

  return std::nullopt;
}

}  // namespace flex_id
