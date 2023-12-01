// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <string>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <re2/re2.h>

namespace {

constexpr char kUSB4Sysfs[] = "/sys/bus/thunderbolt/devices";
constexpr char kUSB4Debugfs[] = "/sys/kernel/debug/thunderbolt";

constexpr char kUSB4HostDevice[] = "0-0";
constexpr char kUSB4HostDomain[] = "domain0";
constexpr char kPCICSDeviceIDOffset = 0;

// The format of the reg dump is:
// # offset relative_offset cap_id vs_cap_id value
// 0x0000    0 0x00 0x00 0x15ef8086
// 0x0001    1 0x00 0x00 0x06134305
// 0x0002    2 0x00 0x00 0x00000001
// Since we are interested in only the first and last hex, we use the following
// regex.
constexpr char kTBTControllerRegex[] =
    R"((0x[0-9a-f]+)\s+\d+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+(0x[0-9a-f]+))";

// Set of Device IDs for Alpine Ridge and Titan Ridge docks. These values are
// taken from:
// https://elixir.bootlin.com/linux/v5.11-rc7/source/drivers/thunderbolt/nhi.h#L54
//
// and the PCI IDs listed as Alpine Ridge here:
// https://pci-ids.ucw.cz/read/PC/8086
//
// TODO(pmalani, b/180026806): If any addition is noticed there, it should be
// added here too.
constexpr uint16_t kAlpineRidgeIDs[] = {
    0x1575, 0x1576, 0x1577, 0x1578, 0x15b5, 0x15b6, 0x15bf, 0x15c0, 0x15c1,
    0x15d2, 0x15d3, 0x15d4, 0x15d9, 0x15da, 0x15db, 0x15dc, 0x15dd, 0x15de,
};

constexpr uint16_t kTitanRidgeIDs[] = {
    0x15e7, 0x15e8, 0x15ea, 0x15eb, 0x15ef, 0x15f0,
};

void PrintSysfsNode(const base::FilePath& dev, const std::string& node_name) {
  std::string str;

  auto auth_path = dev.Append(node_name);
  // If we can't read the sysfs entry, just return silently.
  if (!base::ReadFileToString(auth_path, &str))
    return;

  base::TrimWhitespaceASCII(str, base::TRIM_TRAILING, &str);
  std::cout << node_name << ": " << str << std::endl;
}

void PrintTBTControllerVersion(const std::string& dev_name) {
  auto path = base::FilePath(kUSB4Debugfs).Append(dev_name).Append("regs");

  std::string str;
  if (!base::ReadFileToString(path, &str))
    return;

  std::vector<std::string> entries = base::SplitString(
      str, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  // Go through each reg entry till you find offset 0. This is generally the 2nd
  // entry, so it shouldn't take long.
  for (auto& entry : entries) {
    std::string offset_str, vid_did_str;
    uint32_t offset, vid_did;
    base::TrimWhitespaceASCII(entry, base::TRIM_TRAILING, &entry);
    if (!RE2::FullMatch(entry, kTBTControllerRegex, &offset_str, &vid_did_str))
      continue;

    if (!base::HexStringToUInt(offset_str.c_str(), &offset) ||
        !base::HexStringToUInt(vid_did_str.c_str(), &vid_did)) {
      continue;
    }

    if (offset != kPCICSDeviceIDOffset)
      continue;

    uint16_t device_id = vid_did >> 16;
    std::string controller_family;

    std::vector<uint16_t> ar(std::begin(kAlpineRidgeIDs),
                             std::end(kAlpineRidgeIDs));
    auto it = std::find(ar.begin(), ar.end(), device_id);
    if (it != ar.end())
      controller_family = "Alpine Ridge";

    std::vector<uint16_t> tr(std::begin(kTitanRidgeIDs),
                             std::end(kTitanRidgeIDs));
    it = std::find(tr.begin(), tr.end(), device_id);
    if (it != tr.end())
      controller_family = "Titan Ridge";

    // Return if this is a controller family which isn't in our known list.
    // We don't want to print out device IDs for unknown controller families
    // since we don't know how privacy-sensitive those identifiers might be.
    if (controller_family.empty())
      return;

    std::cout << "Thunderbolt controller type: " << controller_family
              << std::endl;
    return;
  }
}

void PrintDeviceInfo(const base::FilePath& dev) {
  std::cout << "device bus name: " << dev.BaseName() << std::endl;

  PrintSysfsNode(dev, "authorized");
  PrintSysfsNode(dev, "generation");
  PrintSysfsNode(dev, "rx_lanes");
  PrintSysfsNode(dev, "rx_speed");
  PrintTBTControllerVersion(dev.BaseName().value());
  std::cout << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
  base::FileEnumerator it(base::FilePath(kUSB4Sysfs), false,
                          base::FileEnumerator::DIRECTORIES);
  for (base::FilePath dev = it.Next(); !dev.empty(); dev = it.Next()) {
    auto name = dev.BaseName().value();

    // We don't care about the host device or domain.
    if (name == kUSB4HostDevice || name == kUSB4HostDomain)
      continue;

    PrintDeviceInfo(dev);
  }

  return EXIT_SUCCESS;
}
