// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/storage/device_resolver.h"

#include <list>
#include <memory>
#include <string>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <re2/re2.h>

#include <libmount/libmount.h>

#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kDevFsPrefix[] = "/dev/";
constexpr char kSysBlockPath[] = "sys/block/";
constexpr char kProcSwapsPath[] = "proc/swaps";
constexpr char kDmPrefix[] = "dm-";
constexpr char kSlavesDir[] = "slaves/";

// Callback for the libmount parser.
int ParserErrCb(struct libmnt_table* unused, const char* filename, int line) {
  LOG(ERROR) << filename << ": parser encountered error at line " << line;
  return 1;
}

}  // namespace

base::expected<std::unique_ptr<StorageDeviceResolver>, mojom::ProbeErrorPtr>
StorageDeviceResolver::Create(const base::FilePath& rootfs,
                              const std::string& root_device) {
  if (auto devs_result = GetSwapDevices(rootfs); devs_result.has_value()) {
    return std::unique_ptr<StorageDeviceResolver>(
        new StorageDeviceResolver(devs_result.value(), root_device));
  } else {
    return base::unexpected(devs_result.error()->Clone());
  }
}

StorageDeviceResolver::StorageDeviceResolver(
    const std::set<std::string>& swap_backing_devices,
    const std::string& root_device)
    : swap_backing_devices_(swap_backing_devices), root_device_(root_device) {}

// GetSwapDevices parses /proc/swaps via libmount to retrieve the list of swap
// devices and then call into a method to find out the backing physical devices.
base::expected<std::set<std::string>, mojom::ProbeErrorPtr>
StorageDeviceResolver::GetSwapDevices(const base::FilePath& rootfs) {
  auto table = mnt_new_table();
  mnt_reset_table(table);
  mnt_table_set_parser_errcb(table, ParserErrCb);

  auto swaps_path = rootfs.Append(kProcSwapsPath);

  if (mnt_table_parse_swaps(table, swaps_path.value().c_str()) != 0) {
    mnt_free_table(table);
    return base::unexpected(
        CreateAndLogProbeError(mojom::ErrorType::kParseError,
                               "Invalid format of " + swaps_path.value()));
  }

  std::list<std::string> swaps;
  struct libmnt_fs* fs;
  struct libmnt_iter* itr = mnt_new_iter(MNT_ITER_FORWARD);

  while (mnt_table_next_fs(table, itr, &fs) == 0) {
    std::string swap_dev = mnt_fs_get_srcpath(fs);

    // Zram swap device filename in /proc/swaps can be either /dev/zram[0-9] or
    // /zram[0-9] (see b/248317295). Since zram is non-disk based device, we
    // can just skip.
    if (RE2::FullMatch(swap_dev, R"((\/dev)?\/zram\d)"))
      continue;

    // If not zram, we expect devices of the format "/dev/<blah>"
    if (swap_dev.find(kDevFsPrefix) != 0) {
      mnt_free_iter(itr);
      mnt_free_table(table);
      return base::unexpected(CreateAndLogProbeError(
          mojom::ErrorType::kFileReadError,
          "Unexpected swap device location: " + swap_dev));
    }
    swap_dev = swap_dev.substr(std::string(kDevFsPrefix).length());
    if (swap_dev.find("/") != std::string::npos) {
      mnt_free_iter(itr);
      mnt_free_table(table);
      return base::unexpected(CreateAndLogProbeError(
          mojom::ErrorType::kFileReadError,
          "Swap device name shall not contain slashes: " + swap_dev));
    }
    swaps.push_back(swap_dev);
  }

  mnt_free_iter(itr);
  mnt_free_table(table);

  return ResolveDevices(rootfs, swaps);
}

// ResolveDevices determines which physical device is backing the swap device.
// For now check only for the simplest 0-indirection, or single devmapper layer
// for encryption and print an error in case any more complicated setup is
// observed.
base::expected<std::set<std::string>, mojom::ProbeErrorPtr>
StorageDeviceResolver::ResolveDevices(const base::FilePath& rootfs,
                                      const std::list<std::string>& swap_devs) {
  std::set<std::string> result;
  for (auto swap_dev : swap_devs) {
    auto backing_dev = swap_dev;
    if (swap_dev.find(kDmPrefix) == 0) {
      auto path =
          rootfs.Append(kSysBlockPath).Append(swap_dev).Append(kSlavesDir);
      base::FileEnumerator lister(path, false,
                                  base::FileEnumerator::DIRECTORIES);

      std::list<std::string> slaves;
      for (base::FilePath device_path = lister.Next(); !device_path.empty();
           device_path = lister.Next()) {
        slaves.push_back(device_path.BaseName().value());
      }

      if (slaves.size() == 0) {
        return base::unexpected(CreateAndLogProbeError(
            mojom::ErrorType::kFileReadError,
            "No physical backing devices found for: " + backing_dev));
      }
      if (slaves.size() > 1) {
        return base::unexpected(CreateAndLogProbeError(
            mojom::ErrorType::kFileReadError,
            "Too many physical backing devices found for: " + backing_dev));
      }

      backing_dev = slaves.front();
      if (backing_dev.find(kDmPrefix) == 0) {
        return base::unexpected(CreateAndLogProbeError(
            mojom::ErrorType::kFileReadError,
            "Multiple devmapper layers found for: " + backing_dev));
      }
    }
    result.insert(backing_dev);
  }
  return result;
}

mojom::StorageDevicePurpose StorageDeviceResolver::GetDevicePurpose(
    const std::string& dev_name) const {
  if (swap_backing_devices_.find(dev_name) != swap_backing_devices_.end())
    return mojom::StorageDevicePurpose::kSwapDevice;
  if (dev_name == root_device_)
    return mojom::StorageDevicePurpose::kBootDevice;
  return mojom::StorageDevicePurpose::kUnknown;
}

}  // namespace diagnostics
