// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/dlc.h"

#include <set>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <chromeos/constants/imageloader.h>
#include <chromeos/dbus/service_constants.h>

#include "imageloader/component.h"
#include "imageloader/manifest.h"

namespace imageloader {

namespace {

// The name of the image.
constexpr char kImageName[] = "dlc.img";
constexpr char kSlotAName[] = "dlc_a";
constexpr char kSlotBName[] = "dlc_b";
constexpr char kManifestFileName[] = "imageloader.json";
constexpr char kTableFileName[] = "table";

AOrB GetImageAOrB(const std::string& a_or_b) {
  if (a_or_b == imageloader::kSlotNameA) {
    return AOrB::kDlcA;
  } else if (a_or_b == imageloader::kSlotNameB) {
    return AOrB::kDlcB;
  } else {
    return AOrB::kUnknown;
  }
}

}  // namespace

Dlc::Dlc(const std::string& id,
         const std::string& package,
         const base::FilePath& mount_base)
    : id_(id), package_(package), mount_base_(mount_base) {}

base::FilePath Dlc::GetManifestPath() {
  return base::FilePath(kDlcManifestRootpath)
      .Append(id_)
      .Append(package_)
      .Append(kManifestFileName);
}

base::FilePath Dlc::GetTablePath() {
  return base::FilePath(kDlcManifestRootpath)
      .Append(id_)
      .Append(package_)
      .Append(kTableFileName);
}

base::FilePath Dlc::GetImagePath(const AOrB a_or_b) {
  base::FilePath root =
      base::FilePath(kDlcImageRootpath).Append(id_).Append(package_);
  if (a_or_b == AOrB::kDlcA) {
    return root.Append(kSlotAName).Append(kImageName);
  } else if (a_or_b == AOrB::kDlcB) {
    return root.Append(kSlotBName).Append(kImageName);
  } else {
    return base::FilePath();
  }
}

// static
base::FilePath Dlc::GetMountPoint(const base::FilePath& mount_base,
                                  const std::string& id,
                                  const std::string& package) {
  return mount_base.Append(id).Append(package);
}

base::FilePath Dlc::GetMountPoint() {
  return GetMountPoint(mount_base_, id_, package_);
}

bool Dlc::Mount(HelperProcessProxy* proxy, const std::string& a_or_b_str) {
  AOrB a_or_b = GetImageAOrB(a_or_b_str);

  if (a_or_b == AOrB::kUnknown) {
    LOG(ERROR) << "Unknown image type: " << a_or_b_str;
    return false;
  }

  return Mount(proxy, GetImagePath(a_or_b), GetManifestPath(), GetTablePath(),
               GetMountPoint());
}

bool Dlc::Mount(HelperProcessProxy* proxy, const base::FilePath& path) {
  return Mount(proxy, path, GetManifestPath(), GetTablePath(), GetMountPoint());
}

bool Dlc::Mount(HelperProcessProxy* proxy,
                const base::FilePath& image_path,
                const base::FilePath& manifest_path,
                const base::FilePath& table_path,
                const base::FilePath& mount_point) {
  std::string manifest_raw;
  if (!base::ReadFileToStringWithMaxSize(manifest_path, &manifest_raw,
                                         kMaximumFilesize)) {
    LOG(ERROR) << "Could not read manifest file: " << manifest_path.value();
    return false;
  }
  Manifest manifest;
  if (!manifest.ParseManifest(manifest_raw))
    return false;

  std::string table;
  if (!base::ReadFileToStringWithMaxSize(table_path, &table,
                                         kMaximumFilesize)) {
    LOG(ERROR) << "Could not read table.";
    return false;
  }
  base::File image(image_path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!image.IsValid()) {
    LOG(ERROR) << "Could not open image file '" << image_path.value()
               << "': " << base::File::ErrorToString(image.error_details());
    return false;
  }
  base::ScopedFD image_fd(image.TakePlatformFile());

  return proxy->SendMountCommand(image_fd.get(), mount_point.value(),
                                 manifest.fs_type(), table);
}

}  // namespace imageloader
