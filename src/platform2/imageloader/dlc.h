// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This class is an abstraction for a Chrome OS Downloadable Content (DLC).
//
// A DLC module is a dynamically installed Chrome OS package that is verified
// via verity on device. DLC provides a way to install packages on demand
// instead of bundling all (used/unused) packages into root file system.
//
// This class verfies and mounts a DLC module image. A DLC module can be
// installed via API provided by dlc_service.

#ifndef IMAGELOADER_DLC_H_
#define IMAGELOADER_DLC_H_

#include <string>

#include <base/files/file_path.h>
#include <base/gtest_prod_util.h>

#include "imageloader/helper_process_proxy.h"

namespace imageloader {

// Enum on the two images (A/B) for one DLC module.
// We keep two copies (A/B) for each DLC module in order to sync with platform
// AutoUpdate (A/B update).
enum class AOrB { kDlcA, kDlcB, kUnknown };

class Dlc {
 public:
  explicit Dlc(const std::string& id,
               const std::string& package,
               const base::FilePath& mount_base);
  Dlc(const Dlc&) = delete;
  Dlc& operator=(const Dlc&) = delete;

  // Mount the image.
  bool Mount(HelperProcessProxy* proxy, const std::string& a_or_b);

  // Mount the image at path.
  bool Mount(HelperProcessProxy* proxy, const base::FilePath& path);

  // Returns the directory where the DLC will be mounted. look at |mount_base_|.
  base::FilePath GetMountPoint();

  // Static version of the above function.
  static base::FilePath GetMountPoint(const base::FilePath& mount_base,
                                      const std::string& id,
                                      const std::string& package);

 private:
  FRIEND_TEST_ALL_PREFIXES(DlcTest, MountDlc);
  // Mount the image from |image_path| to |mount_point| using imageloader.json
  // at |manifest_path| and table at |table_path|
  bool Mount(HelperProcessProxy* proxy,
             const base::FilePath& image_path,
             const base::FilePath& manifest_path,
             const base::FilePath& table_path,
             const base::FilePath& mount_point);

  // Get the path to the DLC manifest (imageloader.json)
  base::FilePath GetManifestPath();

  // Get the path to the table file.
  base::FilePath GetTablePath();

  // Get the path to the DLC image itself.
  base::FilePath GetImagePath(const AOrB a_or_b);

  // ID of the DLC module image.
  std::string id_;

  // Package ID of the DLC module image.
  std::string package_;

  // The base directory where we need to mount the image. The DLC image will be
  // mounted at |mount_base|/|id_|/|package_|/a_or_b.
  base::FilePath mount_base_;
};

}  // namespace imageloader

#endif  // IMAGELOADER_DLC_H_
