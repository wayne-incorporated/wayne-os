// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGELOADER_VERITY_MOUNTER_H_
#define IMAGELOADER_VERITY_MOUNTER_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/gtest_prod_util.h>

namespace imageloader {

// Timeout for dmsetup.
constexpr int kDMSetupTimeoutSeconds = 30;

class VerityMounter {
 public:
  VerityMounter() = default;
  VerityMounter(const VerityMounter&) = delete;
  VerityMounter& operator=(const VerityMounter&) = delete;

  virtual ~VerityMounter() = default;

  virtual bool Mount(const base::ScopedFD& image_fd,
                     const base::FilePath& mount_point,
                     const std::string& fs_type,
                     const std::string& table);

  bool Cleanup(const base::FilePath& mount_point);

  bool CleanupAll(bool dry_run,
                  const base::FilePath& parent_dir,
                  std::vector<base::FilePath>* paths);

  // Take the raw table, clean up any newlines, insert the device_path, and add
  // the correct error_condition.
  static bool SetupTable(std::string* table, const std::string& device_path);
};

}  // namespace imageloader

#endif  // IMAGELOADER_VERITY_MOUNTER_H_
