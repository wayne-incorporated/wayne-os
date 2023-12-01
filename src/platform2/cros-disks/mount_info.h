// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_MOUNT_INFO_H_
#define CROS_DISKS_MOUNT_INFO_H_

#include <string>
#include <vector>

#include <gtest/gtest_prod.h>

namespace cros_disks {

struct MountPointData;

// A class for querying information about mount points.
class MountInfo {
 public:
  MountInfo();
  MountInfo(const MountInfo&) = delete;
  MountInfo& operator=(const MountInfo&) = delete;

  ~MountInfo();

  // Decodes an encoded path by replacing any occurrence of \xxx, a backslash
  // followed by an octal number, with an ASCII character of the same octal
  // value.
  std::string DecodePath(const std::string& encoded_path) const;

  // Returns the list of mount paths associated with a given source path.
  std::vector<std::string> GetMountPaths(const std::string& source_path) const;

  // Returns true if a given mount path is found among the mount points.
  bool HasMountPath(const std::string& mount_path) const;

  // Retrieves the list of mount points from a given file, which has
  // the same format as /proc/self/mountinfo. Returns true on success.
  // Refer to <linux source>/Documentation/filesystems/proc.txt for details
  // about /proc/self/mountinfo.
  // TODO(crbug.com/1163081): This should be replaced with using libmount.
  bool RetrieveFromFile(const std::string& path);

  // Retrieves the list of mount points of the current process by reading
  // /proc/self/mountinfo. Returns true on success.
  bool RetrieveFromCurrentProcess();

 private:
  // Converts a 3-character octal string into a decimal integer.
  // Returns -1 if the conversion fails.
  int ConvertOctalStringToInt(const std::string& octal) const;

  // A list of mount points gathered by the last call to RetrieveMountInfo().
  std::vector<MountPointData> mount_points_;

  FRIEND_TEST(MountInfoTest, ConvertOctalStringToInt);
};

}  // namespace cros_disks

#endif  // CROS_DISKS_MOUNT_INFO_H_
