// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PCIGUARD_SYSFS_UTILS_H_
#define PCIGUARD_SYSFS_UTILS_H_

#include <base/files/file_util.h>
#include <gtest/gtest_prod.h>
#include <memory>
#include <string>

using base::FilePath;

namespace pciguard {

class SysfsUtils {
 public:
  SysfsUtils();
  virtual ~SysfsUtils() = default;
  virtual int OnInit(void);
  virtual int AuthorizeThunderboltDev(base::FilePath devpath);
  virtual int AuthorizeAllDevices(void);
  virtual int DeauthorizeAllDevices(void);
  virtual int DenyNewDevices(void);

 private:
  explicit SysfsUtils(FilePath root);
  const FilePath allowlist_path_;
  const FilePath pci_lockdown_path_;
  const FilePath pci_rescan_path_;
  const FilePath tbt_devices_path_;
  const FilePath pci_devices_path_;

  int SetAuthorizedAttribute(base::FilePath devpath, bool enable);
  int DeauthorizeThunderboltDev(base::FilePath devpath);

  friend class SysfsUtilsTest;
  FRIEND_TEST(SysfsUtilsTest, CheckDenyNewDevices);
  FRIEND_TEST(SysfsUtilsTest, CheckDeauthorizeAllDevices);
  FRIEND_TEST(SysfsUtilsTest, CheckAuthorizeAllDevices);
  friend std::unique_ptr<SysfsUtils> std::make_unique<SysfsUtils>(FilePath&);
};

}  // namespace pciguard

#endif  // PCIGUARD_SYSFS_UTILS_H_
