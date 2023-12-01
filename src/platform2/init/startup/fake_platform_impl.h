// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_STARTUP_FAKE_PLATFORM_IMPL_H_
#define INIT_STARTUP_FAKE_PLATFORM_IMPL_H_

#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

#include <base/files/file_util.h>

#include "init/startup/platform_impl.h"

namespace startup {

// This class is utilized by tests to override functions that
// use of system calls or other functionality that utilizes
// system command outputs.

class FakePlatform : public Platform {
 public:
  FakePlatform();

  void SetStatResultForPath(const base::FilePath& path, const struct stat& st);

  void SetStatvfsResultForPath(const base::FilePath& path,
                               const struct statvfs& st);

  void SetMountEncOutputForArg(const std::string& arg,
                               const std::string& output);

  void SetMountResultForPath(const base::FilePath& path,
                             const std::string& output);

  int GetBootAlertForArg(const std::string& arg);

  void SetVpdResult(const int result);

  void SetClobberLogFile(const base::FilePath& path);

  void SetIoctlReturnValue(int ret);

  // `startup::Platform` overrides.
  bool Stat(const base::FilePath& path, struct stat* st) override;
  bool Statvfs(const base::FilePath& path, struct statvfs* st) override;
  bool Mount(const base::FilePath& src,
             const base::FilePath& dst,
             const std::string& type,
             unsigned long flags,  // NOLINT(runtime/int)
             const std::string& data) override;
  bool Mount(const std::string& src,
             const base::FilePath& dst,
             const std::string& type,
             unsigned long flags,  // NOLINT(runtime/int)
             const std::string& data) override;
  bool Umount(const base::FilePath& path) override;
  base::ScopedFD Open(const base::FilePath& pathname, int flags) override;
  // NOLINTNEXTLINE(runtime/int)
  int Ioctl(int fd, unsigned long request, int* arg1) override;

  int MountEncrypted(const std::vector<std::string>& args,
                     std::string* const output) override;

  void BootAlert(const std::string& arg) override;

  bool VpdSlow(const std::vector<std::string>& args,
               std::string* output) override;

  void ClobberLog(const std::string& msg) override;

  void RemoveInBackground(const std::vector<base::FilePath>& paths) override;

 private:
  std::unordered_map<std::string, struct stat> result_map_;
  std::unordered_map<std::string, struct statvfs> result_statvfs_map_;
  std::unordered_map<std::string, std::string> mount_result_map_;
  std::vector<std::string> umount_vector_;
  int open_ret_ = -1;
  int ioctl_ret_ = 0;
  std::unordered_map<std::string, std::string> mount_enc_result_map_;
  std::unordered_map<std::string, int> alert_result_map_;
  int vpd_result_;
  base::FilePath clobber_log_;
};

}  // namespace startup

#endif  // INIT_STARTUP_FAKE_PLATFORM_IMPL_H_
