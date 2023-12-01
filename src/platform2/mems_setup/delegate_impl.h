// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEMS_SETUP_DELEGATE_IMPL_H_
#define MEMS_SETUP_DELEGATE_IMPL_H_

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <chromeos-config/libcros_config/cros_config.h>

#include "mems_setup/delegate.h"

namespace mems_setup {

// This is an implementation detail of the DelegateImpl, but it is made
// visible for testing purposes
bool LoadVpdFromString(const std::string& vpd_data,
                       std::map<std::string, std::string>* cache);

class DelegateImpl : public Delegate {
 public:
  DelegateImpl();

  std::optional<std::string> ReadVpdValue(const std::string& key) override;
  bool ProbeKernelModule(const std::string& module) override;

  bool CreateDirectory(const base::FilePath&) override;
  bool Exists(const base::FilePath&) override;
  std::vector<base::FilePath> EnumerateAllFiles(
      base::FilePath file_path) override;

  std::optional<gid_t> FindGroupId(const char* group) override;

  int GetPermissions(const base::FilePath& path) override;
  bool SetPermissions(const base::FilePath& path, int mode) override;

  bool SetOwnership(const base::FilePath& path,
                    uid_t user,
                    gid_t group) override;

  std::optional<std::string> GetIioSarSensorDevlink(
      std::string sys_path) override;

  brillo::CrosConfigInterface* GetCrosConfig() override;

 private:
  void LoadVpdIfNeeded();

  std::map<std::string, std::string> vpd_cache_;
  bool vpd_loaded_ = false;

  brillo::CrosConfig cros_config_;
};

}  // namespace mems_setup

#endif  // MEMS_SETUP_DELEGATE_IMPL_H_
