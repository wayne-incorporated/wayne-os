// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEMS_SETUP_DELEGATE_H_
#define MEMS_SETUP_DELEGATE_H_

#include <unistd.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <chromeos-config/libcros_config/cros_config_interface.h>
#include <libsar/sar_config_reader.h>

namespace mems_setup {

class Delegate {
 public:
  virtual ~Delegate() = default;

  virtual std::optional<std::string> ReadVpdValue(const std::string& key) = 0;
  virtual bool ProbeKernelModule(const std::string& module) = 0;

  virtual bool CreateDirectory(const base::FilePath&) = 0;
  virtual bool Exists(const base::FilePath&) = 0;
  virtual std::vector<base::FilePath> EnumerateAllFiles(
      base::FilePath file_path) = 0;

  libsar::SarConfigReader::Delegate* GetSarConfigReaderDelegate() {
    return sar_config_reader_delegate_.get();
  }

  virtual std::optional<gid_t> FindGroupId(const char* group) = 0;

  virtual int GetPermissions(const base::FilePath& path) = 0;
  virtual bool SetPermissions(const base::FilePath& path, int mode) = 0;

  virtual bool SetOwnership(const base::FilePath& path,
                            uid_t user,
                            gid_t group) = 0;

  virtual std::optional<std::string> GetIioSarSensorDevlink(
      std::string sys_path) = 0;

  virtual brillo::CrosConfigInterface* GetCrosConfig() = 0;

 protected:
  Delegate(std::unique_ptr<libsar::SarConfigReader::Delegate>
               sar_config_reader_delegate)
      : sar_config_reader_delegate_(std::move(sar_config_reader_delegate)) {}
  Delegate(const Delegate&) = delete;
  Delegate& operator=(const Delegate&) = delete;

  std::unique_ptr<libsar::SarConfigReader::Delegate>
      sar_config_reader_delegate_;
};

}  // namespace mems_setup

#endif  // MEMS_SETUP_DELEGATE_H_
