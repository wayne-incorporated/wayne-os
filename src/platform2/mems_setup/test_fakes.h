// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEMS_SETUP_TEST_FAKES_H_
#define MEMS_SETUP_TEST_FAKES_H_

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <chromeos-config/libcros_config/fake_cros_config.h>
#include <libmems/test_fakes.h>
#include <libsar/test_fakes.h>

#include "mems_setup/delegate.h"

namespace mems_setup {
namespace fakes {

class FakeDelegate : public Delegate {
 public:
  FakeDelegate();

  void SetVpdValue(const std::string& name, const std::string& value) {
    CHECK(!name.empty());
    CHECK(!value.empty());
    vpd_.emplace(name, value);
  }

  std::optional<std::string> ReadVpdValue(const std::string& key) override;

  bool ProbeKernelModule(const std::string& module) override;

  size_t GetNumModulesProbed() const { return probed_modules_.size(); }

  bool CreateDirectory(const base::FilePath&) override;
  bool Exists(const base::FilePath&) override;
  std::vector<base::FilePath> EnumerateAllFiles(
      base::FilePath file_path) override;

  void CreateFile(const base::FilePath&);
  void SetStringToFile(const base::FilePath&, const std::string&);

  std::optional<gid_t> FindGroupId(const char* group) override;

  int GetPermissions(const base::FilePath& path) override;
  bool SetPermissions(const base::FilePath& path, int mode) override;

  void AddGroup(const std::string& name, gid_t gid) {
    groups_.emplace(name, gid);
  }

  bool GetOwnership(const base::FilePath& path, uid_t* user, gid_t* group);
  bool SetOwnership(const base::FilePath& path,
                    uid_t user,
                    gid_t group) override;

  void SetMockDevlink(std::string mock_devlink) {
    mock_devlink_ = mock_devlink;
  }
  std::optional<std::string> GetIioSarSensorDevlink(
      std::string sys_path) override;

  brillo::CrosConfigInterface* GetCrosConfig() override;
  brillo::FakeCrosConfig* GetFakeCrosConfig();

  void SetMockContext(libmems::fakes::FakeIioContext* mock_context) {
    mock_context_ = mock_context;
  }

 private:
  std::vector<std::string> probed_modules_;
  std::map<std::string, std::string> vpd_;
  std::map<std::string, gid_t> groups_;
  std::map<std::string, int> permissions_;
  std::map<std::string, std::pair<uid_t, gid_t>> ownerships_;
  std::set<base::FilePath> existing_files_;
  std::optional<std::string> mock_devlink_;
  std::unique_ptr<brillo::FakeCrosConfig> cros_config_;

  libmems::fakes::FakeIioContext* mock_context_ = nullptr;
};

}  // namespace fakes

}  // namespace mems_setup

#endif  // MEMS_SETUP_TEST_FAKES_H_
