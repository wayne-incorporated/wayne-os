// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <chromeos-config/libcros_config/fake_cros_config.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "runtime_probe/generic_probe_config_loader.h"
#include "runtime_probe/system/context_mock_impl.h"
#include "runtime_probe/utils/file_test_utils.h"

namespace runtime_probe {

namespace {

constexpr char kConfigName[] = "probe_config.json";
constexpr char kConfigHash[] = "14127A36F3A2509343AF7F19387537F608B07EE1";

base::FilePath GetTestDataPath() {
  char* src_env = std::getenv("SRC");
  CHECK(src_env != nullptr)
      << "Expect to have the envvar |SRC| set when testing.";
  return base::FilePath(src_env).Append("testdata");
}

class GenericProbeConfigLoaderTest : public BaseFileTest {
 protected:
  void SetUp() {
    SetTestRoot(Context::Get()->root_dir());
    testdata_root_ = GetTestDataPath();
  }

  // Sets cros_debug flag to the given value.
  void SetCrosDebug(CrosDebugFlag value) {
    mock_context_.fake_crossystem()->VbSetSystemPropertyInt(
        kCrosSystemCrosDebugKey, static_cast<int>(value));
  }

  base::FilePath testdata_root_;

 private:
  ContextMockImpl mock_context_;
};

}  // namespace

TEST_F(GenericProbeConfigLoaderTest, Load_NoCrosDebugEnabled) {
  for (const auto cros_config_flag :
       {CrosDebugFlag::kDisabled, CrosDebugFlag::kUnknown}) {
    SetCrosDebug(cros_config_flag);
    const auto rel_file_path = testdata_root_.Append(kConfigName);

    GenericProbeConfigLoader probe_config_loader{rel_file_path};
    const auto probe_config = probe_config_loader.Load();
    EXPECT_FALSE(probe_config);
  }
}

TEST_F(GenericProbeConfigLoaderTest, Load_CrosDebugEnabled) {
  SetCrosDebug(CrosDebugFlag::kEnabled);
  const auto rel_file_path = testdata_root_.Append(kConfigName);
  const auto abs_file_path = base::MakeAbsoluteFilePath(rel_file_path);

  GenericProbeConfigLoader probe_config_loader{rel_file_path};
  const auto probe_config = probe_config_loader.Load();
  EXPECT_TRUE(probe_config);
  EXPECT_EQ(probe_config->path(), abs_file_path);
  EXPECT_EQ(probe_config->checksum(), kConfigHash);
}

}  // namespace runtime_probe
