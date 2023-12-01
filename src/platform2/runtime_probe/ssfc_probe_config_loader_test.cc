// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <chromeos-config/libcros_config/fake_cros_config.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "runtime_probe/ssfc_probe_config_loader.h"
#include "runtime_probe/system/context_mock_impl.h"
#include "runtime_probe/utils/file_test_utils.h"

namespace runtime_probe {

namespace {

base::FilePath GetTestDataPath() {
  char* src_env = std::getenv("SRC");
  CHECK(src_env != nullptr)
      << "Expect to have the envvar |SRC| set when testing.";
  return base::FilePath(src_env).Append("testdata");
}

class SsfcProbeConfigLoaderTest : public BaseFileTest {
 protected:
  void SetUp() {
    SetTestRoot(Context::Get()->root_dir());
    testdata_root_ = GetTestDataPath();
  }

  // Sets model names to the given value.
  void SetModelName(const std::string& val) {
    mock_context_.fake_cros_config()->SetString(kCrosConfigModelNamePath,
                                                kCrosConfigModelNameKey, val);
  }

  // Sets cros_debug flag to the given value.
  void SetCrosDebug(CrosDebugFlag value) {
    mock_context_.fake_crossystem()->VbSetSystemPropertyInt(
        kCrosSystemCrosDebugKey, static_cast<int>(value));
  }

  // Creates parent directories as needed before copying the file.
  bool CreateDirectoryAndCopyFile(const base::FilePath& from_path,
                                  const base::FilePath& to_path) const {
    PCHECK(base::CreateDirectoryAndGetError(to_path.DirName(), nullptr));
    PCHECK(base::CopyFile(from_path, to_path));
    return true;
  }

  SsfcProbeConfigLoader probe_config_loader_;
  base::FilePath testdata_root_;

 private:
  ContextMockImpl mock_context_;
};

}  // namespace

TEST_F(SsfcProbeConfigLoaderTest, Load_RootfsWhenCrosDebugDisabled) {
  constexpr char kModelName[] = "ModelFoo";
  SetCrosDebug(CrosDebugFlag::kDisabled);
  SetModelName(kModelName);
  constexpr char kConfigAHash[] = "77DCF20DC22837B9E90D162C0D3A4DB1B16BFEDB";
  const base::FilePath rootfs_config_path = root_dir()
                                                .Append(kRuntimeProbeConfigDir)
                                                .Append(kModelName)
                                                .Append(kSsfcProbeConfigName);
  const base::FilePath stateful_partition_config_path =
      root_dir()
          .Append(kUsrLocal)
          .Append(kRuntimeProbeConfigDir)
          .Append(kModelName)
          .Append(kSsfcProbeConfigName);

  // Copy config_a to rootfs.
  CreateDirectoryAndCopyFile(testdata_root_.Append("probe_config_ssfc.json"),
                             rootfs_config_path);
  // Copy config_b to stateful partition.
  CreateDirectoryAndCopyFile(testdata_root_.Append("probe_config_ssfc_b.json"),
                             stateful_partition_config_path);

  const auto probe_config = probe_config_loader_.Load();
  EXPECT_TRUE(probe_config);
  EXPECT_EQ(probe_config->path(), rootfs_config_path);
  EXPECT_EQ(probe_config->checksum(), kConfigAHash);
}

TEST_F(SsfcProbeConfigLoaderTest, Load_StatefulPartitionWhenCrosDebugEnabled) {
  constexpr char kModelName[] = "ModelFoo";
  SetCrosDebug(CrosDebugFlag::kEnabled);
  SetModelName(kModelName);
  constexpr char kConfigBHash[] = "2B99CBEA041B0C0B273893116A6204C04E0F9D0D";
  const base::FilePath rootfs_config_path = root_dir()
                                                .Append(kRuntimeProbeConfigDir)
                                                .Append(kModelName)
                                                .Append(kSsfcProbeConfigName);
  const base::FilePath stateful_partition_config_path =
      root_dir()
          .Append(kUsrLocal)
          .Append(kRuntimeProbeConfigDir)
          .Append(kModelName)
          .Append(kSsfcProbeConfigName);

  // Copy config_a to rootfs.
  CreateDirectoryAndCopyFile(testdata_root_.Append("probe_config_ssfc.json"),
                             rootfs_config_path);
  // Copy config_b to stateful partition.
  CreateDirectoryAndCopyFile(testdata_root_.Append("probe_config_ssfc_b.json"),
                             stateful_partition_config_path);

  const auto probe_config = probe_config_loader_.Load();
  EXPECT_TRUE(probe_config);
  EXPECT_EQ(probe_config->path(), stateful_partition_config_path);
  EXPECT_EQ(probe_config->checksum(), kConfigBHash);
}

TEST_F(SsfcProbeConfigLoaderTest, Load_RootfsWhenCrosDebugEnabled) {
  constexpr char kModelName[] = "ModelFoo";
  SetCrosDebug(CrosDebugFlag::kEnabled);
  SetModelName(kModelName);
  constexpr char kConfigAHash[] = "77DCF20DC22837B9E90D162C0D3A4DB1B16BFEDB";
  const base::FilePath rootfs_config_path = root_dir()
                                                .Append(kRuntimeProbeConfigDir)
                                                .Append(kModelName)
                                                .Append(kSsfcProbeConfigName);
  // Copy config_a to rootfs. No configs under stateful partition.
  CreateDirectoryAndCopyFile(testdata_root_.Append("probe_config_ssfc.json"),
                             rootfs_config_path);

  const auto probe_config = probe_config_loader_.Load();
  EXPECT_TRUE(probe_config);
  EXPECT_EQ(probe_config->path(), rootfs_config_path);
  EXPECT_EQ(probe_config->checksum(), kConfigAHash);
}

TEST_F(SsfcProbeConfigLoaderTest, Load_MissingFileFailed) {
  constexpr char kModelName[] = "ModelFoo";
  SetCrosDebug(CrosDebugFlag::kDisabled);
  SetModelName(kModelName);

  const auto probe_config = probe_config_loader_.Load();
  EXPECT_FALSE(probe_config);
}

TEST_F(SsfcProbeConfigLoaderTest, Load_NotAllowedProbeFunctionsFailed) {
  constexpr char kModelName[] = "ModelFoo";
  SetCrosDebug(CrosDebugFlag::kDisabled);
  SetModelName(kModelName);
  const base::FilePath rootfs_config_path = root_dir()
                                                .Append(kRuntimeProbeConfigDir)
                                                .Append(kModelName)
                                                .Append(kSsfcProbeConfigName);

  // Copy invalid probe config (AVL) to rootfs.
  CreateDirectoryAndCopyFile(testdata_root_.Append("probe_config.json"),
                             rootfs_config_path);

  const auto probe_config = probe_config_loader_.Load();
  EXPECT_FALSE(probe_config);
}

}  // namespace runtime_probe
