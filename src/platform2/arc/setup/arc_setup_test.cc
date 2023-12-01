// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// How to build and run the tests: see arc_setup_util_unittest.cc

#include "arc/setup/arc_setup.h"

#include <iterator>
#include <set>

#include <base/command_line.h>
#include <base/environment.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "arc/setup/arc_setup_util.h"

namespace arc {

namespace {

class MockArcMounter : public ArcMounter {
 public:
  MockArcMounter() = default;
  MockArcMounter(const MockArcMounter&) = delete;
  MockArcMounter& operator=(const MockArcMounter&) = delete;

  ~MockArcMounter() override = default;

  bool Mount(const std::string& source,
             const base::FilePath& target,
             const char* filesystem_type,
             unsigned long mount_flags,  // NOLINT(runtime/int)
             const char* data) override {
    mount_points_.insert(target.value());
    return true;
  }

  bool Remount(const base::FilePath& target_directory,
               unsigned long mount_flags,  // NOLINT(runtime/int)
               const char* data) override {
    return true;
  }

  bool LoopMount(const std::string& source,
                 const base::FilePath& target,
                 unsigned long mount_flags) override {  // NOLINT(runtime/int)
    loop_mount_points_.insert(target.value());
    return true;
  }

  bool BindMount(const base::FilePath& old_path,
                 const base::FilePath& new_path) override {
    mount_points_.insert(new_path.value());
    return true;
  }

  bool SharedMount(const base::FilePath& path) override { return true; }

  bool Umount(const base::FilePath& path) override {
    auto it = mount_points_.find(path.value());
    if (it == mount_points_.end())
      return false;
    mount_points_.erase(it);
    return true;
  }

  bool UmountIfExists(const base::FilePath& path) override {
    Umount(path);
    // If mount does not exist, succeed anyway.
    return true;
  }

  bool LoopUmount(const base::FilePath& path) override {
    auto it = loop_mount_points_.find(path.value());
    if (it == loop_mount_points_.end())
      return false;
    loop_mount_points_.erase(it);
    return true;
  }

  bool LoopUmountIfExists(const base::FilePath& path) override {
    LoopUmount(path);
    // If loop mount does not exist, succeed anyway.
    return true;
  }

  std::multiset<std::string> mount_points_;
  std::multiset<std::string> loop_mount_points_;
};

}  // namespace

// Tests MockArcMounter itself.
TEST(ArcSetup, TestMockArcMounter) {
  MockArcMounter mounter;
  EXPECT_TRUE(mounter.BindMount(base::FilePath("/a"), base::FilePath("/b")));
  EXPECT_TRUE(mounter.BindMount(base::FilePath("/c"), base::FilePath("/b")));
  EXPECT_EQ(2U, mounter.mount_points_.size());
  EXPECT_FALSE(mounter.Umount(base::FilePath("/x")));  // unknown path
  EXPECT_TRUE(mounter.Umount(base::FilePath("/b")));
  EXPECT_EQ(1U, mounter.mount_points_.size());
  EXPECT_TRUE(mounter.Umount(base::FilePath("/b")));
  EXPECT_TRUE(mounter.mount_points_.empty());
  EXPECT_FALSE(mounter.Umount(base::FilePath("/b")));  // now /b is unknown

  // Do the same for loop.
  EXPECT_TRUE(mounter.LoopMount("/a.img", base::FilePath("/d"), 0U));
  EXPECT_TRUE(mounter.LoopMount("/c.img", base::FilePath("/d"), 0U));
  EXPECT_EQ(2U, mounter.loop_mount_points_.size());
  EXPECT_FALSE(mounter.LoopUmount(base::FilePath("/x")));  // unknown path
  EXPECT_TRUE(mounter.LoopUmount(base::FilePath("/d")));
  EXPECT_EQ(1U, mounter.loop_mount_points_.size());
  EXPECT_TRUE(mounter.LoopUmount(base::FilePath("/d")));
  EXPECT_TRUE(mounter.loop_mount_points_.empty());
  EXPECT_FALSE(mounter.LoopUmount(base::FilePath("/d")));  // now /d is unknown
}

// Tests --mode=onetime-setup and --mode=onetime-stop.
TEST(ArcSetup, TestOnetimeSetupStop) {
  const char* argv[] = {"test", "--mode=onetime-setup"};
  base::CommandLine::ForCurrentProcess()->InitFromArgv(std::size(argv), argv);
  std::unique_ptr<base::Environment> env(base::Environment::Create());

  // ArcSetup needs some config variables.
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  const base::FilePath config_json(temp_directory.GetPath().Append("json"));
  ASSERT_TRUE(WriteToFile(config_json, 0700, "{\"WRITABLE_MOUNT\": false}"));

  ArcSetup setup(Mode::ONETIME_SETUP, config_json);
  setup.set_arc_mounter_for_testing(std::make_unique<MockArcMounter>());

  // Do the one-time setup and confirm both loop and non-loop mount points are
  // not empty.
  setup.MountOnOnetimeSetupForTesting();
  // Check that |loop_mount_points_| has system and vendor images etc.
  EXPECT_FALSE(
      static_cast<const MockArcMounter*>(setup.arc_mounter_for_testing())
          ->loop_mount_points_.empty());

  // Do the one-time stop and confirm all mount points are cleaned up.
  setup.UnmountOnOnetimeStopForTesting();
  EXPECT_TRUE(
      static_cast<const MockArcMounter*>(setup.arc_mounter_for_testing())
          ->mount_points_.empty());
  EXPECT_TRUE(
      static_cast<const MockArcMounter*>(setup.arc_mounter_for_testing())
          ->loop_mount_points_.empty());
}

}  // namespace arc
