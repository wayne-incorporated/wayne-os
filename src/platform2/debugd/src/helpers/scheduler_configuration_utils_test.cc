// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/helpers/scheduler_configuration_utils.h"

#include <fcntl.h>
#include <stdio.h>

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace debugd {

namespace {

constexpr char kChromeCPUSubsetSubpath[] = "fs/cgroup/cpuset/chrome/cpus";
constexpr char kChronosContainerCPUSubsetSubpath[] =
    "fs/cgroup/cpuset/chronos_containers/cpus";
constexpr char kSessionManagerCPUSubsetSubpath[] =
    "fs/cgroup/cpuset/session_manager_containers/cpus";

}  // namespace

class SchedulerConfigurationHelperTest : public testing::Test {
 public:
  std::string GetOnlineOrPresentString(int in_int) {
    return std::string("0-" + std::to_string(in_int - 1));
  }

  std::string GetOfflineString(int online, int total) {
    return std::string(std::to_string(online) + "-" +
                       std::to_string(total - 1));
  }

  // Create system files to represent different CPU states.
  void CreateSysInterface(const base::FilePath& cpu_root_dir,
                          const base::FilePath& base_sys_path,
                          int online,
                          int present,
                          int total) {
    // Set up a fake tempdir mimicking a performance mode CPU.
    ASSERT_TRUE(base::CreateDirectory(cpu_root_dir));
    // Create online CPUs, and turn them all on.
    for (int cur_online_cpu = 0; cur_online_cpu < online; cur_online_cpu++) {
      base::FilePath cpu_subroot =
          cpu_root_dir.Append("cpu" + std::to_string(cur_online_cpu));
      ASSERT_TRUE(base::CreateDirectory(cpu_subroot));
      std::string flag = "1";
      ASSERT_EQ(flag.size(), base::WriteFile(cpu_subroot.Append("online"),
                                             flag.c_str(), flag.size()));

      // Establish odd CPUs as virtual siblings.
      base::FilePath topology = cpu_subroot.Append("topology");
      ASSERT_TRUE(base::CreateDirectory(topology));
      // For cpu_num "0", string should read "0-1".
      // For cpu_num "3", string should read "2-3" and so forth.
      int lower;
      if (cur_online_cpu % 2 == 0) {
        lower = cur_online_cpu;
      } else {
        lower = cur_online_cpu - 1;
      }
      std::string topology_str =
          std::to_string(lower) + "-" + std::to_string(lower + 1);
      // Assert cases manually made by previous logic still work.
      if (cur_online_cpu == 0 || cur_online_cpu == 1) {
        ASSERT_EQ(topology_str, "0-1");
      } else if (cur_online_cpu == 2 || cur_online_cpu == 3) {
        ASSERT_EQ(topology_str, "2-3");
      }
      ASSERT_EQ(topology_str.size(),
                base::WriteFile(topology.Append("thread_siblings_list"),
                                topology_str.c_str(), topology_str.size()));
    }

    // Establish the control files.
    base::FilePath online_cpus_file = cpu_root_dir.Append("online");
    std::string online_cpus = GetOnlineOrPresentString(online);
    ASSERT_EQ(online_cpus.size(),
              base::WriteFile(online_cpus_file, online_cpus.c_str(),
                              online_cpus.size()));

    // Create set of present CPUs.
    base::FilePath present_cpus_file = cpu_root_dir.Append("present");
    std::string present_cpus = GetOnlineOrPresentString(present);

    ASSERT_EQ(present_cpus.size(),
              base::WriteFile(present_cpus_file, present_cpus.c_str(),
                              present_cpus.size()));

    // Establish the offline CPUs.
    base::FilePath offline_cpus_file = cpu_root_dir.Append("offline");
    if (online == total) {
      // If all CPUs are online, the offline file is empty.
      const char terminator = 0xa;
      ASSERT_EQ(1, base::WriteFile(offline_cpus_file, &terminator, 1));
    } else {
      // If not all CPUs are online, offline file is "online-(total - 1)".
      // So if 2 CPUs online and 8 CPUs total, online string would be "0-1"
      // and offline string would be "2-7".
      std::string offline_cpus = GetOfflineString(online, total);
      ASSERT_EQ(offline_cpus.size(),
                base::WriteFile(offline_cpus_file, offline_cpus.c_str(),
                                offline_cpus.size()));
    }

    // Setup the cpu set files.
    base::FilePath chrome_cpuset =
        base_sys_path.Append(kChromeCPUSubsetSubpath);
    base::FilePath chronos_cpuset =
        base_sys_path.Append(kChronosContainerCPUSubsetSubpath);
    base::FilePath session_manager_cpuset =
        base_sys_path.Append(kSessionManagerCPUSubsetSubpath);

    for (const auto& cpuset :
         {chrome_cpuset, chronos_cpuset, session_manager_cpuset}) {
      ASSERT_TRUE(base::CreateDirectory(cpuset.DirName()));
      // Sets the range to A to make sure the debugd code updates it.
      std::string range = "A";
      ASSERT_EQ(range.size(),
                base::WriteFile(cpuset, range.data(), range.size()));
    }
  }

  void CheckPerformanceMode(const base::FilePath& cpu_root_dir) {
    for (const std::string& cpu_num : {"0", "1", "2", "3"}) {
      base::FilePath cpu_control =
          cpu_root_dir.Append("cpu" + cpu_num).Append("online");
      std::string control_contents;
      ASSERT_TRUE(base::ReadFileToString(cpu_control, &control_contents));
      EXPECT_EQ("1", control_contents);
    }
  }

  void CheckConservativeModeShared(const base::FilePath& cpu_root_dir,
                                   std::vector<std::string>* cpu_list) {
    for (const std::string& cpu_num : *cpu_list) {
      base::FilePath cpu_control =
          cpu_root_dir.Append("cpu" + cpu_num).Append("online");
      std::string control_contents;
      ASSERT_TRUE(base::ReadFileToString(cpu_control, &control_contents));
      if (cpu_num == "0" || cpu_num == "2") {
        EXPECT_EQ("1", control_contents);
      } else if (cpu_num == "1" || cpu_num == "3") {
        EXPECT_EQ("0", control_contents);
      }
    }
  }

  void CheckConservativeMode(const base::FilePath& cpu_root_dir) {
    std::vector<std::string> cpu_list;
    cpu_list.push_back("0");
    cpu_list.push_back("1");
    cpu_list.push_back("2");
    cpu_list.push_back("3");
    CheckConservativeModeShared(cpu_root_dir, &cpu_list);
  }

  void CheckConservativeModeTwoCpus(const base::FilePath& cpu_root_dir) {
    std::vector<std::string> cpu_list;
    cpu_list.push_back("0");
    cpu_list.push_back("1");
    CheckConservativeModeShared(cpu_root_dir, &cpu_list);
  }
};

TEST_F(SchedulerConfigurationHelperTest, ParseCPUs) {
  // Note the usual security principle in this test: the kernel shouldn't return
  // any of these invalid sequences ("0-?", etc.), but it's important to handle
  // unexpected input gracefully.
  debugd::SchedulerConfigurationUtils utils{base::FilePath("/sys")};

  std::vector<std::string> raw_num;
  EXPECT_TRUE(utils.ParseCPUNumbers("1", &raw_num));
  EXPECT_EQ(std::vector<std::string>({"1"}), raw_num);

  // Test a simple range.
  std::vector<std::string> range;
  EXPECT_TRUE(utils.ParseCPUNumbers("0-3", &range));
  EXPECT_EQ(std::vector<std::string>({"0", "1", "2", "3"}), range);

  // Test a comma separated list.
  std::vector<std::string> list;
  EXPECT_TRUE(utils.ParseCPUNumbers("0,3,4,7", &list));
  EXPECT_EQ(std::vector<std::string>({"0", "3", "4", "7"}), list);

  // Some devices have weird topologies.
  std::vector<std::string> complex_range;
  EXPECT_TRUE(utils.ParseCPUNumbers("0,2-3,6", &complex_range));
  EXPECT_EQ(std::vector<std::string>({"0", "2", "3", "6"}), complex_range);

  std::vector<std::string> complex_range2;
  EXPECT_TRUE(utils.ParseCPUNumbers("0,2-5,6-10,17-25,32", &complex_range2));
  EXPECT_EQ(std::vector<std::string>({"0",  "2",  "3",  "4",  "5",  "6",  "7",
                                      "8",  "9",  "10", "17", "18", "19", "20",
                                      "21", "22", "23", "24", "25", "32"}),
            complex_range2);

  // Invalid ranges.
  std::vector<std::string> invalid;
  EXPECT_FALSE(utils.ParseCPUNumbers("-", &invalid));
  EXPECT_FALSE(utils.ParseCPUNumbers(",", &invalid));
  EXPECT_FALSE(utils.ParseCPUNumbers("?", &invalid));
  EXPECT_FALSE(utils.ParseCPUNumbers("0-?", &invalid));
  EXPECT_FALSE(utils.ParseCPUNumbers("1,?", &invalid));
  EXPECT_FALSE(utils.ParseCPUNumbers("0-", &invalid));
  EXPECT_FALSE(utils.ParseCPUNumbers("-9", &invalid));
  EXPECT_FALSE(utils.ParseCPUNumbers("1-1", &invalid));
  EXPECT_FALSE(utils.ParseCPUNumbers("5-1", &invalid));
}

TEST_F(SchedulerConfigurationHelperTest, WriteFlag) {
  debugd::SchedulerConfigurationUtils utils{base::FilePath("/sys")};
  base::FilePath target_file;

  ASSERT_TRUE(base::CreateTemporaryFile(&target_file));

  base::ScopedFD fd(open(target_file.value().c_str(), O_RDWR | O_CLOEXEC));
  ASSERT_LE(0, fd.get());

  ASSERT_TRUE(utils.WriteFlagToCPUControlFile(fd, "test"));

  std::string file_contents;
  ASSERT_TRUE(base::ReadFileToString(target_file, &file_contents));

  EXPECT_EQ("test", file_contents);
}

TEST_F(SchedulerConfigurationHelperTest, TestSchedulers) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  const base::FilePath cpu_root_dir =
      temp_dir.GetPath().Append("devices").Append("system").Append("cpu");
  // Create a simple system interface, with 4 CPUs online and present.
  CreateSysInterface(cpu_root_dir, temp_dir.GetPath(), 4, 4, 4);

  size_t num_cpus_disabled = 0;
  debugd::SchedulerConfigurationUtils utils(temp_dir.GetPath());
  ASSERT_TRUE(utils.GetControlFDs());
  ASSERT_TRUE(utils.GetCPUSetFDs());
  ASSERT_TRUE(utils.EnablePerformanceConfiguration(&num_cpus_disabled));
  ASSERT_EQ(0U, num_cpus_disabled);

  CheckPerformanceMode(cpu_root_dir);

  // Now enable conservative mode.
  SchedulerConfigurationUtils utils2(temp_dir.GetPath());
  ASSERT_TRUE(utils2.GetControlFDs());
  ASSERT_TRUE(utils2.GetCPUSetFDs());
  ASSERT_TRUE(utils2.EnableConservativeConfiguration(&num_cpus_disabled));
  ASSERT_EQ(2U, num_cpus_disabled);

  CheckConservativeMode(cpu_root_dir);

  // Before going back to performance mode, update the control files to mimick
  // the kernel's actions.
  base::FilePath online_cpus_file = cpu_root_dir.Append("online");
  base::FilePath offline_cpus_file = cpu_root_dir.Append("offline");
  std::string online_now = "0,2";
  std::string offline_now = "1,3";
  ASSERT_EQ(
      online_now.size(),
      base::WriteFile(online_cpus_file, online_now.c_str(), online_now.size()));
  ASSERT_EQ(offline_now.size(),
            base::WriteFile(offline_cpus_file, offline_now.c_str(),
                            offline_now.size()));

  // Re-enable performance and test.
  SchedulerConfigurationUtils utils3(temp_dir.GetPath());
  ASSERT_TRUE(utils3.GetControlFDs());
  ASSERT_TRUE(utils3.GetCPUSetFDs());
  ASSERT_TRUE(utils3.EnablePerformanceConfiguration(&num_cpus_disabled));
  ASSERT_EQ(0U, num_cpus_disabled);

  CheckPerformanceMode(cpu_root_dir);

  // Check the cpuset file. Because this unit test is crudely mocking the
  // behavior of the CPU control files, the cpuset file ends out of date. But
  // that's OK: it needs to have a valid range and not EINVAL.
  base::FilePath chrome_cpuset =
      temp_dir.GetPath().Append(kChromeCPUSubsetSubpath);
  base::FilePath chronos_cpuset =
      temp_dir.GetPath().Append(kChronosContainerCPUSubsetSubpath);
  base::FilePath session_manager_cpuset =
      temp_dir.GetPath().Append(kSessionManagerCPUSubsetSubpath);

  for (const auto& cpuset :
       {chrome_cpuset, chronos_cpuset, session_manager_cpuset}) {
    std::string cpuset_contents;
    ASSERT_TRUE(base::ReadFileToString(cpuset, &cpuset_contents));
    EXPECT_EQ("0,2", cpuset_contents);
  }
}

TEST_F(SchedulerConfigurationHelperTest, TestSchedulersWithMissingCPUs) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  const base::FilePath cpu_root_dir =
      temp_dir.GetPath().Append("devices").Append("system").Append("cpu");
  // Create a filesystem with two online/present CPUs out of 8.
  CreateSysInterface(cpu_root_dir, temp_dir.GetPath(), 2, 2, 8);

  size_t num_cpus_disabled = 0;

  // Enable conservative mode.
  SchedulerConfigurationUtils utils2(temp_dir.GetPath());
  ASSERT_TRUE(utils2.GetControlFDs());
  ASSERT_TRUE(utils2.GetCPUSetFDs());
  ASSERT_TRUE(utils2.EnableConservativeConfiguration(&num_cpus_disabled));
  // The second processor (1) is disabled of the available (0-1).
  ASSERT_EQ(1U, num_cpus_disabled);

  CheckConservativeModeTwoCpus(cpu_root_dir);
}

}  // namespace debugd
