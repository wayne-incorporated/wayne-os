// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_HELPERS_SCHEDULER_CONFIGURATION_UTILS_H_
#define DEBUGD_SRC_HELPERS_SCHEDULER_CONFIGURATION_UTILS_H_

#include <map>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/gtest_prod_util.h>

namespace debugd {

// Class to provide functionality to the CPU control profiles in /sys.
//
// Functions are gathered into this class in order to provide a testable
// interface.
class SchedulerConfigurationUtils {
 public:
  // |base_path| is normally /sys but can be adjusted for testing.
  explicit SchedulerConfigurationUtils(const base::FilePath& base_path)
      : base_path_{base_path},
        fd_map_{},
        offline_cpus_{},
        online_cpus_{},
        cpusets_fds_{},
        online_cpus_fd_{} {}
  SchedulerConfigurationUtils(const SchedulerConfigurationUtils&) = delete;
  SchedulerConfigurationUtils& operator=(const SchedulerConfigurationUtils&) =
      delete;

  ~SchedulerConfigurationUtils() = default;

  // This enables all cores. The number of cores disabled after changing the
  // configuration is written to |num_cores_disabled| regardless of the return
  // value of the function.
  bool EnablePerformanceConfiguration(size_t* num_cores_disabled);

  // This disables virtual cores. |num_cores_disabled| is updated in the same
  // way as EnablePerformanceConfiguration.
  bool EnableConservativeConfiguration(size_t* num_cores_disabled);

  // Store a map of all the CPU control files. The CPU number is mapped to its
  // file descriptor. This also stores the vector of offline and offline CPUs,
  // to avoid it being re-calculated later.
  bool GetControlFDs();

  // Open the file descriptors to the cpuset files before sandboxing.
  bool GetCPUSetFDs();

  // This takes a range of CPUs from the /sys filesystem, which could be a raw
  // number, hyphen separated range or comma separated list/range, and converts
  // it into a vector.
  static bool ParseCPUNumbers(const std::string& cpus,
                              std::vector<std::string>* result);

 private:
  enum class DisableSiblingsResult {
    PHYSICAL_CORE,
    SUCCESS,
    ERROR,
  };

  // This disables sibling threads of physical cores.
  DisableSiblingsResult DisableSiblings(const std::string& cpu_num);

  // Writes the online status to CPU control file fd.
  static bool WriteFlagToCPUControlFile(const base::ScopedFD& fd,
                                        const std::string& flag);

  // This fetches the FD from the map, makes sure it exists, and then writes it.
  bool LookupFDAndWriteFlag(const std::string& cpu_number,
                            const std::string& flag);

  // This writes the flag to disable the given CPU by number.
  bool DisableCPU(const std::string& cpu_number);

  // This writes the flag to enable the given CPU by number.
  bool EnableCPU(const std::string& cpu_number);

  bool PruneNonPresentCpus(std::vector<std::string>* cpu_nums);

  // This reads either the offline or online CPU list and opens FDs for the
  // listed CPUs, putting them into |fd_map_|.
  bool GetFDsFromControlFile(const base::FilePath& path,
                             std::vector<std::string>* cpu_nums);

  // This updates all cpuset files for Chrome OS's cgroups.
  bool UpdateAllCPUSets();

  // Returns a the path to the sibling thread file for the purpose of unit
  // testing.
  base::FilePath GetSiblingPath(const std::string& cpu_num);

  // The base FilePath, adjustable for testing.
  base::FilePath base_path_;
  // A map of |cpu_num| to |fd|.
  std::map<std::string, base::ScopedFD> fd_map_;
  // A vector of offline CPUs.
  std::vector<std::string> offline_cpus_;
  // A vector of online CPUs.
  std::vector<std::string> online_cpus_;
  // The FDs of the cpuset control files to update.
  std::vector<base::ScopedFD> cpusets_fds_;
  // The file containing the online CPU range.
  base::ScopedFD online_cpus_fd_;

  FRIEND_TEST_ALL_PREFIXES(SchedulerConfigurationHelperTest, WriteFlag);
  FRIEND_TEST_ALL_PREFIXES(SchedulerConfigurationHelperTest, ParseCPUs);
  FRIEND_TEST_ALL_PREFIXES(SchedulerConfigurationHelperTest, TestSchedulers);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_HELPERS_SCHEDULER_CONFIGURATION_UTILS_H_
