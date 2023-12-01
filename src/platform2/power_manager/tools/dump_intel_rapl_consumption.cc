// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This utility reports power consumption for certain Intel SoCs, calculated by
// averaging the running energy consumption counter provided by Linux powercap
// driver subset of Intel RAPL (Running Average Power Limit) energy report.
// RAPL provides info per Power Domain: DRAM and PKG. PKG refers to the
// processor die, and includes the PP0 (cores) and PP1 (graphics) subdomains.
//
// MSRs reference can be found in "Sec. 14.9 Platform Specific Power Management
// Support" of the "Intel 64 and IA-32 Architectures Software Developer’s
// Manual Volume 3B: System Programming Guide, Part 2" [1].
// Info of Linux powercap driver can be reached in kernel documentation [2].
//
// [1]
// https://www.intel.com/content/www/us/en/architecture-and-technology/64-ia-32-architectures-software-developer-vol-3b-part-2-manual.html
// [2]
// https://github.com/torvalds/linux/blob/HEAD/Documentation/power/powercap/powercap.rst

#include <inttypes.h>
#include <math.h>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "power_manager/common/util.h"

namespace {

// Path to the powercap driver sysfs interface, if it doesn't exist,
// either the kernel is old w/o powercap driver, or it is not configured.
constexpr const char kPowercapPath[] = "/sys/class/powercap";

// Cap of a maximal reasonable power in Watts
constexpr const double kMaxWatts = 1e3;

struct PowerDomain {
  base::FilePath file_path;
  std::string name;
  uint64_t max_energy;

  bool operator<(const PowerDomain& that) const {
    return file_path < that.file_path;
  }
};

}  // namespace

int main(int argc, char** argv) {
  DEFINE_int32(interval_ms, 1000, "Interval to collect consumption (ms).");
  DEFINE_bool(repeat, false, "Repeat forever.");
  DEFINE_bool(verbose, false, "Verbose logging.");
  brillo::FlagHelper::Init(
      argc, argv, "Print average power consumption per domain for Intel SoCs");

  brillo::InitLog(brillo::kLogToStderr);

  // Kernel v3.13+ supports powercap, it also requires a proper configuration
  // enabling it; leave a verbose footprint of the kernel string, and examine
  // whether or not the system supports the powercap driver.
  if (FLAGS_verbose) {
    const base::SysInfo sys;
    printf("OS version: %s\n", sys.OperatingSystemVersion().c_str());
  }
  base::FilePath powercap_file_path(kPowercapPath);
  PCHECK(base::PathExists(powercap_file_path))
      << "No powercap driver sysfs interface, couldn't find "
      << powercap_file_path.value();

  std::vector<PowerDomain> power_domains;
  std::string domain_name;

  // Probe the power domains and sub-domains
  base::FilePath powercap_path(kPowercapPath);
  base::FileEnumerator dirs(powercap_path, false,
                            base::FileEnumerator::DIRECTORIES,
                            FILE_PATH_LITERAL("intel-rapl:*"));
  for (base::FilePath dir = dirs.Next(); !dir.empty(); dir = dirs.Next()) {
    base::FilePath domain_file_path = dir.Append("name");
    base::FilePath energy_file_path = dir.Append("energy_uj");
    base::FilePath maxeng_file_path = dir.Append("max_energy_range_uj");
    uint64_t max_energy_uj;

    if (!base::PathExists(domain_file_path)) {
      fprintf(stderr, "Unable to find %s\n", domain_file_path.value().c_str());
      continue;
    }
    if (!base::PathExists(energy_file_path)) {
      fprintf(stderr, "Unable to find %s\n", energy_file_path.value().c_str());
      continue;
    }
    if (!base::PathExists(maxeng_file_path)) {
      fprintf(stderr, "Unable to find %s\n", maxeng_file_path.value().c_str());
      continue;
    }

    power_manager::util::ReadStringFile(domain_file_path, &domain_name);
    power_manager::util::ReadUint64File(maxeng_file_path, &max_energy_uj);
    power_domains.push_back({energy_file_path, domain_name, max_energy_uj});
    if (FLAGS_verbose)
      printf("Found domain %-10s (max %" PRIu64 " uj) at %s\n",
             domain_name.c_str(), max_energy_uj, dir.value().c_str());
  }

  PCHECK(!power_domains.empty())
      << "No power domain found at " << powercap_file_path.value();

  // As the enumeration above does not guarantee the order, transform the
  // paths in lexicographical order, make the collecting data in a style
  // of domain follows by sub-domain, it can be done by sorting.
  // e.g., package-0 psys core ... -> package-0 core ... psys
  sort(power_domains.begin(), power_domains.end());

  for (const auto& domain : power_domains)
    printf("%10s ", domain.name.c_str());
  printf(" (Note: Values in Watts)\n");

  uint32_t num_domains = power_domains.size();
  std::vector<uint64_t> energy_before(num_domains);
  std::vector<uint64_t> energy_after(num_domains);
  do {
    for (int i = 0; i < num_domains; ++i)
      power_manager::util::ReadUint64File(power_domains[i].file_path,
                                          &energy_before[i]);
    const base::TimeTicks ticks_before = base::TimeTicks::Now();

    base::PlatformThread::Sleep(base::Milliseconds(FLAGS_interval_ms));

    for (int i = 0; i < num_domains; ++i)
      power_manager::util::ReadUint64File(power_domains[i].file_path,
                                          &energy_after[i]);
    const base::TimeDelta time_delta = base::TimeTicks::Now() - ticks_before;

    for (int i = 0; i < num_domains; ++i) {
      uint64_t energy_delta = (energy_after[i] >= energy_before[i])
                                  ? energy_after[i] - energy_before[i]
                                  : power_domains[i].max_energy -
                                        energy_before[i] + energy_after[i];
      double average_power =
          static_cast<double>(energy_delta) / (time_delta.InSecondsF() * 1e6);

      // Skip enormous sample if the counter is reset during suspend-to-RAM
      if (average_power > kMaxWatts) {
        printf("%10s ", "skip");
        continue;
      }
      printf("%10.6f ", average_power);
    }
    printf("\n");
  } while (FLAGS_repeat);

  return 0;
}
