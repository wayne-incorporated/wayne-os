// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <iostream>
#include <set>
#include <vector>

#include <base/files/file_util.h>
#include <base/strings/string_split.h>
#include <gtest/gtest.h>
#include "debugd/src/log_tool.h"

namespace debugd {

namespace {
// NB: No new entries may be added here.  Fix the docs instead!
const std::set<base::StringPiece> kEmptyEntries{
    "CLIENT_ID",
    "DEVICETYPE",
    "LOGDATE",
    "amdgpu_gem_info",
    "amdgpu_gtt_mm",
    "amdgpu_vram_mm",
    "android_app_storage",
    "arcvm_console_output",
    "atmel_tp_deltas",
    "atmel_tp_refs",
    "atmel_ts_deltas",
    "atmel_ts_refs",
    "atrus_logs",
    "authpolicy",
    "bio_crypto_init.LATEST",
    "bio_crypto_init.PREVIOUS",
    "bio_fw_updater.LATEST",
    "bio_fw_updater.PREVIOUS",
    "biod.LATEST",
    "biod.PREVIOUS",
    "bios_info",
    "blkid",
    "bootstat_summary",
    "bt_usb_disconnects",
    "cbi_info",
    "cheets_log",
    "chrome_system_log",
    "chrome_system_log.PREVIOUS",
    "chromeos-pgmem",
    "clobber-state.log",
    "clobber.log",
    "cr50_version",
    "cros_ec.log",
    "cros_ec.previous",
    "cros_ec_panicinfo",
    "cros_ec_pdinfo",
    "cros_fp.log",
    "cros_fp.previous",
    "cros_ish.log",
    "cros_ish.previous",
    "cros_scp.log",
    "cros_scp.previous",
    "cros_tp console",
    "cros_tp frame",
    "cros_tp version",
    "crostini",
    "crosvm.log",
    "drm_gem_objects",
    "drm_state",
    "ec_info",
    "edid-decode",
    "eventlog",
    "font_info",
    "framebuffer",
    "hammerd",
    "hardware_class",
    "hardware_verification_report",
    "hostname",
    "i915_error_state",
    "i915_gem_gtt",
    "i915_gem_objects",
    "ifconfig",
    "input_devices",
    "iw_list",
    "kernel-crashes",
    "logcat",
    "lsblk",
    "lsmod",
    "mali_memory",
    "memd clips",
    "memd.parameters",
    "memory_spd_info",
    "mm-esim-status",
    "mm-status",
    "modetest",
    "mount-encrypted",
    "netlog",
    "netstat",
    "network-devices",
    "network-services",
    "nvmap_iovmm",
    "oemdata",
    "pagetypeinfo",
    "pchg_info",
    "platform_identity_customization_id",
    "platform_identity_model",
    "platform_identity_name",
    "platform_identity_sku",
    "platform_identity_whitelabel_tag",
    "power_supply_info",
    "power_supply_sysfs",
    "powerd.LATEST",
    "powerd.PREVIOUS",
    "powerd.out",
    "powerwash_count",
    "ps",
    "qcom_fw_info",
    "sensor_info",
    "stateful_trim_data",
    "stateful_trim_state",
    "storage_info",
    "swap_info",
    "syslog",
    "system_log_stats",
    "threads",
    "tlsdate",
    "top memory",
    "top thread",
    "touch_fw_version",
    "tpm-firmware-updater",
    "tpm_version",
    "typecd",
    "ui_log",
    "update_engine.log",
    "upstart",
    "usb4 devices",
    "verified boot",
    "vmlog.1.LATEST",
    "vmlog.1.PREVIOUS",
    "vmlog.LATEST",
    "vmlog.PREVIOUS",
    "vpd_2.0",
    "wifi_status_no_anonymize",
    "zram block device stat names",
    "zram new stats names",
};
}  // namespace

TEST(LogToolDocTest, EntriesDocumented) {
  // Check if there are matching entries of the markdown document.
  auto categories = GetAllDebugTitlesForTest();
  std::set<base::StringPiece> documented_entries;
  std::set<base::StringPiece> empty_entries;
  std::vector<base::StringPiece> unsorted_documented_entries;
  constexpr char kLogEntriesMd[] = "docs/log_entries.md";

  base::FilePath markdown_filepath(
      base::FilePath(getenv("SRC")).Append(kLogEntriesMd));
  std::string mdfile;
  CHECK(base::ReadFileToString(markdown_filepath, &mdfile));

  std::vector<base::StringPiece> lines = base::SplitStringPiece(
      mdfile, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  for (auto it = lines.begin(); it != lines.end(); ++it) {
    const auto& line = *it;

    // Make sure lines before/after headers are blank.
    if (line.substr(0, 1) == "#") {
      if (it != lines.begin()) {
        --it;
        CHECK_EQ(*it, "") << "Need blank line before header: " << line;
        ++it;
      }

      ++it;
      CHECK_EQ(*it, "") << "Need blank line after header: " << line;
    }

    if (line.substr(0, 3) == "## ") {
      const auto& entry = line.substr(3);
      unsorted_documented_entries.push_back(entry);
      documented_entries.insert(entry);

      // We know from check above that there was a blank line after the header.
      // Check its contents now.
      ++it;
      const auto& contents = *it;
      if (contents.substr(0, 3) == "## ") {
        empty_entries.insert(entry);
        --it;
      } else {
        EXPECT_TRUE(kEmptyEntries.find(entry) == kEmptyEntries.end())
            << "Remove \"" << entry << "\" exception from test kEmptyEntries!";
      }
    }
  }
  CHECK_GE(documented_entries.size(), 2)
      << "Expecting at least 2 document entries but only found "
      << documented_entries.size();

  for (const auto& category : categories) {
    for (const auto& entry : category) {
      EXPECT_TRUE(documented_entries.find(entry) != documented_entries.end())
          << "Please add an entry for \"" << entry << "\" in " << kLogEntriesMd;
      EXPECT_TRUE(empty_entries.find(entry) == empty_entries.end() ||
                  kEmptyEntries.find(entry) != kEmptyEntries.end())
          << "\"" << entry << "\" must be properly documented; no stub entries "
          << "are allowed in " << kLogEntriesMd;
    }
  }

  auto it = std::is_sorted_until(unsorted_documented_entries.begin(),
                                 unsorted_documented_entries.end());
  EXPECT_TRUE(it == unsorted_documented_entries.end())
      << *it << " is not sorted in " << kLogEntriesMd;
}

TEST(LogToolDocTest, EntriesAreSorted) {
  // Check if entries of log_tool.cc are sorted.
  auto categories = GetAllDebugTitlesForTest();
  for (const auto& category : categories) {
    if (category.size() <= 1)
      continue;
    auto it = std::is_sorted_until(category.begin(), category.end());
    EXPECT_TRUE(it == category.end()) << *it << " is not sorted.";
  }
}

}  // namespace debugd
