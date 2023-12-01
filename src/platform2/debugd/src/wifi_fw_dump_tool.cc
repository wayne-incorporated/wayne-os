// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/wifi_fw_dump_tool.h"

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>

namespace debugd {

std::string WifiFWDumpTool::WifiFWDump() {
  // Directory to search for the wifi firmware dumper in.
  // The full path to the dumper file is unknown because it contains a
  // variably-named directory.
  const char kDirectoryToSearch[] = "/sys/kernel/debug/iwlwifi";
  const base::FilePath wifi_dumper_dir(kDirectoryToSearch);

  if (!base::PathExists(wifi_dumper_dir)) {
    return "Failure: Could not find supported WiFi device. This command "
           "currently only supports Intel WiFi devices.";
  }
  // dir_enum enumerates all directories contained in wifi_dumper_dir
  // non-recursively.
  base::FileEnumerator dir_enum(wifi_dumper_dir, false,
                                base::FileEnumerator::DIRECTORIES);

  // Iterate through subdirectories and check for wifi firmware dumper file.
  for (base::FilePath dir_name = dir_enum.Next(); !dir_name.empty();
       dir_name = dir_enum.Next()) {
    // The path to the firmware dumper file is hardcoded as the wifi_fw_dump
    // crosh command currently only supports Intel wifi.
    base::FilePath dumper_file = dir_name.Append("iwlmvm/fw_dbg_collect");

    // Check if dumper file is contained within dir_name directory.
    if (base::PathExists(dumper_file)) {
      // Write '1' to the dumper file to trigger firmware dump. WriteFile should
      // return the number of bytes written.
      if (base::WriteFile(dumper_file, "1", 1) != 1) {
        return "Failure: Unable to trigger WiFi firmware dump. Failed when "
               "attempting to write to " +
               dumper_file.value();
      }
      return "Success: WiFi firmware dump triggered. Output can be found in "
             "one or both of the following directories: /var/spool/crash/ "
             "/var/log/ ";
    }
  }
  // If below line is executed, the dumper file was not found.
  return "Failure: Could not find supported WiFi device. This command "
         "currently only supports Intel WiFi devices.";
}

}  // namespace debugd
