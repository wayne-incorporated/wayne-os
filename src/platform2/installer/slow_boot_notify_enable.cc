// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/process/process.h>
#include <vboot/crossystem.h>

#include "installer/inst_util.h"
#include "installer/slow_boot_notify.h"

using std::string;
using std::vector;

void ExtractFspm(const string& partition, const base::FilePath& fspm_path) {
  if (partition != "A" && partition != "B") {
    LOG(ERROR) << "unsupported partition: " << partition;
    return;
  }

  base::FilePath fw_bin_path;
  if (!CreateTemporaryFile(&fw_bin_path))
    return;

  vector<string> cmd = {"/usr/sbin/flashrom",
                        "-p",
                        "host",
                        "-r",
                        "-i",
                        "FW_MAIN_" + partition + ":" + fw_bin_path.value()};
  int result;
  if ((result = RunCommand(cmd))) {
    LOG(ERROR) << "Error reading FW_MAIN_" << partition
               << " result: " << result;
    base::DeleteFile(fw_bin_path);
    return;
  }

  cmd = {"/usr/bin/cbfstool", fw_bin_path.value(),
         "extract",           "-n",
         "fspm.bin",          "-f",
         fspm_path.value()};
  if ((result = RunCommand(cmd)))
    LOG(ERROR) << "Error extracting FSPM from FW_MAIN_" << partition
               << " result: " << result;

  base::DeleteFile(fw_bin_path);
}

void SlowBootNotifyPreFwUpdate(const base::FilePath& fspm_main) {
  char partition[VB_MAX_STRING_PROPERTY];

  if (VbGetSystemPropertyString("mainfw_act", partition, sizeof(partition)) !=
      0)
    return;

  ExtractFspm(partition, fspm_main);
}

void SlowBootNotifyPostFwUpdate(const base::FilePath& fspm_next) {
  // After firmware update, get the ID of the new partition/region. If there is
  // no firmware update, region returned by fw_try_next is the same as
  // mainfw_act.
  char partition[VB_MAX_STRING_PROPERTY];
  VbGetSystemPropertyString("fw_try_next", partition, sizeof(partition));
  ExtractFspm(partition, fspm_next);
}

bool SlowBootNotifyRequired(const base::FilePath& fspm_main,
                            const base::FilePath& fspm_next) {
  // Enable slow boot notification only if FSPMs are different. Reduce
  // notification noise if one/both of the FSPMs don't exist (due to unforeseen
  // errors).
  if (base::PathExists(fspm_main) && base::PathExists(fspm_next) &&
      !ContentsEqual(fspm_main, fspm_next)) {
    LOG(INFO) << "Slow boot notification enabled.";
    return true;
  }

  LOG(INFO) << "Slow boot notification disabled.";
  return false;
}
