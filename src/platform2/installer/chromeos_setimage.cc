// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "installer/chromeos_setimage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <vector>

#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <verity/dm-bht.h>

#include "installer/chromeos_install_config.h"
#include "installer/chromeos_verity.h"
#include "installer/inst_util.h"

using std::string;

//
// There is nothing in our codebase that calls chromeos-setimage,
// except for post install, so only it's use case is required
// here. I think.
//
// New dm argument syntax:
// TODO(taysom:defect 32847)
// In the future, the <num> field will be mandatory.
//
// <device>        ::= [<num>] <device-mapper>+
// <device-mapper> ::= <head> "," <target>+
// <head>          ::= <name> <uuid> <mode> [<num>]
// <target>        ::= <start> <length> <type> <options> ","
// <mode>          ::= "ro" | "rw"
// <uuid>          ::= xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | "none"
// <type>          ::= "verity" | "bootcache" | ...
//
// Notes:
//  1. uuid is a label for the device and we set it to "none".
//  2. The <num> field will be optional initially and assumed to be 1.
//     Once all the scripts that set these fields have been set, it will
//     made mandatory.
//
// Coming attractions:
// The upstream version of verity does not use name/value pairs for
// arguments. All arguments are positional. The current code for
// finding the root_hexdigest and salt will need to change accordingly.
//
// Don't know if we can make the code parse both types of arguments.

bool SetImage(const InstallConfig& install_config) {
  LOG(INFO) << "SetImage";

  // Re-hash the root filesystem and use the table for dm-verity.
  // We extract the parameters for verification from the kernel
  // partition, but we regenerate and reappend the hash tree to
  // keep the updater from needing to manage them explicitly.
  // Instead, rootfs integrity will be validated on next boot through
  // the verified kernel configuration.

  string kernel_config = DumpKernelConfig(install_config.kernel.device());

  LOG(INFO) << "KERNEL_CONFIG: " << kernel_config.c_str();

  // An example value: <root_hexdigest and salt values shortened>
  //
  // quiet loglevel=1 console=tty2 init=/sbin/init add_efi_memmap boot=local
  // noresume noswap i915.modeset=1 cros_secure tpm_tis.force=1
  // tpm_tis.interrupts=0 nmi_watchdog=panic,lapic root=/dev/dm-0 rootwait
  // ro dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1
  // dm="vroot none ro,0 1740800 verity payload=%U+1 hashtree=%U+1
  // hashstart=1740800 alg=sha1 root_hexdigest=30348c07f salt=a9864eaf11f4
  // 66fc48dffef" noinitrd cros_debug vt.global_cursor_default=0 kern_guid=%U
  //

  base::FilePath kernel_config_root =
      base::FilePath(ExtractKernelArg(kernel_config, "root"));
  string dm_config = ExtractKernelArg(kernel_config, "dm");
  std::vector<string> dm_parts = base::SplitString(
      dm_config, ",", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  // Extract verity specific options
  string verity_args;
  for (unsigned i = 0; i < dm_parts.size(); i++) {
    if (dm_parts[i].find(" verity ") != string::npos) {
      verity_args = dm_parts[i];
      break;
    }
  }
  if (verity_args.empty()) {
    LOG(ERROR) << "Didn't find verity args in the dm command line: "
               << dm_config;
    return false;
  }

  // Extract specific verity arguments
  string rootfs_sectors = ExtractKernelArg(verity_args, "hashstart");
  string verity_algorithm = ExtractKernelArg(verity_args, "alg");
  string expected_hash = ExtractKernelArg(verity_args, "root_hexdigest");
  string salt = ExtractKernelArg(verity_args, "salt");

  bool enable_rootfs_verification = IsReadonly(kernel_config_root);

  if (!enable_rootfs_verification)
    MakeFileSystemRw(install_config.root.device());

  LOG(INFO) << "Setting up verity.";
  LoggingTimerStart();
  verity::DmBht bht;
  int result = chromeos_verity(&bht, verity_algorithm,
                               install_config.root.device(), getpagesize(),
                               (uint64_t)(atoi(rootfs_sectors.c_str()) / 8),
                               salt, expected_hash, enable_rootfs_verification);
  LoggingTimerFinish();

  return result == 0;
}
