// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_STARTUP_FLAGS_H_
#define INIT_STARTUP_FLAGS_H_

namespace startup {

// Define a struct to contain the flags we set when parsing USE flags.
struct Flags {
  // Indicates built with USE=encrypted_reboot_vault. Used to determine
  // if we need to setup the encrypted reboot vault.
  bool encrypted_reboot_vault;
  // Indicates built with USE=encrypted_stateful, used to determine which
  // mount function to use
  bool encstateful;
  // Indicates built with USE=direncryption. Used when mounting the stateful
  // partition to determine if we should enable directory encryption.
  bool direncryption;
  // Indicates built with USE=fsverity. Used when mounting the stateful
  // partition.
  bool fsverity;
  // Indicates built with USE=lvm_stateful_partition. Used when mounting the
  // stateful partition.
  bool lvm_stateful;
  // Indicates built with USE=prjquota. Used when mounting the stateful
  // partition.
  bool prjquota;
  // Not a USE flag, but indicates if built with both USE=tpm2 and
  // USE=encrypted_stateful. Used to determine if we will try to create
  // a system key.
  bool sys_key_util;
};

}  // namespace startup

#endif  // INIT_STARTUP_FLAGS_H_
