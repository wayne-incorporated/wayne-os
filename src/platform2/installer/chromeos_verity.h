/* Copyright 2012 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef INSTALLER_CHROMEOS_VERITY_H_
#define INSTALLER_CHROMEOS_VERITY_H_

#include <stdint.h>

#include <string>

#include <base/files/file_path.h>

#include <verity/dm-bht.h>

/* chromeos_verity
 * This calculated the verity hash-trie for a filesystem and places it
 * immdiately after the FS on the device, and checks that the expected
 * root hash is generated.
 *
 * @alg - algorithm to use. md5, sha1, or sha256
 * @device - block device which contains the fs and will contain hash trie
 * @blocksize - size of block to hash on.  Usually page size - 4k on x86.
 * @salt - ascii string with a salt value to add before calculating each hash
 * @expected - ascii string with the exptected final root hash value
 * @enforce_rootfs_verification - bool indicating whether we should complain if
 *   expected doesn't matchp
 * return - 0 for success, non-zero indicates failure
 *
 */
int chromeos_verity(verity::DmBhtInterface* bht,
                    const std::string& alg,
                    const base::FilePath& device,
                    unsigned blocksize,
                    uint64_t fs_blocks,
                    const std::string& salt,
                    const std::string& expected,
                    bool enforce_rootfs_verification);

#endif  // INSTALLER_CHROMEOS_VERITY_H_
