// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_CONTAINER_OBB_MOUNTER_UTIL_H_
#define ARC_CONTAINER_OBB_MOUNTER_UTIL_H_

#include <linux/msdos_fs.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "arc/container/obb-mounter/volume.h"

namespace base {
class File;
}

namespace fat {

// Reads a little-endian 16-bit unsigned int from the given address.
// No alignment required for |data|.
uint16_t GetUnalignedLE16(const uint8_t* data);

// Appends the given slot's long file name characters to |out| in the reversed
// order.
void AppendLongFileNameCharactersReversed(const msdos_dir_slot& slot,
                                          std::u16string* out);

// Reads the FAT (file allocation table) value at the given index.
// If there is an error, or reached EOF, returns kInvalidValue.
int64_t ReadFileAllocationTable(base::File* file,
                                FatType fat_type,
                                int64_t fat_start,
                                int64_t index);

}  // namespace fat

#endif  // ARC_CONTAINER_OBB_MOUNTER_UTIL_H_
