// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_PSTORE_DUMP_PERSISTENT_RAM_BUFFER_H_
#define VM_TOOLS_PSTORE_DUMP_PERSISTENT_RAM_BUFFER_H_

#include <stdint.h>

#include <string>
#include <utility>

#include <base/files/file_path.h>

namespace vm_tools {
namespace pstore_dump {

// From fs/pstore/ram_core.c
/**
 * struct persistent_ram_buffer - persistent circular RAM buffer
 *
 * @sig:
 *      signature to indicate header (PERSISTENT_RAM_SIG xor PRZ-type value)
 * @start:
 *      offset into @data where the beginning of the stored bytes begin
 * @size:
 *      number of valid bytes stored in @data
 */
struct persistent_ram_buffer {
  uint32_t sig;
  uint32_t start;
  uint32_t size;
  uint8_t data[0];
};

// From fs/pstore/ram_core.c
#define PERSISTENT_RAM_SIG (0x43474244) /* DBGC */

bool GetPersistentRamBufferContent(const persistent_ram_buffer* buf,
                                   size_t buf_capacity,
                                   std::string* out_content);
bool HandlePstore(const base::FilePath& path);
bool HandlePstoreDmesg(const base::FilePath& path);

}  // namespace pstore_dump
}  // namespace vm_tools

#endif  // VM_TOOLS_PSTORE_DUMP_PERSISTENT_RAM_BUFFER_H_
