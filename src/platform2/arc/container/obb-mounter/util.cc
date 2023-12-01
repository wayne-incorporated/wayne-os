// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/container/obb-mounter/util.h"

#include <iterator>

#include <base/logging.h>

namespace fat {

uint16_t GetUnalignedLE16(const uint8_t* data) {
  return data[0] | (data[1] << 8);
}

void AppendLongFileNameCharactersReversed(const msdos_dir_slot& slot,
                                          std::u16string* out) {
  if (slot.id & 0x40) {  // Starting a new name.
    out->clear();
  }
  // Guard against corrupted image consuming too much memory.
  if (out->size() >= FAT_LFN_LEN) {
    return;
  }
  // Slots are stored in the reversed order while each slot holds characters in
  // the normal order. Here we append the characters in the reversed order so
  // that |out| contains all characters in the reversed order.
  out->resize(out->size() + 13);
  for (size_t i = 0; i < std::size(slot.name0_4) / 2; ++i) {
    (*out)[out->size() - 1 - i] = GetUnalignedLE16(slot.name0_4 + i * 2);
  }
  for (size_t i = 0; i < std::size(slot.name5_10) / 2; ++i) {
    (*out)[out->size() - 6 - i] = GetUnalignedLE16(slot.name5_10 + i * 2);
  }
  for (size_t i = 0; i < std::size(slot.name11_12) / 2; ++i) {
    (*out)[out->size() - 12 - i] = GetUnalignedLE16(slot.name11_12 + i * 2);
  }
}

int64_t ReadFileAllocationTable(base::File* file,
                                FatType fat_type,
                                int64_t fat_start,
                                int64_t index) {
  int64_t fat_offset = 0;
  switch (fat_type) {
    case FatType::FAT_12:
      fat_offset = (index / 2) * 3 + (index % 2);
      break;
    case FatType::FAT_16:
      fat_offset = index * 16 / 8;
      break;
    case FatType::FAT_32:
      fat_offset = index * 32 / 8;
      break;
  }
  const int64_t read_pos = fat_start + fat_offset;
  const int read_size = fat_type == FatType::FAT_32 ? 4 : 2;
  char buf[4];
  if (file->Read(read_pos, buf, read_size) != read_size) {
    LOG(ERROR) << "Read error at " << read_pos;
    return kInvalidValue;
  }
  int64_t result = kInvalidValue;
  switch (fat_type) {
    case FatType::FAT_12: {
      const int n_shift = (index % 2) ? 4 : 0;
      result = (le16toh(*reinterpret_cast<__le16*>(buf)) >> n_shift) & 0xfff;
      if (result < FAT_START_ENT || result >= BAD_FAT12)
        result = kInvalidValue;
      break;
    }
    case FatType::FAT_16:
      result = le16toh(*reinterpret_cast<__le16*>(buf));
      if (result < FAT_START_ENT || result >= BAD_FAT16)
        result = kInvalidValue;
      break;
    case FatType::FAT_32:
      result = le32toh(*reinterpret_cast<__le32*>(buf));
      if (result < FAT_START_ENT || result >= BAD_FAT32)
        result = kInvalidValue;
      break;
  }
  return result;
}

}  // namespace fat
