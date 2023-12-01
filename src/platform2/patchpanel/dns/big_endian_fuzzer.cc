// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "patchpanel/dns/big_endian.h"

namespace patchpanel {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  FuzzedDataProvider provider(data, size);
  std::string str_buf = provider.ConsumeRandomLengthString(256);
  base::BigEndianReader reader(str_buf.c_str(), str_buf.length());

  static constexpr size_t kLen = 16;
  char buf[kLen];
  base::StringPiece s;
  uint8_t u8;
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;
  while (reader.remaining() > 0) {
    reader.ReadU8(&u8);
    uint8_t x = u8 % 3;
    if (x == 0)
      reader.ReadU16(&u16);
    else if (x == 1)
      reader.ReadU32(&u32);
    else
      reader.ReadU64(&u64);

    reader.ReadU8(&u8);
    reader.ReadBytes(&buf, u8 % kLen);
    reader.ReadU8(&u8);
    reader.ReadPiece(&s, u8 % kLen);
  }

  return 0;
}

}  // namespace patchpanel
