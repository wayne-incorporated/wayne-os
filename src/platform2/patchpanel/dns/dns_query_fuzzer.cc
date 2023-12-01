// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "patchpanel/dns/big_endian.h"
#include "patchpanel/dns/dns_query.h"
#include "patchpanel/dns/io_buffer.h"

namespace patchpanel {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  FuzzedDataProvider provider(data, size);
  auto buf = base::MakeRefCounted<IOBufferWithSize>(size);
  size_t buf_size = static_cast<size_t>(buf->size());
  base::BigEndianWriter writer(buf->data(), buf_size);
  writer.WriteBytes(data, size);
  DnsQuery query(buf);
  query.Parse(buf_size);

  return 0;
}

}  // namespace patchpanel
