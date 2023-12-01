// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/uploader/metrics_hashes.h"

#include <base/check_op.h>
#include <base/hash/md5.h>
#include <base/logging.h>
#include <base/sys_byteorder.h>

namespace metrics {

namespace {

// Converts the 8-byte prefix of an MD5 hash into a uint64_t value.
inline uint64_t HashToUInt64(const std::string& hash) {
  uint64_t value;
  DCHECK_GE(hash.size(), sizeof(value));
  memcpy(&value, hash.data(), sizeof(value));
  return base::HostToNet64(value);
}

}  // namespace

uint64_t HashMetricName(const std::string& name) {
  // Create an MD5 hash of the given |name|, represented as a byte buffer
  // encoded as an std::string.
  base::MD5Context context;
  base::MD5Init(&context);
  base::MD5Update(&context, name);

  base::MD5Digest digest;
  base::MD5Final(&digest, &context);

  std::string hash_str(reinterpret_cast<char*>(digest.a), std::size(digest.a));
  return HashToUInt64(hash_str);
}

}  // namespace metrics
