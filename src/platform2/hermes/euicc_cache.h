// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_EUICC_CACHE_H_
#define HERMES_EUICC_CACHE_H_

#include "hermes/cached_euicc.pb.h"

#include <base/logging.h>
#include <base/files/file_util.h>
#include <brillo/proto_file_io.h>

namespace hermes {

class EuiccCache {
 public:
  static bool CacheExists(int physical_slot);
  static bool Read(int physical_slot, CachedEuicc* cached_euicc);
  static bool Write(int physical_slot, CachedEuicc euicc);
};

}  // namespace hermes

#endif  // HERMES_EUICC_CACHE_H_
