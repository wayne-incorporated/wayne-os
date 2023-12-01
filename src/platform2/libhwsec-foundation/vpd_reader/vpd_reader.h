// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_VPD_READER_VPD_READER_H_
#define LIBHWSEC_FOUNDATION_VPD_READER_VPD_READER_H_

#include <optional>
#include <string>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

class HWSEC_FOUNDATION_EXPORT VpdReader {
 public:
  VpdReader() = default;
  virtual ~VpdReader() = default;

  // Gets a single value of `key`.
  virtual std::optional<std::string> Get(const std::string& key) = 0;
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_VPD_READER_VPD_READER_H_
