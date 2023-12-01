// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HAMMERD_MOCK_FMAP_UTILS_H_
#define HAMMERD_MOCK_FMAP_UTILS_H_

#include <string>

#include <gmock/gmock.h>

#include "hammerd/fmap_utils.h"

namespace hammerd {

class MockFmap : public FmapInterface {
 public:
  MOCK_METHOD(int64_t, Find, (const uint8_t*, unsigned int), (override));
  MOCK_METHOD(const fmap_area*,
              FindArea,
              (const fmap*, const std::string&),
              (override));
};

}  // namespace hammerd
#endif  // HAMMERD_MOCK_FMAP_UTILS_H_
