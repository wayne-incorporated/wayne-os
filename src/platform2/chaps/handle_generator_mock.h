// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_HANDLE_GENERATOR_MOCK_H_
#define CHAPS_HANDLE_GENERATOR_MOCK_H_

#include "chaps/handle_generator.h"

namespace chaps {

class HandleGeneratorMock : public HandleGenerator {
 public:
  MOCK_METHOD0(CreateHandle, int());
};

}  // namespace chaps

#endif  // CHAPS_HANDLE_GENERATOR_MOCK_H_
