// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_CGPT_WRAPPER_H_
#define MINIOS_MOCK_CGPT_WRAPPER_H_

#include "minios/cgpt_wrapper_interface.h"

#include <gmock/gmock.h>

namespace minios {

class MockCgptWrapper : public CgptWrapperInterface {
 public:
  MOCK_METHOD(void, CgptFind, (CgptFindParams * params), (const, override));
  MOCK_METHOD(int,
              CgptGetPartitionDetails,
              (CgptAddParams * params),
              (const, override));
};

}  // namespace minios

#endif  // MINIOS_MOCK_CGPT_WRAPPER_H_
