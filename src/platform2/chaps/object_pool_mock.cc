// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_pool_mock.h"

#include "chaps/object.h"

namespace chaps {

ObjectPoolMock::ObjectPoolMock() {}
ObjectPoolMock::~ObjectPoolMock() {
  for (size_t i = 0; i < v_.size(); ++i) {
    delete v_[i];
  }
}

}  // namespace chaps
