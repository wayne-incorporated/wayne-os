// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGELOADER_MOCK_GLOBAL_CONTEXT_H_
#define IMAGELOADER_MOCK_GLOBAL_CONTEXT_H_

#include <gmock/gmock.h>

#include "imageloader/global_context.h"

namespace imageloader {

class MockGlobalContext : public GlobalContext {
 public:
  MockGlobalContext() = default;
  ~MockGlobalContext() = default;

  MockGlobalContext(const MockGlobalContext&) = delete;
  MockGlobalContext& operator=(const MockGlobalContext&) = delete;

  MOCK_METHOD(bool, IsOfficialBuild, (), (const override));
};

}  // namespace imageloader

#endif  // IMAGELOADER_MOCK_GLOBAL_CONTEXT_H_
