// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef IMAGELOADER_MOCK_VERITY_MOUNTER_H_
#define IMAGELOADER_MOCK_VERITY_MOUNTER_H_

#include "imageloader/verity_mounter.h"

#include <string>

#include "imageloader/gmock/gmock.h"

namespace imageloader {

class MockVerityMounter : public VerityMounter {
 public:
  MockVerityMounter() = default;
  MockVerityMounter(const MockVerityMounter&) = delete;
  MockVerityMounter& operator=(const MockVerityMounter&) = delete;

  MOCK_METHOD(bool,
              Mount,
              (const base::ScopedFD&,
               const base::FilePath&,
               const std::string&),
              (override));
};

}  // namespace imageloader

#endif  // IMAGELOADER_MOCK_VERITY_MOUNTER_H_
