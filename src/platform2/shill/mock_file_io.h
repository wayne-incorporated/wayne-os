// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_FILE_IO_H_
#define SHILL_MOCK_FILE_IO_H_

#include "shill/file_io.h"

#include <gmock/gmock.h>

namespace shill {

class MockFileIO : public FileIO {
 public:
  MockFileIO();
  MockFileIO(const MockFileIO&) = delete;
  MockFileIO& operator=(const MockFileIO&) = delete;

  ~MockFileIO() override;

  MOCK_METHOD(ssize_t, Write, (int, const void*, size_t), (override));
  MOCK_METHOD(ssize_t, Read, (int, void*, size_t), (override));
  MOCK_METHOD(int, Close, (int), (override));
  MOCK_METHOD(int, SetFdNonBlocking, (int), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_FILE_IO_H_
