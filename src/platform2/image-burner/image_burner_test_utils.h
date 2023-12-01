// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGE_BURNER_IMAGE_BURNER_TEST_UTILS_H_
#define IMAGE_BURNER_IMAGE_BURNER_TEST_UTILS_H_

#include <stdint.h>

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "image-burner/image_burner_utils_interfaces.h"

namespace imageburn {

class MockFileSystemWriter : public FileSystemWriter {
 public:
  MOCK_METHOD(bool, Open, (const char*), (override));
  MOCK_METHOD(bool, Close, (), (override));
  MOCK_METHOD(int, Write, (const char*, int), (override));
};

class MockFileSystemReader : public FileSystemReader {
 public:
  MOCK_METHOD(bool, Open, (const char*), (override));
  MOCK_METHOD(bool, Close, (), (override));
  MOCK_METHOD(int64_t, GetSize, (), (override));
  MOCK_METHOD(int, Read, (char*, int), (override));
};

class MockSignalSender : public SignalSender {
 public:
  MOCK_METHOD(void,
              SendFinishedSignal,
              (const char*, bool, const char*),
              (override));
  MOCK_METHOD(void,
              SendProgressSignal,
              (int64_t, int64_t, const char*),
              (override));
};

class MockPathGetter : public PathGetter {
 public:
  MOCK_METHOD(bool, GetRealPath, (const char*, std::string*), (override));
  MOCK_METHOD(bool, GetRootPath, (std::string*), (override));
};

}  // namespace imageburn

#endif  // IMAGE_BURNER_IMAGE_BURNER_TEST_UTILS_H_
