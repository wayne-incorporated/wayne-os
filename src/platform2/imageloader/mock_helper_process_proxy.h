// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGELOADER_MOCK_HELPER_PROCESS_PROXY_H_
#define IMAGELOADER_MOCK_HELPER_PROCESS_PROXY_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "imageloader/helper_process_proxy.h"
#include "imageloader/imageloader_impl.h"

namespace imageloader {

// Mock helper process used for unit testing.
class MockHelperProcessProxy : public HelperProcessProxy {
 public:
  MockHelperProcessProxy() = default;
  MockHelperProcessProxy(const MockHelperProcessProxy&) = delete;
  MockHelperProcessProxy& operator=(const MockHelperProcessProxy&) = delete;

  ~MockHelperProcessProxy() = default;

  // Sends a message telling the helper process to mount the file backed by |fd|
  // at the |path|.
  MOCK_METHOD(bool,
              SendMountCommand,
              (int, const std::string&, FileSystem, const std::string&),
              (override));

  MOCK_METHOD(bool,
              SendUnmountAllCommand,
              (bool, const std::string&, std::vector<std::string>* paths),
              (override));

  MOCK_METHOD(bool, SendUnmountCommand, (const std::string&), (override));
};

}  // namespace imageloader

#endif  // IMAGELOADER_MOCK_HELPER_PROCESS_PROXY_H_
