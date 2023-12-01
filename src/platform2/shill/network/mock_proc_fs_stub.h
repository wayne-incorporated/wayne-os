// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_MOCK_PROC_FS_STUB_H_
#define SHILL_NETWORK_MOCK_PROC_FS_STUB_H_

#include <memory>
#include <string>

#include <gmock/gmock.h>

#include "shill/network/proc_fs_stub.h"

namespace shill {

class MockProcFsStub : public ProcFsStub {
 public:
  explicit MockProcFsStub(const std::string& interface_name);
  MockProcFsStub(const MockProcFsStub&) = delete;
  MockProcFsStub& operator=(const MockProcFsStub&) = delete;
  ~MockProcFsStub() override;

  MOCK_METHOD(bool,
              SetIPFlag,
              (IPAddress::Family, const std::string&, const std::string&),
              (override));
};
}  // namespace shill

#endif  // SHILL_NETWORK_MOCK_PROC_FS_STUB_H_
