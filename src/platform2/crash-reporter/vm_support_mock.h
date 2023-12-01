// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_VM_SUPPORT_MOCK_H_
#define CRASH_REPORTER_VM_SUPPORT_MOCK_H_

#include <string>

#include <gmock/gmock.h>

#include "crash-reporter/vm_support.h"

class VmSupportMock : public VmSupport {
 public:
  MOCK_METHOD(void, AddMetadata, (UserCollector * collector), (override));
  MOCK_METHOD(void,
              FinishCrash,
              (const base::FilePath& crash_meta_path),
              (override));
  MOCK_METHOD(bool, GetMetricsConsent, (), (override));
  MOCK_METHOD(bool,
              ShouldDump,
              (pid_t pid, std::string* out_reason),
              (override));
};

#endif  // CRASH_REPORTER_VM_SUPPORT_MOCK_H_
