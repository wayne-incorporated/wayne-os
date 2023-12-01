// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_KERNEL_COLLECTOR_TEST_H_
#define CRASH_REPORTER_KERNEL_COLLECTOR_TEST_H_

#include "crash-reporter/kernel_collector.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

class KernelCollectorMock : public KernelCollector {
 public:
  MOCK_METHOD(bool, DumpDirMounted, (), (override));
  MOCK_METHOD(void, SetUpDBus, (), (override));
};

#endif  // CRASH_REPORTER_KERNEL_COLLECTOR_TEST_H_
