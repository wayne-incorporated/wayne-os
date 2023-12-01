// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_MK_TESTRUNNER_H_
#define COMMON_MK_TESTRUNNER_H_

#include <memory>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/test/test_timeouts.h>
#include <brillo/syslog_logging.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace platform2 {

// The TestRunner class allows platform2 components to override the default
// testrunner behavior if they have special requirements.
//
// For example, if your test already instantiates a base::AtExitManager, you
// can tell TestRunner not to instantiate another one (multiple instances
// will result in an assert):
//
//  // your_testrunner.cc
//  #include "common-mk/testrunner.h"
//  int main(int argc, char** argv) {
//    platform2::TestRunner::Options opts;
//    opts.instantiate_exit_manager = false;
//    auto runner = platform2::TestRunner(argc, argv, opts);
//    return runner.Run();
//  }
class TestRunner {
 public:
  struct Options {
    // Should be "= default". Using an empty constructor instead to work around
    // a clang bug: https://github.com/llvm/llvm-project/issues/36032
    Options() {}  // = default;
    bool instantiate_exit_manager = true;
    bool instantiate_test_timeouts = true;
    // If true, initializes brillo logging so tests would be able to test logs
    // by calling
    //   brillo::LogToString(true);
    //   brillo::ClearLog();
    //   // Code that produces logs...
    //   // Checks that examine logs from brillo::GetLog()...
    bool initialize_brillo_logging = true;
  };

  TestRunner(int argc, char** argv, const Options& opts = Options()) {
    base::CommandLine::Init(argc, argv);

    if (opts.initialize_brillo_logging) {
      brillo::InitLog(brillo::kLogToStderr);
    } else {
      logging::InitLogging(logging::LoggingSettings());
    }

    if (opts.instantiate_exit_manager) {
      exit_manager_ = std::make_unique<base::AtExitManager>();
    }

    if (opts.instantiate_test_timeouts) {
      TestTimeouts::Initialize();
    }

    testing::InitGoogleTest(&argc, argv);
    testing::InitGoogleMock(&argc, argv);
  }

  int Run() { return RUN_ALL_TESTS(); }

 private:
  std::unique_ptr<base::AtExitManager> exit_manager_;
};

}  // namespace platform2

#endif  // COMMON_MK_TESTRUNNER_H_
