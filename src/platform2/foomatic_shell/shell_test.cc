// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "foomatic_shell/shell.h"

#include <cstdio>
#include <string>

#include <sys/mman.h>

#include "foomatic_shell/process_launcher.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

namespace foomatic_shell {

TEST(Shell, ExecuteShellScript) {
  const std::string data = "it is working";
  const size_t data_size = data.size();
  const std::string script =
      "echo -n \"`echo 'it is working'`\"\n"
      "NOPDF=yes echo -n | cat\n";

  int stdout_fd = memfd_create("foomatic-shell-stdout", 0);
  ASSERT_NE(stdout_fd, -1);

  EXPECT_EQ(ExecuteShellScript(script, stdout_fd, true, false), 0);

  FILE* stdout_fp = fdopen(stdout_fd, "rb");
  ASSERT_NE(stdout_fp, nullptr);
  fseek(stdout_fp, 0, SEEK_SET);
  for (size_t i = 0; i < data_size; i++) {
    EXPECT_EQ(fgetc(stdout_fp), (int)data[i]);
  }
  EXPECT_EQ(fgetc(stdout_fp), EOF);
  fclose(stdout_fp);  // this also closes stdout_fd
}

TEST(Shell, ExecuteShellScriptAndReportCpuTimeSuccess) {
  const std::string data = "it is working";
  const size_t data_size = data.size();
  const std::string script = "echo -n 'it is working'";

  int stdout_fd = memfd_create("foomatic-shell-stdout", 0);
  ASSERT_NE(stdout_fd, -1);

  testing::StrictMock<MetricsLibraryMock> metrics;
  EXPECT_CALL(metrics,
              SendToUMA("ChromeOS.Printing.TimeCostOfSuccessfulFoomaticShell",
                        testing::_, kUmaHistogramMin, kUmaHistogramMax,
                        kUmaHistogramNumBuckets));
  EXPECT_EQ(ExecuteShellScriptAndReportCpuTime(script, stdout_fd, true, false,
                                               metrics),
            0);

  FILE* stdout_fp = fdopen(stdout_fd, "rb");
  ASSERT_NE(stdout_fp, nullptr);
  fseek(stdout_fp, 0, SEEK_SET);
  for (size_t i = 0; i < data_size; i++) {
    EXPECT_EQ(fgetc(stdout_fp), (int)data[i]);
  }
  EXPECT_EQ(fgetc(stdout_fp), EOF);
  fclose(stdout_fp);  // this also closes stdout_fd
}

TEST(Shell, ExecuteShellScriptAndReportCpuTimeFailure) {
  const std::string script = "touch /tmp/new_file";

  int stdout_fd = memfd_create("foomatic-shell-stdout", 0);
  ASSERT_NE(stdout_fd, -1);

  testing::StrictMock<MetricsLibraryMock> metrics;
  EXPECT_CALL(
      metrics,
      SendToUMA("ChromeOS.Printing.TimeCostOfFailedFoomaticShell", testing::_,
                kUmaHistogramMin, kUmaHistogramMax, kUmaHistogramNumBuckets));
  EXPECT_EQ(ExecuteShellScriptAndReportCpuTime(script, stdout_fd, false, false,
                                               metrics),
            kShellError);
}

}  // namespace foomatic_shell
