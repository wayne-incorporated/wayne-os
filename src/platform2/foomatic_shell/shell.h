// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FOOMATIC_SHELL_SHELL_H_
#define FOOMATIC_SHELL_SHELL_H_

#include <string>

#include <metrics/metrics_library.h>

namespace foomatic_shell {

// The maximum size of single script is 16KB.
constexpr size_t kMaxSourceSize = 16 * 1024;

// Parameters of the histogram for the metrics:
//  * ChromeOS.Printing.TimeCostOfSuccessfulFoomaticShell,
//  * ChromeOS.Printing.TimeCostOfFailedFoomaticShell.
// Min and max values are in seconds.
constexpr int kUmaHistogramMin = 1;
constexpr int kUmaHistogramMax = 1000;
constexpr int kUmaHistogramNumBuckets = 20;

// Parse and execute a shell script in |source|. Generated output is saved to
// the file descriptor |output_fd|. When necessary, input data is read from the
// standard input (file descriptor = 0). Error messages are written to standard
// error stream (file descriptor = 2). |output_fd| must be a valid file
// descriptor different that 0 and 2. |verbose_mode| is used to control logging
// level - all logs are dumped to stderr. |verify_mode| is used to disable
// execution of the shell script. |recursion_level| is used to control
// maximum recursion depth and should be set to the default value. The function
// returns exit code returned by executed script or values:
//  * 127 in case of a shell error,
//  * 126 when a child ghostscript process reached CPU time limit.
int ExecuteShellScript(const std::string& source,
                       const int output_fd,
                       const bool verbose_mode,
                       const bool verify_mode,
                       const int recursion_level = 0);

// Wrapper around ExecuteShellScript() that reports CPU time to `metrics` at
// the end.
int ExecuteShellScriptAndReportCpuTime(const std::string& source,
                                       const int output_fd,
                                       const bool verbose_mode,
                                       const bool verify_mode,
                                       MetricsLibraryInterface& metrics,
                                       const int recursion_level = 0);

}  // namespace foomatic_shell

#endif  // FOOMATIC_SHELL_SHELL_H_
