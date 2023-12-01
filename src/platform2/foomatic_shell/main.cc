// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdio>
#include <string>

#include <base/environment.h>
#include <metrics/metrics_library.h>

#include "foomatic_shell/shell.h"

namespace {

// Description of the supported parameters.
const char kDescription[] =
    "Supported parameters:\n  -c - execute the script given in the next "
    "parameter\n  -v - verbose mode\n  -e - this parameter is ignored.\n";

// Prints a message |msg| to stderr and append to it the description of the
// supported parameters.
void PrintErrorMessage(const std::string& msg) {
  fprintf(stderr, "Incorrect parameters: %s.\n%s", msg.c_str(), kDescription);
}

}  // namespace

int main(int argc, char** argv) {
  char* script = nullptr;
  bool verbose = false;
  bool verify = base::Environment::Create()->HasVar("FOOMATIC_VERIFY_MODE");

  // Parse the input parameters.
  for (int i = 1; i < argc; ++i) {
    const std::string parameter = argv[i];
    // Option -c is supposed to be followed by a script to execute.
    if (parameter == "-c") {
      if (script != nullptr) {
        PrintErrorMessage("No more than one -c parameter is allowed");
        return -1;
      }
      if (++i == argc) {
        PrintErrorMessage("No script after -c parameter");
        return -1;
      }
      script = argv[i];
      continue;
    }
    // Parameter -v means verbose mode.
    if (parameter == "-v") {
      verbose = true;
      continue;
    }
    // Parameter -e is ignored.
    if (parameter == "-e")
      continue;
    // Unknown parameter - exit with an error.
    PrintErrorMessage("Unknown parameter " + parameter);
    return -1;
  }

  // The parameter -c must be specified.
  if (script == nullptr) {
    PrintErrorMessage("Parameter -c must be set");
    return -1;
  }

  // Run in the standard mode (execute given script).
  if (strlen(script) > foomatic_shell::kMaxSourceSize) {
    PrintErrorMessage("The script provided with -c parameter is too large");
    return -1;
  }
  MetricsLibrary metrics;
  return foomatic_shell::ExecuteShellScriptAndReportCpuTime(
      std::string(script), 1, verbose, verify, metrics);
}
