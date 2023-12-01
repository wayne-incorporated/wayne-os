/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_CLI_H_
#define HARDWARE_VERIFIER_CLI_H_

#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "hardware_verifier/hw_verification_report_getter.h"

namespace hardware_verifier {

enum CLIVerificationResult {
  kPass = 0,

  // The whole process works without errors, but the verification
  // report shows the device is not compliant.
  kFail,

  // Skip the verification process.
  kSkippedVerification,

  // Failed to load the probe result from the specific file.
  kInvalidProbeResultFile,

  // Failed to load the verification payload from either the default one
  // or the specific one.
  kInvalidHwVerificationSpecFile,

  // The |runtime_probe| fails to return a valid probe result.
  kProbeFail,

  // Content in the verification payload and the probe result are not matched
  // to each other.
  kProbeResultHwVerificationSpecMisalignment,

  kUnknownError
};

enum CLIOutputFormat {
  kProtoBin,  // Protobuf binary format.
  kText       // Human readable text format for debug purpose.
};

// A class that holds the core logic of the program if runs in CLI mode.
class CLI {
 public:
  // Constructor, it sets the dependent classes to the default implementation.
  CLI();
  CLI(const CLI&) = delete;
  CLI& operator=(const CLI&) = delete;

  // Verifies the probe result with the verification payload and then outputs
  // the report.
  //
  // @param probe_result_file: Path to the file that contains the probe result.
  //     If the string is empty, it invokes |runtime_probe| to get the probe
  //     result.
  // @param hw_verification_spec_file: Path to the file that contains the
  //     verification payload.  If the string is empty, it reads the default
  //     verification payload file in the rootfs.
  // @param output_format: The format of the output data.
  // @param pii: Output result including PII data like UUID and generic device
  // info.
  //
  // @return Execution result, can be either the verification result or the
  //     failure code.
  CLIVerificationResult Run(const std::string& probe_result_file,
                            const std::string& hw_verification_spec_file,
                            const CLIOutputFormat output_format,
                            bool pii);

 protected:
  // This constructor is reserved only for testing.
  CLI(std::unique_ptr<HwVerificationReportGetter> vr_getter,
      std::ostream* output_stream)
      : vr_getter_(std::move(vr_getter)), output_stream_(output_stream) {}

 private:
  // Dependent classes.
  std::unique_ptr<HwVerificationReportGetter> vr_getter_;

  // Instance to the output stream, default to |std::cout|.
  std::ostream* output_stream_;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_CLI_H_
