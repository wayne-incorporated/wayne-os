// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/verified_access/verified_access.h"

#include <optional>
#include <stdio.h>
#include <utility>

#include <base/base64.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <brillo/data_encoding.h>
#include <brillo/syslog_logging.h>

namespace {

constexpr char kGenerateCommand[] = "generate";
constexpr char kVerifyCommand[] = "verify";

constexpr char kInputSwitch[] = "input";
constexpr char kBinarySwitch[] = "binary";

const char kUsage[] = R"(
Usage: hwsec-test-va <command> [<args>]
Commands:
  |generate|
      Generates a VA challenge signed with well-known VA signing key and prints
      the base64-encoded result in stdout.
  |verify| --input=<filename> [--binary]
      Verifies the VA challenge response from attestation service. By default,
      reads last argument that follows as the base64-encoded response. If the
      input is in binary (i.e., not base64-encoded), specify '--binary'.
)";

constexpr char kExpectedChallengePrefix[] = "EnterpriseKeyChallenge";

void PrintUsage() {
  printf("%s", kUsage);
}

}  // namespace

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToStderr);

  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  const auto& args = cl->GetArgs();
  if (args.empty()) {
    PrintUsage();
    return 1;
  }

  if (args.front() == kGenerateCommand) {
    hwsec_test_utils::verified_access::VerifiedAccessChallenge va;
    std::optional<attestation::SignedData> challenge =
        va.GenerateChallenge(kExpectedChallengePrefix);
    if (!challenge) {
      printf("Failed to generate VA challenge.\n");
      return 1;
    }
    std::string serialized_challenge;
    if (!challenge->SerializeToString(&serialized_challenge)) {
      printf("Failed to serialize VA challenge.\n");
      return 1;
    }
    printf("%s",
           brillo::data_encoding::Base64Encode(serialized_challenge).c_str());
    return 0;
  }

  if (args.front() == kVerifyCommand) {
    const std::string path = cl->GetSwitchValueASCII(kInputSwitch);
    if (path.empty()) {
      printf("No valid file path specified.\n");
      return 1;
    }
    std::string data;
    if (!base::ReadFileToString(base::FilePath(path), &data)) {
      printf("Failed to read file.\n");
      return 1;
    }
    if (!cl->HasSwitch(kBinarySwitch)) {
      std::string tmp;
      if (!brillo::data_encoding::Base64Decode(data, &tmp)) {
        printf("Failed to base64 decode the file content.\n");
        return 1;
      }
      data = std::move(tmp);
    }
    // At this point, |data| is the binary representation regardless of the
    // given data format.
    attestation::SignedData signed_challenge_response;
    if (!signed_challenge_response.ParseFromString(data)) {
      printf("Failed to parse serialized |attestation::SignedData|.\n");
      return 1;
    }

    hwsec_test_utils::verified_access::VerifiedAccessChallenge va;
    if (!va.VerifyChallengeResponse(signed_challenge_response,
                                    kExpectedChallengePrefix)) {
      printf("Failed to verify challenge response.\n");
      return 1;
    }
    printf("Succeeded.\n");
    return 0;
  }

  // None of the command matches; print usage and return non-zero exit status.
  PrintUsage();
  return 1;
}
