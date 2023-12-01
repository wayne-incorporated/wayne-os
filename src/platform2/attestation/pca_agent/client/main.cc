// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <sysexits.h>

#include <memory>
#include <optional>
#include <string>

#include <attestation/proto_bindings/pca_agent.pb.h>
#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/dbus/dbus_connection.h>
#include <brillo/syslog_logging.h>
#include <dbus/bus.h>

#include "attestation/common/print_interface_proto.h"
#include "attestation/pca_agent/dbus-proxies.h"

namespace {
const char kEnrollCommand[] = "enroll";
const char kGetCertificateCommand[] = "get_certificate";
const char kUsage[] = R"(
Usage: pca_agent_client <command> [<args>]
Commands:
  enroll --input=<input_file> --output=<output_file>
      Sends the enroll request stored in |input| to PCA server and stores the
      response in |output|.
  get_certificate --input=<input_file> --output=<output_file>
      Sends the cert request stored in |input| to PCA server and stores the
      response in |output|.
)";

const char kInputSwitch[] = "input";
const char kOutputSwitch[] = "output";
const char kACATypeSwitch[] = "aca_type";

std::optional<attestation::ACAType> GetACAType(base::CommandLine* cmd_line) {
  const std::string val = cmd_line->GetSwitchValueASCII(kACATypeSwitch);
  if (val.empty() || val == "default") {
    return attestation::DEFAULT_ACA;
  }
  if (val == "test") {
    return attestation::TEST_ACA;
  }
  return std::nullopt;
}
}  // namespace

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
  const auto& args = command_line->GetArgs();
  brillo::InitLog(brillo::kLogToStderr);

  // dbus proxy setup
  brillo::DBusConnection connection;
  scoped_refptr<dbus::Bus> bus = connection.Connect();
  CHECK(bus) << "Failed to connect to system bus through libbrillo";
  auto pca_agent = std::make_unique<org::chromium::PcaAgentProxy>(bus);

  brillo::ErrorPtr error;
  if (command_line->HasSwitch("help") || command_line->HasSwitch("h") ||
      args.empty()) {
    printf("%s", kUsage);
    return EX_USAGE;
  }
  if (args.front() == kEnrollCommand) {
    std::string input_filename =
        command_line->GetSwitchValueASCII(kInputSwitch);
    std::string output_filename =
        command_line->GetSwitchValueASCII(kOutputSwitch);
    if (input_filename.empty() || output_filename.empty()) {
      printf("%s", kUsage);
      return EX_USAGE;
    }
    auto aca_type = GetACAType(command_line);
    if (!aca_type) {
      printf("%s", kUsage);
      return EX_USAGE;
    }
    attestation::pca_agent::EnrollRequest req;
    if (!base::ReadFileToString(base::FilePath(input_filename),
                                req.mutable_request())) {
      LOG(ERROR) << "Failed to read file: " << input_filename;
      return EX_IOERR;
    }
    req.set_aca_type(*aca_type);
    attestation::pca_agent::EnrollReply reply;
    if (!pca_agent->Enroll(req, &reply, &error)) {
      LOG(ERROR) << "Error sending dbus message: " << error->GetMessage();
      return EX_SOFTWARE;
    }
    if (reply.status() != attestation::STATUS_SUCCESS) {
      LOG(ERROR) << "Failed to enroll: " << GetProtoDebugString(reply.status());
      return EX_SOFTWARE;
    }
    if (reply.response().empty()) {
      LOG(ERROR) << "Unexpected empty response";
      return EX_SOFTWARE;
    }
    if (base::WriteFile(base::FilePath(output_filename),
                        reply.response().data(), reply.response().size()) !=
        static_cast<int>(reply.response().size())) {
      LOG(ERROR) << "Failed to write file: " << output_filename;
      return EX_IOERR;
    }
  } else if (args.front() == kGetCertificateCommand) {
    std::string input_filename =
        command_line->GetSwitchValueASCII(kInputSwitch);
    std::string output_filename =
        command_line->GetSwitchValueASCII(kOutputSwitch);
    if (input_filename.empty() || output_filename.empty()) {
      printf("%s", kUsage);
      return EX_USAGE;
    }
    auto aca_type = GetACAType(command_line);
    if (!aca_type) {
      printf("%s", kUsage);
      return EX_USAGE;
    }
    attestation::pca_agent::GetCertificateRequest req;
    if (!base::ReadFileToString(base::FilePath(input_filename),
                                req.mutable_request())) {
      LOG(ERROR) << "Failed to read file: " << input_filename;
      return EX_IOERR;
    }
    req.set_aca_type(*aca_type);
    attestation::pca_agent::GetCertificateReply reply;
    if (!pca_agent->GetCertificate(req, &reply, &error)) {
      LOG(ERROR) << "Error sending dbus message: " << error->GetMessage();
      return EX_SOFTWARE;
    }
    if (reply.status() != attestation::STATUS_SUCCESS) {
      LOG(ERROR) << "Failed to get certificate: "
                 << GetProtoDebugString(reply.status());
      return EX_SOFTWARE;
    }
    if (reply.response().empty()) {
      LOG(ERROR) << "Unexpected empty response";
      return EX_SOFTWARE;
    }
    if (base::WriteFile(base::FilePath(output_filename),
                        reply.response().data(), reply.response().size()) !=
        static_cast<int>(reply.response().size())) {
      LOG(ERROR) << "Failed to write file: " << output_filename;
      return EX_IOERR;
    }
  }
  return EX_OK;
}
