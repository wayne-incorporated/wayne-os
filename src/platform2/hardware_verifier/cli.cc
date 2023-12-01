/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hardware_verifier/cli.h"

#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/json_util.h>
#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

#include "hardware_verifier/hardware_verifier.pb.h"
#include "hardware_verifier/hw_verification_report_getter_impl.h"
#include "hardware_verifier/observer.h"

namespace hardware_verifier {

namespace {

using ReportGetterErrorCode = HwVerificationReportGetter::ErrorCode;

CLIVerificationResult
ConvertHwVerificationReportGetterErrorCodeToCLIVerificationResult(
    ReportGetterErrorCode error_code) {
  switch (error_code) {
    case ReportGetterErrorCode::kErrorCodeMissingDefaultHwVerificationSpecFile:
      return CLIVerificationResult::kSkippedVerification;
    case ReportGetterErrorCode::kErrorCodeInvalidHwVerificationSpecFile:
      return CLIVerificationResult::kInvalidHwVerificationSpecFile;
    case ReportGetterErrorCode::kErrorCodeInvalidProbeResultFile:
      return CLIVerificationResult::kInvalidProbeResultFile;
    case ReportGetterErrorCode::kErrorCodeProbeFail:
      return CLIVerificationResult::kProbeFail;
    case ReportGetterErrorCode::
        kErrorCodeProbeResultHwVerificationSpecMisalignment:
      return CLIVerificationResult::kProbeResultHwVerificationSpecMisalignment;
    case ReportGetterErrorCode::kErrorCodeNoError:
    default:
      NOTREACHED() << "Invalid HwVerificationReportGetter::ErrorCode: "
                   << static_cast<int>(error_code);
      return CLIVerificationResult::kUnknownError;
  }
}

std::optional<std::string> OutputInTextFormat(
    HwVerificationReport hw_verification_report, bool pii) {
  std::stringstream ss;
  const auto generic_device_info = hw_verification_report.generic_device_info();
  hw_verification_report.clear_generic_device_info();

  // Output the AVL qualification status in JSON format.
  auto json_print_opts = google::protobuf::util::JsonPrintOptions();
  json_print_opts.add_whitespace = true;
  json_print_opts.always_print_primitive_fields = true;
  std::string json_output_data;
  const auto convert_status = google::protobuf::util::MessageToJsonString(
      hw_verification_report, &json_output_data, json_print_opts);
  if (!convert_status.ok()) {
    LOG(ERROR) << "Failed to output the qualification report in JSON: "
               << convert_status.ToString() << ".";
    return std::nullopt;
  }
  ss << "[Component Qualification Status]\n" << json_output_data;

  if (pii) {
    // Output the generic device info in prototxt format.
    ss << "\n[Generic Device Info]\n";
    // Enclose google::protobuf::io::OstreamOutputStream in another nested
    // scope so that its data will be flushed while being destroyed.
    google::protobuf::io::OstreamOutputStream ostream_output_stream{&ss};
    if (!google::protobuf::TextFormat::Print(generic_device_info,
                                             &ostream_output_stream)) {
      LOG(ERROR)
          << "Failed to output the generic device info in prototxt format.";
      return std::nullopt;
    }
  }
  return ss.str();
}

}  // namespace

CLI::CLI()
    : vr_getter_(std::make_unique<HwVerificationReportGetterImpl>()),
      output_stream_(&std::cout) {}

CLIVerificationResult CLI::Run(const std::string& probe_result_file,
                               const std::string& hw_verification_spec_file,
                               const CLIOutputFormat output_format,
                               bool pii) {
  ReportGetterErrorCode error_code;
  auto hw_verification_report = vr_getter_->Get(
      probe_result_file, hw_verification_spec_file, &error_code);
  if (error_code != ReportGetterErrorCode::kErrorCodeNoError) {
    return ConvertHwVerificationReportGetterErrorCodeToCLIVerificationResult(
        error_code);
  }

  if (!pii) {
    // Remove PII data.
    for (auto& mutable_component :
         *(hw_verification_report->mutable_found_component_infos())) {
      mutable_component.clear_component_uuid();
    }
    hw_verification_report->clear_generic_device_info();
  }

  LOG(INFO) << "Output the report.";
  switch (output_format) {
    case CLIOutputFormat::kProtoBin: {
      std::string s;
      if (!hw_verification_report->SerializeToString(&s)) {
        return CLIVerificationResult::kUnknownError;
      }
      LOG(INFO) << "Output the report in protobuf binary format, " << s.size()
                << "bytes.";
      *output_stream_ << s;
      break;
    }
    case CLIOutputFormat::kText: {
      auto output_data = OutputInTextFormat(*hw_verification_report, pii);
      if (!output_data.has_value()) {
        return CLIVerificationResult::kUnknownError;
      }
      LOG(INFO) << "Output the report in text format:";
      LOG(INFO) << output_data.value();
      *output_stream_ << output_data.value();
    }
  }

  LOG(INFO) << "Send to Observer.";
  auto observer = Observer::GetInstance();
  observer->RecordHwVerificationReport(*hw_verification_report);

  return (hw_verification_report->is_compliant()
              ? CLIVerificationResult::kPass
              : CLIVerificationResult::kFail);
}

}  // namespace hardware_verifier
