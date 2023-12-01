// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzz test for ParseUploadsLog.

#include "diagnostics/cros_healthd/events/crash_events.h"

#include <string>
#include <vector>

#include <base/time/time.h>
#include <base/logging.h>
#include <base/json/json_writer.h>
#include <base/values.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace diagnostics {

namespace mojom = ash::cros_healthd::mojom;

namespace {
class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

// Generates a lower-case random alphabetical string of a fixed length 16.
std::string ConsumeAlphabeticalString(FuzzedDataProvider& data_provider) {
  std::string result(16u, '\0');
  for (char& c : result) {
    c = data_provider.ConsumeIntegralInRange<char>('a', 'z');
  }
  return result;
}

// Converts crash type string to crash type.
mojom::CrashEventInfo::CrashType GetCrashTypeFromString(base::StringPiece s) {
  if (s == "kernel") {
    return mojom::CrashEventInfo::CrashType::kKernel;
  } else if (s == "ec") {
    return mojom::CrashEventInfo::CrashType::kEmbeddedController;
  } else {
    return mojom::CrashEventInfo::CrashType::kUnknown;
  }
}

// Creates a valid log line.
void MakeValidLogLine(FuzzedDataProvider& data_provider,
                      base::Time creation_time,
                      uint64_t init_offset,
                      std::ostringstream& input,
                      std::vector<mojom::CrashEventInfoPtr>& expected) {
  base::Value::Dict log_line;
  // A random extra field.
  log_line.Set(ConsumeAlphabeticalString(data_provider),
               ConsumeAlphabeticalString(data_provider));
  const auto local_id = ConsumeAlphabeticalString(data_provider);
  log_line.Set("path_hash", local_id);
  const auto capture_time =
      base::Time::FromTimeT(data_provider.ConsumeIntegral<uint16_t>());
  log_line.Set("capture_time", base::NumberToString(capture_time.ToTimeT()));
  // upload_id would be ignored when is_uploaded=False.
  const auto crash_report_id = ConsumeAlphabeticalString(data_provider);
  log_line.Set("upload_id", crash_report_id);
  const auto crash_type = ConsumeAlphabeticalString(data_provider);
  log_line.Set("fatal_crash_type", crash_type);

  std::string log_line_str;
  CHECK(base::JSONWriter::Write(log_line, &log_line_str));
  input << log_line_str << "\n";
  expected.push_back(mojom::CrashEventInfo::New(
      /*crash_type=*/GetCrashTypeFromString(crash_type),
      /*local_id=*/local_id,
      /*capture_time=*/capture_time,
      /*upload_info=*/
      mojom::CrashUploadInfo::New(
          /*crash_report_id=*/crash_report_id,
          /*creation_time=*/creation_time,
          /*offset=*/init_offset + expected.size())));
}

void CheckParsedResult(const std::string& input,
                       const std::vector<mojom::CrashEventInfoPtr>& expected,
                       bool is_uploaded,
                       base::Time creation_time,
                       uint64_t init_offset,
                       uint64_t* parsed_bytes) {
  auto results = ParseUploadsLog(input, /*is_uploaded=*/is_uploaded,
                                 /*creation_time=*/creation_time,
                                 /*init_offset=*/init_offset,
                                 /*parsed_bytes=*/parsed_bytes);
  CHECK_GE(results.size(), expected.size());
  size_t results_found = 0;
  for (const auto& result : results) {
    if (results_found >= expected.size()) {
      break;
    }
    if (result.Equals(expected[results_found])) {
      ++results_found;
    }
  }
  CHECK_EQ(results_found, expected.size());
  // To accurately test parsed_bytes for a random string essentially requires
  // writing a substantial portion of the the parser. Hence, we only check that
  // parsed_bytes is in a normal range.
  if (parsed_bytes) {
    CHECK_LE(*parsed_bytes, input.size());
  }
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider data_provider(data, size);
  const uint8_t num_input =
      data_provider.ConsumeIntegralInRange<uint8_t>(0u, 16u);
  const auto creation_time =
      base::Time::FromTimeT(data_provider.ConsumeIntegral<uint16_t>());
  const uint64_t init_offset = data_provider.ConsumeIntegral<uint16_t>();

  std::ostringstream input;
  std::vector<mojom::CrashEventInfoPtr> expected;
  for (uint8_t i = 0; i < num_input; ++i) {
    if (data_provider.ConsumeBool()) {
      // Provide  a random number of valid lines so that we have some confidence
      // that the parser would still function normally after encountering a mix
      // of valid log lines and random strings. We make different valid lines
      // so we know that the parser won't be confused by random strings and
      // returning the parse result from the previous valid log lines.
      MakeValidLogLine(data_provider, creation_time, init_offset, input,
                       expected);
    } else {
      input << data_provider.ConsumeRandomLengthString() << "\n";
    }
  }

  uint64_t parsed_bytes;
  uint64_t* parsed_bytes_pointer = nullptr;
  if (data_provider.ConsumeBool()) {
    parsed_bytes_pointer = &parsed_bytes;
  }

  // Check whether parsed results include all parsed crash info in their
  // expected order, for both uploaded and unuploaded.
  CheckParsedResult(/*input=*/input.str(), /*expected=*/expected,
                    /*is_uploaded=*/true,
                    /*creation_time=*/creation_time,
                    /*init_offset=*/init_offset,
                    /*parsed_bytes=*/parsed_bytes_pointer);
  // Clear the field for expected now to prepare for checking unuploaded
  // crashes: Unuploaded crashes don't have the upload_info field.
  for (auto& item : expected) {
    item->upload_info = nullptr;
  }
  CheckParsedResult(/*input=*/input.str(), /*expected=*/expected,
                    /*is_uploaded=*/false,
                    /*creation_time=*/creation_time,
                    /*init_offset=*/init_offset,
                    /*parsed_bytes=*/parsed_bytes_pointer);
  return 0;
}
}  // namespace diagnostics
