// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <brillo/http/http_form_data.h>
#include <brillo/streams/memory_stream.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace {
constexpr int kRandomDataMaxLength = 64;
constexpr int kMaxRecursionDepth = 256;

std::unique_ptr<brillo::http::TextFormField> CreateTextFormField(
    FuzzedDataProvider* data_provider) {
  return std::make_unique<brillo::http::TextFormField>(
      data_provider->ConsumeRandomLengthString(kRandomDataMaxLength),
      data_provider->ConsumeRandomLengthString(kRandomDataMaxLength),
      data_provider->ConsumeRandomLengthString(kRandomDataMaxLength),
      data_provider->ConsumeRandomLengthString(kRandomDataMaxLength));
}

std::unique_ptr<brillo::http::FileFormField> CreateFileFormField(
    FuzzedDataProvider* data_provider) {
  brillo::StreamPtr mem_stream = brillo::MemoryStream::OpenCopyOf(
      data_provider->ConsumeRandomLengthString(kRandomDataMaxLength), nullptr);
  return std::make_unique<brillo::http::FileFormField>(
      data_provider->ConsumeRandomLengthString(kRandomDataMaxLength),
      std::move(mem_stream),
      data_provider->ConsumeRandomLengthString(kRandomDataMaxLength),
      data_provider->ConsumeRandomLengthString(kRandomDataMaxLength),
      data_provider->ConsumeRandomLengthString(kRandomDataMaxLength),
      data_provider->ConsumeRandomLengthString(kRandomDataMaxLength));
}

std::unique_ptr<brillo::http::MultiPartFormField> CreateMultipartFormField(
    FuzzedDataProvider* data_provider, int depth) {
  std::unique_ptr<brillo::http::MultiPartFormField> multipart_field =
      std::make_unique<brillo::http::MultiPartFormField>(
          data_provider->ConsumeRandomLengthString(kRandomDataMaxLength),
          data_provider->ConsumeRandomLengthString(kRandomDataMaxLength),
          data_provider->ConsumeRandomLengthString(kRandomDataMaxLength));

  // Randomly add fields to this like we do the base FormData, but don't loop
  // forever.
  while (data_provider->ConsumeBool()) {
    if (data_provider->ConsumeBool()) {
      // Add a random text field to the form.
      multipart_field->AddCustomField(CreateTextFormField(data_provider));
    }
    if (data_provider->ConsumeBool()) {
      // Add a random file field to the form.
      multipart_field->AddCustomField(CreateFileFormField(data_provider));
    }
    // Limit our recursion depth. We could make this part of our code iterative,
    // but that won't help because in libbrillo we use recursion to generate the
    // stream so we would hit a stack depth limit there as well.
    if (depth < kMaxRecursionDepth && data_provider->ConsumeBool()) {
      // Add a random multipart form field to the form.
      multipart_field->AddCustomField(
          CreateMultipartFormField(data_provider, depth + 1));
    }
  }

  return multipart_field;
}

}  // namespace

bool IgnoreLogging(int, const char*, int, size_t, const std::string&) {
  return true;
}

class Environment {
 public:
  Environment() {
    // Disable logging. Normally this would be done with logging::SetMinLogLevel
    // but that doesn't work for brillo::Error for because it's not using the
    // LOG(ERROR) macro which is where the actual log level check occurs.
    logging::SetLogMessageHandler(&IgnoreLogging);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);
  // Randomly add a bunch of fields to the FormData and then when done extract
  // and consume the data stream.
  brillo::http::FormData form_data(
      data_provider.ConsumeRandomLengthString(kRandomDataMaxLength));
  while (data_provider.remaining_bytes() > 0) {
    if (data_provider.ConsumeBool()) {
      // Add a random text field to the form.
      form_data.AddCustomField(CreateTextFormField(&data_provider));
    }
    if (data_provider.ConsumeBool()) {
      // Add a random file field to the form.
      form_data.AddCustomField(CreateFileFormField(&data_provider));
    }
    if (data_provider.ConsumeBool()) {
      // Add a random multipart form field to the form.
      form_data.AddCustomField(CreateMultipartFormField(&data_provider, 0));
    }
  }

  brillo::StreamPtr form_stream = form_data.ExtractDataStream();
  if (!form_stream)
    return 0;

  // We need to use a decent sized buffer and call ReadAllBlocking to avoid
  // excess overhead with reading here that can make the fuzzer timeout.
  uint8_t buffer[32768];
  while (form_stream->GetRemainingSize() > 0) {
    if (!form_stream->ReadAllBlocking(buffer, sizeof(buffer), nullptr)) {
      // If there's an error reading from the stream, then bail since we'd
      // likely just see repeated errors and never exit.
      break;
    }
  }

  return 0;
}
