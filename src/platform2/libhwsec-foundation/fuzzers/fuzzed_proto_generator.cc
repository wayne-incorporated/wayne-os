// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/fuzzers/fuzzed_proto_generator.h"

#include <stdint.h>

#include <string>
#include <utility>
#include <vector>

#include <base/notreached.h>
#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/unknown_field_set.h>
#include <google/protobuf/wire_format.h>

using brillo::Blob;
using brillo::BlobFromString;
using brillo::BlobToString;

namespace {

// Threshold on generating nested protobuf messages.
constexpr int kMaxNestingDepth = 100;
// Generated protobuf field numbers are capped at this maximum.
constexpr int kMaxFieldNumber = 1000;

Blob SerializeProtobufUnknownFieldSet(
    const google::protobuf::UnknownFieldSet& field_set) {
  std::string serialized;
  field_set.SerializeToString(&serialized);
  return BlobFromString(serialized);
}

}  // namespace

namespace hwsec_foundation {

FuzzedProtoGenerator::FuzzedProtoGenerator(FuzzedDataProvider& provider)
    : provider_(provider) {}

FuzzedProtoGenerator::FuzzedProtoGenerator(
    std::vector<brillo::Blob> byte_breadcrumbs, FuzzedDataProvider& provider)
    : provider_(provider), byte_breadcrumbs_(std::move(byte_breadcrumbs)) {}

FuzzedProtoGenerator::~FuzzedProtoGenerator() = default;

Blob FuzzedProtoGenerator::Generate() {
  return GenerateMessageOrBlob(/*nesting_depth=*/0);
}

Blob FuzzedProtoGenerator::GenerateMessageOrBlob(int nesting_depth) {
  // Choose among a few ways to generate the result.
  switch (provider_.ConsumeIntegralInRange<int>(0, 2)) {
    case 0: {
      // Construct a valid message with (zero or more) recursively generated
      // fields.
      google::protobuf::UnknownFieldSet field_set;
      if (nesting_depth < kMaxNestingDepth) {
        while (GenerateAndAddField(nesting_depth + 1, field_set)) {
        }
      }
      return SerializeProtobufUnknownFieldSet(field_set);
    }
    case 1: {
      // Construct a "random" blob by taking it from Libfuzzer-supplied data.
      return BlobFromString(provider_.ConsumeRandomLengthString());
    }
    case 2: {
      // Take a breadcrumb (if there's one).
      if (byte_breadcrumbs_.empty())
        return Blob();
      const int selected_index = provider_.ConsumeIntegralInRange<int>(
          0, byte_breadcrumbs_.size() - 1);
      return byte_breadcrumbs_[selected_index];
    }
  }
  NOTREACHED();
  return Blob();
}

bool FuzzedProtoGenerator::GenerateAndAddField(
    int nesting_depth, google::protobuf::UnknownFieldSet& field_set) {
  // Generate the protobuf field number. Note that we're allowing using a number
  // multiple times, because that's how repeated fields are represented on the
  // wire.
  int field_number = provider_.ConsumeIntegralInRange<int>(0, kMaxFieldNumber);
  if (field_number == 0) {
    // Zero is a sentinel used to stop adding more fields to the current field
    // set.
    return false;
  }
  // Choose among a few ways to generate the resulting payload. Note: we don't
  // add SGROUP/EGROUP, which were only used in a deprecated protobuf feature.
  switch (provider_.ConsumeIntegralInRange<int>(0, 3)) {
    case 0: {
      // Add a payload of the VARINT wire type (it corresponds to: int32, int64,
      // uint32, uint64, sint32, sint64, bool, enum).
      field_set.AddVarint(field_number, provider_.ConsumeIntegral<uint64_t>());
      return true;
    }
    case 1: {
      // Add a payload of the I32 wire type (it corresponds to: fixed32,
      // sfixed32, float).
      field_set.AddFixed32(field_number, provider_.ConsumeIntegral<uint32_t>());
      return true;
    }
    case 2: {
      // Add a payload of the I64 wire type (it corresponds to: fixed64,
      // sfixed64, double).
      field_set.AddFixed64(field_number, provider_.ConsumeIntegral<uint64_t>());
      return true;
    }
    case 3: {
      // Add a payload of the LEN wire type (it corresponds to: string, bytes,
      // embedded messages, packed repeated fields). The value is generated
      // recursively.
      field_set.AddLengthDelimited(
          field_number, BlobToString(GenerateMessageOrBlob(nesting_depth)));
      return true;
    }
  }
  NOTREACHED();
  return false;
}

}  // namespace hwsec_foundation
