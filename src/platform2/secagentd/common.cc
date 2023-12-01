// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secagentd/common.h"

#include <string>
#include <unistd.h>

#include "absl/strings/str_format.h"
#include "secagentd/bpf/bpf_types.h"
#include "secagentd/bpf_skeleton_wrappers.h"

namespace secagentd {

extern "C" int indirect_c_callback(void* ctx, void* data, size_t size) {
  if (ctx == nullptr || size < sizeof(bpf::cros_event)) {
    return -1;
  }
  auto* f = static_cast<BpfEventCb*>(ctx);
  f->Run(*static_cast<bpf::cros_event*>(data));
  return 0;
}

namespace Types {

absl::FormatConvertResult<absl::FormatConversionCharSet::kString>
AbslFormatConvert(const BpfSkeleton& type,
                  const absl::FormatConversionSpec&,
                  absl::FormatSink* output_sink) {
  static const absl::flat_hash_map<Types::BpfSkeleton, std::string>
      kTypeToString{{Types::BpfSkeleton::kProcess, "Process"}};
  auto i = kTypeToString.find(type);
  output_sink->Append(i != kTypeToString.end() ? i->second : "Unknown");
  return {.value = true};
}
}  // namespace Types

std::ostream& operator<<(std::ostream& out, const Types::BpfSkeleton& type) {
  out << absl::StreamFormat("%s", type);
  return out;
}

absl::FormatConvertResult<absl::FormatConversionCharSet::kString>
AbslFormatConvert(const Types::Plugin& type,
                  const absl::FormatConversionSpec&,
                  absl::FormatSink* sink) {
  static const absl::flat_hash_map<Types::Plugin, std::string> kTypeToString{
      {Types::Plugin::kProcess, "Process"}, {Types::Plugin::kAgent, "Agent"}};

  auto i = kTypeToString.find(type);
  sink->Append(i != kTypeToString.end() ? i->second : "Unknown");
  return {.value = true};
}

std::ostream& operator<<(std::ostream& out, const Types::Plugin& type) {
  out << absl::StreamFormat("%s", type);
  return out;
}
}  // namespace secagentd
