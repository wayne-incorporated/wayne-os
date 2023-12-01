// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_COMMON_H_
#define SECAGENTD_COMMON_H_

#include <unistd.h>
#include "absl/strings/str_format.h"

namespace secagentd {
// Used by BPF skeleton wrappers to help call a C++ class method from a C style
// callback. The void* ctx shall always point to a
// RepeatingCallback<void(const bpf::event&)>. void* data is cast into a
// bpf::event and then passed into this RepeatingCallback.
extern "C" int indirect_c_callback(void* ctx, void* data, size_t size);

namespace Types {
enum class BpfSkeleton { kProcess, kNetwork };
enum class Plugin { kAgent, kNetwork, kProcess };

absl::FormatConvertResult<absl::FormatConversionCharSet::kString>
AbslFormatConvert(const BpfSkeleton& type,
                  const absl::FormatConversionSpec&,
                  absl::FormatSink* output_sink);

absl::FormatConvertResult<absl::FormatConversionCharSet::kString>
AbslFormatConvert(const Types::Plugin& type,
                  const absl::FormatConversionSpec&,
                  absl::FormatSink* sink);

}  // namespace Types

std::ostream& operator<<(std::ostream& out, const Types::Plugin& type);
std::ostream& operator<<(std::ostream& out, const Types::BpfSkeleton& type);
}  // namespace secagentd

#endif  // SECAGENTD_COMMON_H_
