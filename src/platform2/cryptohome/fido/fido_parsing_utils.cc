// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fido/fido_parsing_utils.h"

#include <string>

#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/stringprintf.h"

#include <base/check.h>

namespace cryptohome {
namespace fido_device {
namespace fido_parsing_utils {

namespace {

constexpr bool AreSpansDisjoint(base::span<const uint8_t> lhs,
                                base::span<const uint8_t> rhs) {
  return lhs.data() + lhs.size() <= rhs.data() ||  // [lhs)...[rhs)
         rhs.data() + rhs.size() <= lhs.data();    // [rhs)...[lhs)
}

}  // namespace

std::vector<uint8_t> Materialize(base::span<const uint8_t> span) {
  return std::vector<uint8_t>(span.begin(), span.end());
}

void Append(std::vector<uint8_t>* target, base::span<const uint8_t> in_values) {
  CHECK(AreSpansDisjoint(*target, in_values));
  target->insert(target->end(), in_values.begin(), in_values.end());
}

std::vector<uint8_t> Extract(base::span<const uint8_t> span,
                             size_t pos,
                             size_t length) {
  return Materialize(ExtractSpan(span, pos, length));
}

base::span<const uint8_t> ExtractSpan(base::span<const uint8_t> span,
                                      size_t pos,
                                      size_t length) {
  if (!(pos <= span.size() && length <= span.size() - pos))
    return base::span<const uint8_t>();
  return span.subspan(pos, length);
}

}  // namespace fido_parsing_utils
}  // namespace fido_device
}  // namespace cryptohome
