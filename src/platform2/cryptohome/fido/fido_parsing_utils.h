// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FIDO_FIDO_PARSING_UTILS_H_
#define CRYPTOHOME_FIDO_FIDO_PARSING_UTILS_H_

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "base/containers/span.h"

namespace cryptohome {
namespace fido_device {
namespace fido_parsing_utils {

// Returns a materialized copy of |span|, that is, a vector with the same
// elements.
std::vector<uint8_t> Materialize(base::span<const uint8_t> span);

// Returns a materialized copy of the static |span|, that is, an array with the
// same elements.
template <size_t N>
std::array<uint8_t, N> Materialize(base::span<const uint8_t, N> span) {
  std::array<uint8_t, N> array;
  std::copy(span.begin(), span.end(), array.begin());
  return array;
}

// Appends |in_values| to the end of |target|. The underlying container for
// |in_values| should *not* be |target|.
void Append(std::vector<uint8_t>* target, base::span<const uint8_t> in_values);

// Safely extracts, with bound checking, a contiguous subsequence of |span| of
// the given |length| and starting at |pos|. Returns an empty vector/span if the
// requested range is out-of-bound.
std::vector<uint8_t> Extract(base::span<const uint8_t> span,
                             size_t pos,
                             size_t length);
base::span<const uint8_t> ExtractSpan(base::span<const uint8_t> span,
                                      size_t pos,
                                      size_t length);

}  // namespace fido_parsing_utils
}  // namespace fido_device
}  // namespace cryptohome

#endif  // CRYPTOHOME_FIDO_FIDO_PARSING_UTILS_H_
