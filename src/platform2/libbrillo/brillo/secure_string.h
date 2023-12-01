// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_SECURE_STRING_H_
#define LIBBRILLO_BRILLO_SECURE_STRING_H_

#include <cstddef>
#include <iterator>
#include <memory>
#include <type_traits>

#include <base/check.h>
#include <brillo/asan.h>
#include <brillo/brillo_export.h>

namespace brillo {

// An implementation of the proposed "secure_clear" standard:
// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p1315r5.html.
//
// This function is guaranteed to fill in the whole buffer
// and is not subject to compiler optimization as allowed by Sub-clause 5.1.2.3
// of C Standard [ISO/IEC 9899:2011] which states:
// In the abstract machine, all expressions are evaluated as specified by the
// semantics. An actual implementation need not evaluate part of an expression
// if it can deduce that its value is not used and that no needed side effects
// are produced (including any caused by calling a function or accessing
// a volatile object).
// While memset() can be optimized out in certain situations (since most
// compilers implement this function as intrinsic and know of its side effects),
// this function will not be optimized out.
//
// SecureClearBytes is used to write beyond the size() in several functions.
// Since this is intentional, disable address sanitizer from analyzing it.
BRILLO_EXPORT BRILLO_DISABLE_ASAN void SecureClearBytes(void* v, size_t n);

// Variant of SecureClearBytes that works with contiguous containers (vector,
// array, etc.), strings, and c-style arrays.
template <typename C>
BRILLO_EXPORT void SecureClearContainer(C& v) {  // NOLINT(runtime/references)
  using T = std::remove_reference_t<decltype(*std::data(v))>;
  static_assert(std::is_trivially_destructible_v<T>,
                "Element type of the container must be trivially destructible");
  SecureClearBytes(std::data(v), std::size(v) * sizeof(T));
}

// Variant of SecureClearBytes that works with generic (trivially destructible)
// objects, including scalar objects such as "int", "int*", etc.
template <typename T>
BRILLO_EXPORT void SecureClearObject(T& v) {  // NOLINT(runtime/references)
  static_assert(!std::is_pointer_v<T>,
                "Pass the object to be cleared, not a pointer");
  static_assert(!std::is_array_v<T>, "Use SecureClearContainer for arrays");
  static_assert(std::is_trivially_destructible_v<T>,
                "Object must be trivially destructible");
  SecureClearBytes(std::addressof(v), sizeof(v));
}

// Compare [n] bytes starting at [s1] with [s2] and return 0 if they match,
// 1 if they don't. Time taken to perform the comparison is only dependent on
// [n] and not on the relationship of the match between [s1] and [s2].
// When n == 0, returns 0 (same as memcmp).
BRILLO_EXPORT int SecureMemcmp(const void* s1, const void* s2, size_t n);

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_SECURE_STRING_H_
