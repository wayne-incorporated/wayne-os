// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_UTILITY_NO_DEFAULT_INIT_H_
#define LIBHWSEC_FOUNDATION_UTILITY_NO_DEFAULT_INIT_H_

#include <type_traits>
#include <utility>

// Helper type to create variable of an arbitrary type which does not allow for
// default construction. This is most useful in contexts like structs where you
// want force specific fields to be explicitly initialized.
//
// Example usage:
//
//   struct StructName {
//     NoDefault<int> val;
//     NoDefault<std::string> str;
//   };
//
// This would prevent the following code from compiling:
//
//   StructName{};
//   StructName{.val = 123};
//   StructName{.str = "456"};
//
// But this code still works:
//
//   StructName{.val = 123, .str = "456"};
//
// The helper is trying to become a drop-in replacement for the original type,
// but it would not work if the original type is a "final" object or union.
// If some operations(e.g. std::move, or implicit casting) don't work, you can
// try to static_cast the helper to the reference of the original type.

namespace hwsec_foundation {

template <typename T, typename = void>
class NoDefault : public T {
 public:
  using T::T;
  using T::operator=;

  constexpr NoDefault(T&& t) : T(std::move(t)) {}  // NOLINT(runtime/explicit)
  constexpr NoDefault(const T& t) : T(t) {}        // NOLINT(runtime/explicit)
  NoDefault() = delete;

  ~NoDefault() = default;
};

template <typename T>
class NoDefault<T, std::enable_if_t<std::is_scalar_v<T>>> {
 public:
  constexpr NoDefault(T v) : value_(v) {}  // NOLINT(runtime/explicit)
  NoDefault() = delete;

  ~NoDefault() = default;

  constexpr operator T() const { return value_; }
  constexpr operator T&() { return value_; }

  template <int&... ExplicitArgumentBarrier,
            typename U = T,
            typename = std::void_t<decltype(*std::declval<U>())>>
  constexpr auto& operator*() const {
    return *value_;
  }

  template <int&... ExplicitArgumentBarrier,
            typename U = T,
            typename = std::void_t<decltype(*std::declval<U>())>>
  constexpr T operator->() const {
    return value_;
  }

 private:
  T value_;
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_UTILITY_NO_DEFAULT_INIT_H_
