// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Alternative implementation of NoDefault (see no_default_init.h) that provides
// slightly different semantics. Like the other type, it disables the default
// constructor in order to force to you explicitly initialize the value while
// supporting all other constructors of the underlying type.
//
// However, unlike NoDefault this type does not attempt to be automatically
// convertible to the underlying type and instead provides pointer-like
// semantics requiring an explicit dereference. This makes it similar to the
// API of std::optional, minus the "might not contain a value" part.
//
// The main advantage of using this implementation is that it can work with any
// type, including final types which cannot be subclassed. It also provides a
// more consistent API that always works the same way, whereas with NoDefault if
// implicit conversion fails you have to do explicit conversion, which is more
// awkward than a dereference. The main disadvantage is that you always have to
// use a dereference to access the underlying value.

#ifndef LIBHWSEC_FOUNDATION_UTILITY_EXPLICIT_INIT_H_
#define LIBHWSEC_FOUNDATION_UTILITY_EXPLICIT_INIT_H_

#include <type_traits>
#include <utility>

namespace hwsec_foundation {

template <typename T>
class ExplicitInit final {
 public:
  ExplicitInit() = delete;

  // Define conversion constructors that can construct the underlying type T
  // from any other type T can be constructed from. We need a bit of SFINAE
  // complexity here to ensure that implicit conversions remain implicit and
  // explicit remain explicit.
  template <typename U,
            std::enable_if_t<std::is_convertible_v<U, T>, bool> = true>
  constexpr ExplicitInit(U&& u)  // NOLINT(runtime/explicit)
      : value_(std::forward<U>(u)) {}
  template <typename U,
            std::enable_if_t<!std::is_convertible_v<U, T>, bool> = true>
  constexpr explicit ExplicitInit(U&& u) : value_(std::forward<U>(u)) {}

  // Define a generic forwarding constructor that works with any multi-argument
  // T constructors. This uses perfect forwarding like the other single-arg
  // constructors but it's not important for us to emulate "explicit".
  template <typename First, typename Second, typename... Rest>
  constexpr ExplicitInit(First&& first, Second&& second, Rest&&... rest)
      : value_(std::forward<First>(first),
               std::forward<Second>(second),
               std::forward<Rest>(rest)...) {}

  constexpr ExplicitInit(const ExplicitInit&) = default;
  constexpr ExplicitInit(ExplicitInit&&) = default;
  constexpr ExplicitInit& operator=(const ExplicitInit&) = default;
  constexpr ExplicitInit& operator=(ExplicitInit&&) = default;

  constexpr const T& operator*() const { return value_; }
  constexpr T& operator*() { return value_; }

  constexpr const T* operator->() const { return &value_; }
  constexpr T* operator->() { return &value_; }

  constexpr T& value() { return value_; }
  constexpr const T& value() const { return value_; }

 private:
  T value_;
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_UTILITY_EXPLICIT_INIT_H_
