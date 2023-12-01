// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_TYPE_TRAITS_H_
#define HERMES_TYPE_TRAITS_H_

#include <type_traits>
#include <vector>

namespace hermes_internal {

template <typename... Ts>
struct make_void {
  typedef void type;
};
template <typename... Ts>
using void_t = typename make_void<Ts...>::type;

template <typename T>
struct is_array : std::false_type {};

template <typename T, std::size_t N>
struct is_array<std::array<T, N>> : std::true_type {};

template <typename T>
struct is_vector : std::false_type {};

template <typename T, typename Allocator>
struct is_vector<std::vector<T, Allocator>> : std::true_type {};

template <typename, typename = void>
struct is_iterator : std::false_type {};

template <typename T>
struct is_iterator<T,
                   void_t<typename std::iterator_traits<T>::iterator_category>>
    : std::true_type {};

}  // namespace hermes_internal

namespace hermes {

template <typename E>
constexpr auto to_underlying(E e) noexcept {
  return static_cast<std::underlying_type_t<E>>(e);
}

template <typename T, typename ReturnType>
using EnableIfArrayOrVector_t =
    std::enable_if_t<hermes_internal::is_vector<T>::value ||
                         hermes_internal::is_array<T>::value,
                     ReturnType>;

template <typename T, typename ReturnType>
using EnableIfIterator_t =
    std::enable_if_t<hermes_internal::is_iterator<T>::value, ReturnType>;

}  // namespace hermes

#endif  // HERMES_TYPE_TRAITS_H_
