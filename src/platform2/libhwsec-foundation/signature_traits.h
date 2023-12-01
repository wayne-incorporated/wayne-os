// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_SIGNATURE_TRAITS_H_
#define LIBHWSEC_FOUNDATION_SIGNATURE_TRAITS_H_

#include <functional>
#include <tuple>
#include <type_traits>

#include <base/functional/callback.h>

namespace hwsec_foundation {

template <class Signature>
struct signature_trait;

template <class ReturnType, class... Args>
struct signature_trait<ReturnType(Args...)> {
  using type = std::tuple<ReturnType, Args...>;
};

template <class ReturnType, class... Args>
struct signature_trait<ReturnType (*)(Args...)> {
  using type = std::tuple<ReturnType, Args...>;
};

template <class ReturnType, class C, class... Args>
struct signature_trait<ReturnType (C::*)(Args...)> {
  using type = std::tuple<ReturnType, Args...>;
};

template <class ReturnType, class... Args>
struct signature_trait<std::function<ReturnType(Args...)>> {
  using type = std::tuple<ReturnType, Args...>;
};
template <class ReturnType, class... Args>
struct signature_trait<base::RepeatingCallback<ReturnType(Args...)>> {
  using type = std::tuple<ReturnType, Args...>;
};
template <class ReturnType, class... Args>
struct signature_trait<base::OnceCallback<ReturnType(Args...)>> {
  using type = std::tuple<ReturnType, Args...>;
};

template <class Signature>
using signature_trait_t = typename signature_trait<Signature>::type;

template <class Signature1, class Signature2>
using is_same_signature =
    std::is_same<signature_trait_t<Signature1>, signature_trait_t<Signature2>>;

template <class Signature1, class Signature2>
constexpr bool is_same_signature_v =
    is_same_signature<Signature1, Signature2>::value;

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_SIGNATURE_TRAITS_H_
