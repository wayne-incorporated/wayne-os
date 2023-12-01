// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_APPLY_IMPL_H_
#define VM_TOOLS_CONCIERGE_APPLY_IMPL_H_

#include <utility>

namespace vm_tools {
namespace internal {

template <typename U, typename... Ts, class Tuple, std::size_t... I>
U ApplyImpl(base::OnceCallback<U(Ts...)> f,
            Tuple&& t,
            std::index_sequence<I...>) {
  return std::move(f).Run(std::move(std::get<I>(std::forward<Tuple>(t)))...);
}

template <typename U, typename... Ts, class Tuple>
U Apply(base::OnceCallback<U(Ts...)> f, Tuple&& t) {
  return ApplyImpl(std::move(f), std::forward<Tuple>(t),
                   std::make_index_sequence<sizeof...(Ts)>{});
}

template <typename U, typename T>
U Apply(base::OnceCallback<U(T)> f, T&& val) {
  return std::move(f).Run(std::forward<T>(val));
}

}  // namespace internal
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_APPLY_IMPL_H_
