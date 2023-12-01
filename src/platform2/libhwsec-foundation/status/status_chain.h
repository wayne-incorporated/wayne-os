// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_STATUS_STATUS_CHAIN_H_
#define LIBHWSEC_FOUNDATION_STATUS_STATUS_CHAIN_H_

#include <iostream>
#include <string>
#include <type_traits>
#include <utility>

// error.h is the finalized header, do not include any other impl headers
// directly.
#include "libhwsec-foundation/status/impl/error.h"

namespace hwsec_foundation {
namespace status {

// Trait check for being a |StatusChain| holding type.
namespace _impl_ {

template <typename T>
std::false_type __is_status_chain(const T&);

// |StackableError| is aliased as |StatusChain| bellow.
template <typename _Et>
std::true_type __is_status_chain(const StackableError<_Et>&);

}  // namespace _impl_

// Alias the traits to be publicly visible.
template <typename T>
using is_status_chain = decltype(_impl_::__is_status_chain(std::declval<T>()));
template <typename T>
constexpr inline bool is_status_chain_v = is_status_chain<T>::value;
template <typename _Et>
using has_make_status_trait = _impl_::has_make_status_trait<_Et>;
template <typename _Et>
inline constexpr bool has_make_status_trait_v =
    _impl_::has_make_status_trait_v<_Et>;
template <typename _Et>
using has_base_error_type = _impl_::has_base_error_type<_Et>;
template <typename _Et>
inline constexpr bool has_base_error_type_v =
    _impl_::has_base_error_type_v<_Et>;

// Declare base |Error| type
using Error = _impl_::Error;

// |StackableError| is the canonical Status holder for use in hwsec. Alias it
// to a Status resambling name.
template <typename _Et>
using StatusChain = _impl_::StackableError<_Et>;

// Make a usable discard tag.
constexpr _impl_::WrapTransformOnly WrapTransformOnly;

// Factory function for |StatusChain| which by-passes the trait overload for
// creating a status. While it is not enforceable, this function should ONLY be
// used from inside |MakeStatusTrait| customization.
template <typename _Et, typename... Args>
[[clang::return_typestate(unconsumed)]] StatusChain<_Et> NewStatus(
    Args&&... args) {
  static_assert(std::is_base_of_v<Error, _Et> || std::is_same_v<Error, _Et>,
                "Supplied type is not derived from |Error|.");
  return StatusChain<_Et>(new _Et(std::forward<Args>(args)...));
}

// Return |nullptr| error object in a typed |StatusChain| container.
template <typename _Et>
[[clang::return_typestate(consumed)]] StatusChain<_Et> OkStatus() {
  static_assert(std::is_base_of_v<Error, _Et> || std::is_same_v<Error, _Et>,
                "Supplied type is not derived from |Error|.");
  return StatusChain<_Et>();
}

// Return |nullptr| error object in a typed |const StatusChain| container.
template <typename _Et>
[[clang::return_typestate(consumed)]] const StatusChain<_Et>&
ConstRefOkStatus() {
  // thread_local variable instances are initialized much like static
  // variables, except that they must be initialized separately for each
  // thread, rather than once at program startup. This means that
  // thread_local variables declared within a function are safe.

  // thread_local variable instances are not destroyed before their thread
  // terminates, so they do not have the destruction-order issues of static
  // variables.
  const thread_local StatusChain<_Et> kOkStatus = OkStatus<_Et>();
  return kOkStatus;
}

// Indicates the MakeStatusTrait will always make not ok status.
struct AlwaysNotOk {};

// Specifies default behaviour of the MakeStatus on the object. Default is to
// pass the arguments to the constructor of |_Et|.
template <typename _Et>
struct DefaultMakeStatus : public AlwaysNotOk {
  template <typename... Args>
  [[clang::return_typestate(unconsumed)]] auto operator()(Args&&... args) {
    return StatusChain<_Et>(new _Et(std::forward<Args>(args)...));
  }
};

// Forbids MakeStatus on the object.
struct ForbidMakeStatus {};

// Creates a new error object, wrapped in |StatusChain|. Custom overloads for
// error types may return a different object type, that might need to be dealt
// with in a certain way to get an object convertible to status type.
template <typename _Et,
          typename... Args,
          typename MakeStatusTrait = typename _Et::MakeStatusTrait,
          typename _Rt = decltype(MakeStatusTrait()(
              std::forward<Args>(std::declval<Args&&>())...)),
          std::enable_if_t<
              std::is_base_of_v<AlwaysNotOk, typename _Et::MakeStatusTrait> &&
                  is_status_chain_v<_Rt>,
              int> = 0>
[[clang::return_typestate(unconsumed)]] auto MakeStatus(Args&&... args) {
  static_assert(std::is_base_of_v<Error, _Et> || std::is_same_v<Error, _Et>,
                "Supplied type is not derived from |Error|.");
  return MakeStatusTrait()(std::forward<Args>(args)...);
}

// It the MakeStatusTrait is not derived from the AlwaysNotOk, we should check
// the result of it before using it.
template <typename _Et,
          typename... Args,
          typename MakeStatusTrait = typename _Et::MakeStatusTrait,
          typename _Rt = decltype(MakeStatusTrait()(
              std::forward<Args>(std::declval<Args&&>())...)),
          std::enable_if_t<
              !(std::is_base_of_v<AlwaysNotOk, typename _Et::MakeStatusTrait> &&
                is_status_chain_v<_Rt>),
              int> = 0>
auto MakeStatus(Args&&... args) {
  static_assert(std::is_base_of_v<Error, _Et> || std::is_same_v<Error, _Et>,
                "Supplied type is not derived from |Error|.");
  return MakeStatusTrait()(std::forward<Args>(args)...);
}

}  // namespace status
}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_STATUS_STATUS_CHAIN_H_
