// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_STATUS_STATUS_CHAIN_OR_H_
#define LIBHWSEC_FOUNDATION_STATUS_STATUS_CHAIN_OR_H_

#include <initializer_list>
#include <memory>
#include <type_traits>
#include <utility>
#include <variant>

#include "libhwsec-foundation/status/status_chain.h"

// Convenience class to represent value or non-ok status.

namespace hwsec_foundation {
namespace status {

// The consumable state meaning:
// * consumed => The StatusChainOr contains value.
// * unconsumed => The StatusChainOr contains error.
// * unknown => The StatusChainOr needs to be checked before using it.
//
// The purpose of consumable attribute is to achieve these checks.
// * go/clang-tidy/checks/google3-runtime-statusor-ok-status.md
// * go/clang-tidy/checks/google3-runtime-unchecked-statusor-access.md
//
template <typename _Vt, typename _Et>
class [[clang::consumable(unknown)]]   //
[[clang::consumable_auto_cast_state]]  //
[[nodiscard]] StatusChainOr {
 public:
  using value_type = _Vt;
  using status_type = StatusChain<_Et>;
  using container_type = std::variant<value_type, status_type>;

  // We don't want default constructor.
  StatusChainOr() = delete;

  // We don't want copy constructor.
  StatusChainOr(const StatusChainOr&) = delete;

  // Accept the move constructor.
  StatusChainOr(StatusChainOr&& status_or)
      : value_(std::move(status_or.value_)) {}

  // Implicit conversion to StatusChainOr to allow transparent "return"s.
  template <typename _Ut,
            typename =
                std::enable_if_t<std::is_constructible_v<value_type, _Ut>>>
  [[clang::return_typestate(consumed)]] StatusChainOr(
      _Ut && v)  // NOLINT(runtime/explicit)
      : value_(container_type{std::in_place_type<value_type>,
                              std::forward<_Ut>(v)}) {}

  // Constructs the inner value in-place using the provided args, using the
  // `value_type(args...)` constructor.
  template <typename... Args,
            typename =
                std::enable_if_t<std::is_constructible_v<value_type, Args...>>>
  [[clang::return_typestate(consumed)]] StatusChainOr(
      std::in_place_t, Args && ... args)  // NOLINT(runtime/explicit)
      : value_(container_type{std::in_place_type<value_type>,
                              std::forward<Args>(args)...}) {}

  // Constructs the inner value in-place using the provided args, using the
  // `value_type(args...)` constructor.
  template <typename _Ut, typename... Args,
            typename = std::enable_if_t<std::is_constructible_v<
                value_type, std::initializer_list<_Ut>, Args...>>>
  [[clang::return_typestate(consumed)]] StatusChainOr(
      std::in_place_t, std::initializer_list<_Ut> ilist,
      Args && ... args)  // NOLINT(runtime/explicit)
      : value_(container_type{std::in_place_type<value_type>, ilist,
                              std::forward<Args>(args)...}) {}

  template <int&... ExplicitArgumentBarrier, typename _Ut,
            typename = std::enable_if_t<
                std::is_convertible_v<_Ut*,
                                      typename StatusChain<_Et>::pointer>>>
  [[clang::return_typestate(unconsumed)]] static StatusChainOr
  MakeFromStatusChain(
      StatusChain<_Ut> && other               //
      [[clang::param_typestate(unconsumed)]]  //
      [[clang::return_typestate(consumed)]])  // NOLINT(runtime/explicit)
  {
    return StatusChainOr(std::move(other), StatusChainCtorTag{});
  }

  // We don't want copy operator.
  StatusChainOr& operator=(const StatusChainOr&) = delete;

  StatusChainOr& operator=(StatusChainOr&& status_or) noexcept {
    value_ = std::move(status_or.value_);
    return *this;
  }

  [[clang::callable_when("consumed")]] value_type* operator->() noexcept {
    CHECK(ok()) << " Arrow operator on a non-OK StatusChainOr is not allowed";
    return std::get_if<value_type>(&value_);
  }

  [[clang::callable_when("consumed")]] constexpr const value_type& operator*()
      const& {
    CHECK(ok()) << " Dereferencing a non-OK StatusChainOr is not allowed";
    return *std::get_if<value_type>(&value_);
  }

  [[clang::callable_when("consumed")]] value_type& operator*()& {
    CHECK(ok()) << " Dereferencing a non-OK StatusChainOr is not allowed";
    return *std::get_if<value_type>(&value_);
  }

  [[clang::callable_when("consumed")]] value_type&& operator*()&& {
    CHECK(ok()) << " Dereferencing a non-OK StatusChainOr is not allowed";
    return std::move(*std::get_if<value_type>(&value_));
  }

  [[clang::callable_when("consumed")]] constexpr const value_type& value()
      const& noexcept {
    CHECK(ok()) << " Get the value of a non-OK StatusChainOr is not allowed";
    return *std::get_if<value_type>(&value_);
  }

  [[clang::callable_when("consumed")]] value_type& value()& noexcept {
    CHECK(ok()) << " Get the value of a non-OK StatusChainOr is not allowed";
    return *std::get_if<value_type>(&value_);
  }

  [[clang::callable_when("consumed")]] value_type&& value()&& noexcept {
    CHECK(ok()) << " Get the value of a non-OK StatusChainOr is not allowed";
    return std::move(*std::get_if<value_type>(&value_));
  }

  template <typename U>
  value_type value_or(U && default_value) const& noexcept {
    if (ok()) {
      return *std::get_if<value_type>(&value_);
    }
    return std::forward<U>(default_value);
  }

  template <typename U>
  value_type value_or(U && default_value)&& noexcept {
    if (ok()) {
      return std::move(*std::get_if<value_type>(&value_));
    }
    return std::forward<U>(default_value);
  }

  [[clang::test_typestate(consumed)]] bool ok() const noexcept {
    return std::holds_alternative<value_type>(value_);
  }

  constexpr const status_type& status() const& noexcept {
    if (ok()) {
      return ConstRefOkStatus<_Et>();
    }
    return *std::get_if<status_type>(&value_);
  }

  status_type status() && noexcept {
    if (ok()) {
      return OkStatus<_Et>();
    }
    return std::move(*std::get_if<status_type>(&value_));
  }

  // The Assert* API would be useful to ensure the consumable state of
  // StatusChainOr. This is a workaround for CHECK/DCHECK/ASSERT macros that
  // doesn't work with the consumable attribute.
  // For more information: crbug/1336752#c12, b/223361459
  [[clang::set_typestate(consumed)]]               //
  [[clang::return_typestate(consumed)]]            //
  [[clang::callable_when("consumed", "unknown")]]  //
  StatusChainOr
  AssertOk()&& {
    CHECK(ok()) << "The status should be ok.";
    return std::move(*this);
  }

  [[clang::set_typestate(consumed)]]               //
  [[clang::return_typestate(consumed)]]            //
  [[clang::callable_when("consumed", "unknown")]]  //
  const StatusChainOr&
  AssertOk() const& {
    CHECK(ok()) << "The status should be ok.";
    return *this;
  }

  [[clang::set_typestate(unconsumed)]]               //
  [[clang::return_typestate(unconsumed)]]            //
  [[clang::callable_when("unconsumed", "unknown")]]  //
  StatusChainOr
  AssertNotOk()&& {
    CHECK(!ok()) << "The status should not be ok.";
    return std::move(*this);
  }

  [[clang::set_typestate(unconsumed)]]               //
  [[clang::return_typestate(unconsumed)]]            //
  [[clang::callable_when("unconsumed", "unknown")]]  //
  const StatusChainOr&
  AssertNotOk() const& {
    CHECK(!ok()) << "The status should not be ok.";
    return *this;
  }

  // Hints the compiler the consumable state of a specific stackable error.
  [[clang::set_typestate(consumed)]]               //
  [[clang::return_typestate(consumed)]]            //
  [[clang::callable_when("consumed", "unknown")]]  //
  StatusChainOr
  HintOk()&& noexcept {
    return std::move(*this);
  }

  [[clang::set_typestate(consumed)]]               //
  [[clang::return_typestate(consumed)]]            //
  [[clang::callable_when("consumed", "unknown")]]  //
  constexpr const StatusChainOr&
  HintOk() const& noexcept {
    return *this;
  }

  [[clang::set_typestate(unconsumed)]]               //
  [[clang::return_typestate(unconsumed)]]            //
  [[clang::callable_when("unconsumed", "unknown")]]  //
  StatusChainOr
  HintNotOk()&& noexcept {
    return std::move(*this);
  }

  [[clang::set_typestate(unconsumed)]]               //
  [[clang::return_typestate(unconsumed)]]            //
  [[clang::callable_when("unconsumed", "unknown")]]  //
  constexpr const StatusChainOr&
  HintNotOk() const& noexcept {
    return *this;
  }

  // The error status that would not be the ok status.
  // This would be useful to let the compiler check the object is in the correct
  // consumable state.
  [[clang::callable_when("unconsumed")]]   //
  [[clang::return_typestate(unconsumed)]]  //
  constexpr const status_type&
  err_status() const& noexcept {
    return *std::get_if<status_type>(&value_);
  }

  [[clang::callable_when("unconsumed")]]   //
  [[clang::return_typestate(unconsumed)]]  //
  status_type
  err_status()&& noexcept {
    return std::move(*std::get_if<status_type>(&value_));
  }

 private:
  // Indicates the constructor is for status chain. And prevent the conflict
  // with conversion operator. This is a workaround for the StatusChainOr that
  // the param_typestate doesn't work with the constructor.
  struct StatusChainCtorTag {};

  // Converting move constructor from a compatible stackable error type. It is
  // fine, since our internal stack representation is of a base |Base| type
  // anyway. SFINAE checks that the supplied pointer type is compatible with
  // this object's head type. Since manually specializing the operator could
  // lead to breaking invariant of the head object being castable to class
  // template type |_Et|, we use |ExplicitArgumentBarrier| idiom to make |_Ut|
  // auto-deducible only.
  template <int&... ExplicitArgumentBarrier, typename _Ut,
            typename = std::enable_if_t<std::is_convertible_v<
                _Ut*, typename StatusChain<_Et>::pointer>>>
  [[clang::return_typestate(unconsumed)]] StatusChainOr(
      StatusChain<_Ut> && other                   //
          [[clang::param_typestate(unconsumed)]]  //
          [[clang::return_typestate(consumed)]],  //
      StatusChainCtorTag)
      : value_(
            container_type{std::in_place_type<status_type>, std::move(other)}) {
    CHECK(!std::get<status_type>(value_).ok())
        << " StatusChainOr cannot hold an OK status";
  }

  container_type value_;
};

}  // namespace status
}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_STATUS_STATUS_CHAIN_OR_H_
