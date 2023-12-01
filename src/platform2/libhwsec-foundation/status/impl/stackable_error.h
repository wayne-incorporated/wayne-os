// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_STATUS_IMPL_STACKABLE_ERROR_H_
#define LIBHWSEC_FOUNDATION_STATUS_IMPL_STACKABLE_ERROR_H_

#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include <absl/base/attributes.h>
#include <base/check_op.h>

#include "libhwsec-foundation/status/impl/stackable_error_forward_declarations.h"

#include "libhwsec-foundation/status/impl/stackable_error_range.h"

namespace hwsec_foundation {
namespace status {
namespace _impl_ {

// Type trait checkers to determine if the class, intended to use with the
// status chain, is well-formed.
// TODO(dlunev): add a trait to verify callability of MakeStatusTrait.

template <typename, typename = void>
struct has_make_status_trait : public std::false_type {};
template <typename _Et>
struct has_make_status_trait<_Et, std::void_t<typename _Et::MakeStatusTrait>>
    : public std::true_type {};
template <typename _Et>
inline constexpr bool has_make_status_trait_v =
    has_make_status_trait<_Et>::value;

template <typename, typename = void>
struct has_base_error_type : public std::false_type {};
template <typename _Et>
struct has_base_error_type<_Et, std::void_t<typename _Et::BaseErrorType>>
    : public std::true_type {};
template <typename _Et>
inline constexpr bool has_base_error_type_v = has_base_error_type<_Et>::value;

// A tag-struct to provide into |Wrap| to explicitly discard the previous
// stack  after |WrapTransform|. That allows calling |Wrap| on a chain with
// different |BaseErrorType|.
struct WrapTransformOnly {};

// |StackableError| provides a unique_ptr-like access style for a stack of
// errors. It can be constructed from a raw pointer - to take an ownership of
// the pointer's lifetime - and linked with another StackableError via
// Wrap calls. The object implements iterator's traits to be used with
// range-for loops, and implements a |ToFullString| short-cut to combine the
// error messages of the whole stack.
// Since the object has unique_ptr-like semantics, it can never be copied, only
// moved, raw-ptr constructed or constructed from moving another
// |StackableError|.
//
// Despite being a unique_ptr representation, raw pointer access is a temporary
// convenience for converting existing code and will be deprecated, once the
// codebase adopts |ok()| checks.
// TODO(dlunev): Remove operator-> semantics when |ok()| is adopted.
//
// The consumable state meaning:
// * consumed => The stackable error is in the OK state.
// * unconsumed => The stackable error contains error.
// * unknown => The stackable error needs to be checked before using it.
//
// The purpose of consumable attribute is to achieve these checks.
// * go/clang-tidy/checks/google3-runtime-statusor-ok-status.md
// * go/clang-tidy/checks/google3-runtime-unchecked-statusor-access.md
//
// Template parameters meaning:
// _Et - head's error type. Must be derived from |Base|. Defaulter to |Base|
// _Rt - alias for |_Et| to trigger SFINAE in sub-templates.
// _Ut - uptype of |_Et| Type
// _Dt - a dynamic castable from |_Et| type
template <typename _Et = Error>
class [[clang::consumable(unknown)]]   //
[[clang::consumable_auto_cast_state]]  //
[[nodiscard]] StackableError {
 public:
  static_assert(has_make_status_trait_v<_Et>,
                "|_Et| type doesn't define |MakeStatusTrait|");
  static_assert(has_base_error_type_v<_Et>,
                "|_Et| type doesn't define |BaseErrorType|");

 private:
  // The use of |BaseErrorType| is a tranistional stop gap. Eventually the
  // type stored in stack should be equivalent to |_Et|. That may cause a
  // problem with upcasting the whole stack, since it would be expensive to
  // poke each unique pointer, thus some alternative storage arrangement
  // might be required.
  using stack_holder = StackHolderType<typename _Et::BaseErrorType>;
  using pointer_holder = PointerHolderType<_Et>;

  // Allow the other StackableError to access the head and error_stack.
  template <typename T>
  friend class StackableError;

 public:
  // Mimic unique_ptr type aliases. Through out the code when we check nullness
  // of the head element to |pointer()|, not to the |nullptr|. While this
  // doesn't make any difference at the moment, it may become prominent if we
  // introduce support for the deleters. Deleters introduce the whole another
  // layer of complexity around internal pointer type deduction, to the point
  // where the internal pointer may no longer be a raw-pointer object - it can
  // be anything, up to and including an object with no comparison against
  // |nullptr| or the one that loses some information when compare to |nullptr|.
  // Thus, to safe-guard ourselves against it, we adopt a standard library style
  // of comparing the internal pointer of unique_ptr-like objects.
  using pointer = typename PointerHolderType<_Et>::pointer;
  using element_type = typename PointerHolderType<_Et>::element_type;
  // We do not support deleters presently, but plumb the deleter type through
  // to complete the object trait.
  using deleter_type = typename PointerHolderType<_Et>::deleter_type;
  // Export the types which are actually stored within the stack parallel to
  // |element_type| and |pointer|.
  using base_element_type = typename _Et::BaseErrorType;
  using base_pointer =
      typename StackPointerHolderType<base_element_type>::pointer;

  // Type aliases for ranges and iterators. The underlying types are the
  // implementation details and must not be relied upon directly.
  using iterator = StackableErrorIterator<base_element_type>;
  using const_iterator = StackableErrorConstIterator<base_element_type>;
  // Iterators can be obtained from range with |begin()| and |end()|
  using iterator_range = StackableErrorRange<base_element_type>;
  using const_iterator_range = StackableErrorConstRange<base_element_type>;

  static_assert(std::is_base_of_v<Error, base_element_type> ||
                    std::is_same_v<Error, base_element_type>,
                "|_Et::BaseErrorType| is not derived from |Error|");
  static_assert(std::is_base_of_v<base_element_type, _Et> ||
                    std::is_same_v<base_element_type, _Et>,
                "|_Et| is not derived from |_Et::BaseErrorType|");

 private:
  // Implementation details of the internal holder's types so the rest of the
  // code can be generic. The types and members in the section are considered
  // a StackableError backend. The idea of the split to prevent change of the
  // backend affecting the frontend code - frontend code should never touch
  // the object that represents backend directly.

  // Backend object. Currently represented as
  // std::list<std::unique_ptr<base_element_type>> (see
  // stackable_error_forward_declarations.h).
  //
  // Invariants:
  // * |head_| represents head of the stack.
  // * |error_stack_.front(), error_stack_.end()| represents wrapped stack.
  // * |head_ == nullptr| represents an OK chain.
  // * |stack_error_| never contains null objects.
  // * |stack_error_| stores error cast to the |_Et::BaseErrorType|.
  pointer_holder head_;
  stack_holder error_stack_;

  // Backend interface.

  // Resets the stack.
  [[clang::set_typestate(consumed)]] void ResetInternal() {
    head_.reset();
    error_stack_.clear();
  }

  [[clang::set_typestate(unconsumed)]] void ResetInternal(pointer ptr) {
    DCHECK_NE(ptr, pointer()) << " Reset with |nullptr|";
    head_.reset(std::move(ptr));
    error_stack_.clear();
  }

  void ResetInternal(std::nullptr_t ptr) = delete;

  // Swaps the stacks of two chains.
  void SwapInternal(StackableError& other) noexcept {
    std::swap(head_, other.head_);
    std::swap(error_stack_, other.error_stack_);
  }

  // Return true if the object represents an |ok()| sequence.
  [[clang::test_typestate(consumed)]] bool IsOkInternal() const noexcept {
    return head_ == nullptr;
  }

  // Returns the pointer to the head error object.
  // TODO(dlunev): deprecate when codebase adopts |ok()| checks.
  [[clang::callable_when("unconsumed")]]  //
  [[clang::set_typestate(unconsumed)]]    //
  pointer
  GetErrInternal() const noexcept {
    DCHECK_NE(head_, nullptr) << " |nullptr| in error stack";
    return head_.get();
  }

  // Check if the object already wraps a stack.
  bool IsWrappingInternal() const noexcept {
    return !error_stack_.empty();
  }

  // Returns a range object to use with range-for loops. Ensures const access
  // to the underlying object.
  const_iterator_range RangeInternal() const noexcept {
    return StackableErrorConstRangeFactory<base_element_type>()(
        head_.get(), error_stack_.begin(), error_stack_.end());
  }

  // Returns a range object to use with range-for loops. Allows non-const access
  // to the underlying object.
  iterator_range RangeInternal() noexcept {
    return StackableErrorRangeFactory<base_element_type>()(
        head_.get(), error_stack_.begin(), error_stack_.end());
  }

 public:
  // The following code is considered StackablePointer's frontend. Constructors,
  // assign operators are allowed to construct and move the backend object, but
  // they should not introspect into them. Other methods can only use the
  // backend interface methods.

  // Creates a chain that represents an Ok result.
  [[clang::return_typestate(consumed)]] static StackableError<_Et> Ok() {
    return StackableError<_Et>();
  }

  // Creates a chain that represents an error case. Delegates Status creation to
  // the class'es trait.
  template <typename... Args>
  [[clang::return_typestate(unconsumed)]] static StackableError<_Et> Make(
      Args && ... args) {
    using MakeStatusTrait = typename _Et::MakeStatusTrait;
    return MakeStatusTrait()(std::forward<Args>(args)...);
  }

  // Default constructor creates an empty stack to represent success.
  [[clang::return_typestate(consumed)]] constexpr StackableError() noexcept
      : head_(nullptr), error_stack_() {}

  StackableError(std::nullptr_t) = delete;

  // Constructor from a raw pointer takes ownership of the pointer and puts it
  // on top of the stack.
  [[clang::return_typestate(unconsumed)]] explicit StackableError(pointer ptr)
      : head_(std::move(ptr)), error_stack_() {}

  // Move constructor. Releases the backend object of |other| into our
  // backend object.
  StackableError(StackableError && other [[clang::return_typestate(consumed)]])
      : head_(std::move(other.head_)),
        error_stack_(std::move(other.error_stack_)) {}

  // Converting move constructor from a compatible type. It is fine, since
  // our internal stack representation is of a base |Base| type anyway.
  // SFINAE checks that the supplied pointer type is compatible with this
  // object's head type. Since manually specializing the operator could lead to
  // breaking invariant of the head object being castable to class template type
  // |_Et|, we use |ExplicitArgumentBarrier| idiom to make |_Ut| auto-deducible
  // only.
  template <int&... ExplicitArgumentBarrier, typename _Ut,
            typename = std::enable_if_t<std::is_convertible_v<_Ut*, pointer>>>
  [[clang::return_typestate(unconsumed)]] StackableError(
      StackableError<_Ut> && other [[clang::return_typestate(consumed)]])
      : head_(std::move(other.head_)),
        error_stack_(std::move(other.error_stack_)) {
    static_assert(
        std::is_same_v<base_element_type, typename _Ut::BaseErrorType>,
        "|BaseErrorType| of |other| must be the same with |this|.");
  }

  // Move-assign operator. Releases the backend object of |other| into our
  // backend object.
  StackableError& operator=(StackableError&& other
                            [[clang::return_typestate(consumed)]]) {
    head_ = std::move(other.head_);
    error_stack_ = std::move(other.error_stack_);
    return *this;
  }

  // Converting move-assign operator from a compatible type. See the comments
  // on converting constructor for the template arguments explanation.
  template <int&... ExplicitArgumentBarrier, typename _Ut,
            typename = std::enable_if_t<std::is_convertible_v<_Ut*, pointer>>>
  [[clang::return_typestate(unconsumed)]] StackableError& operator=(
      StackableError<_Ut>&& other [[clang::return_typestate(consumed)]]) {
    static_assert(
        std::is_same_v<base_element_type, typename _Ut::BaseErrorType>,
        "|BaseErrorType| of |other| must be the same with |this|.");
    head_ = std::move(other.head_);
    error_stack_ = std::move(other.error_stack_);
    return *this;
  }

  // Disallow copy since we provide unique_ptr-like semantics.
  StackableError(const StackableError&) = delete;
  StackableError& operator=(const StackableError&) = delete;

  // Returns true if StackableError represents a success.
  [[clang::test_typestate(consumed)]] bool ok() const noexcept {
    return IsOkInternal();
  }

  // The Assert* API would be useful to ensure the consumable state of stackable
  // error. This is a workaround for CHECK/DCHECK/ASSERT macros that doesn't
  // work with the consumable attribute.
  // For more information: crbug/1336752#c12, b/223361459
  [[clang::set_typestate(consumed)]]               //
  [[clang::return_typestate(consumed)]]            //
  [[clang::callable_when("consumed", "unknown")]]  //
  StackableError
  AssertOk()&& {
    CHECK(ok()) << "The status should be ok.";
    return std::move(*this);
  }

  [[clang::set_typestate(consumed)]]               //
  [[clang::return_typestate(consumed)]]            //
  [[clang::callable_when("consumed", "unknown")]]  //
  const StackableError&
  AssertOk() const& {
    CHECK(ok()) << "The status should be ok.";
    return *this;
  }

  [[clang::set_typestate(unconsumed)]]               //
  [[clang::return_typestate(unconsumed)]]            //
  [[clang::callable_when("unconsumed", "unknown")]]  //
  StackableError
  AssertNotOk()&& {
    CHECK(!ok()) << "The status should not be ok.";
    return std::move(*this);
  }

  [[clang::set_typestate(unconsumed)]]               //
  [[clang::return_typestate(unconsumed)]]            //
  [[clang::callable_when("unconsumed", "unknown")]]  //
  const StackableError&
  AssertNotOk() const& {
    CHECK(!ok()) << "The status should not be ok.";
    return *this;
  }

  // Hints the compiler the consumable state of a specific stackable error.
  [[clang::set_typestate(consumed)]]               //
  [[clang::return_typestate(consumed)]]            //
  [[clang::callable_when("consumed", "unknown")]]  //
  StackableError
  HintOk()&& noexcept {
    return std::move(*this);
  }

  [[clang::set_typestate(consumed)]]               //
  [[clang::return_typestate(consumed)]]            //
  [[clang::callable_when("consumed", "unknown")]]  //
  constexpr const StackableError&
  HintOk() const& noexcept {
    return *this;
  }

  [[clang::set_typestate(unconsumed)]]               //
  [[clang::return_typestate(unconsumed)]]            //
  [[clang::callable_when("unconsumed", "unknown")]]  //
  StackableError
  HintNotOk()&& noexcept {
    return std::move(*this);
  }

  [[clang::set_typestate(unconsumed)]]               //
  [[clang::return_typestate(unconsumed)]]            //
  [[clang::callable_when("unconsumed", "unknown")]]  //
  constexpr const StackableError&
  HintNotOk() const& noexcept {
    return *this;
  }

  // Returns self.
  constexpr const StackableError& status() const& noexcept { return *this; }
  StackableError status()&& noexcept { return std::move(*this); }

  // Returns error status.
  [[clang::callable_when("unconsumed")]]   //
  [[clang::return_typestate(unconsumed)]]  //
  constexpr const StackableError&
  err_status() const& noexcept {
    return *this;
  }

  [[clang::callable_when("unconsumed")]]   //
  [[clang::return_typestate(unconsumed)]]  //
  StackableError
  err_status()&& noexcept {
    return std::move(*this);
  }

  // Const reference to the top error object. It is a logic error to query
  // |error()| or dereference a |StackableError| that represents success.
  // |noexcept(noexcept(*std::declval<pointer>()))| means that the function is
  // not throwing if dereferencing of the object of the pointer type would not
  // be throwing. Outer |noexcept| in the sequence is a function definition
  // keyword, which, when its argument is |true|, defines the function as
  // non-throwing. The inner |noexcept| is an operator that evaluates to |true|
  // if the operation supplied as its argument can throw. Combining those
  // together
  // * If |*std::declval<pointer>()| can throw - the inner |noexcept| will
  // return
  //   |true|, and |false| otherwise.
  // * The outer |noexcept| will consume the value, and based on it will declare
  //   the function as either throwing or non-throwing.
  [[clang::callable_when("unconsumed")]]  //
  std::add_lvalue_reference_t<element_type>
  error() const noexcept(noexcept(*std::declval<pointer>())) {
    CHECK(!ok()) << " Dereferencing an OK chain is not allowed";
    return *GetErrInternal();
  }

  // Dereferencing the stack is equivalent to calling |error()| method on it -
  // it returns const reference to the top error object.
  // See the explanation for |noexcept(noexcept(...))| in |error()| method
  // comment.
  [[clang::callable_when("unconsumed")]]  //
  std::add_lvalue_reference_t<element_type>
  operator*() const noexcept(noexcept(*std::declval<pointer>())) {
    return error();
  }

  // Returns the pointer to the head of the error stack or the value
  // representing a nullptr pointer.
  // TODO(dlunev): deprecate when codebase adopts |ok()| checks.
  [[clang::callable_when("unconsumed")]] pointer operator->() const noexcept {
    CHECK(!ok()) << " Arrow operator on an OK chain is not allowed";
    return GetErrInternal();
  }

  // Resets current stack.
  [[clang::set_typestate(consumed)]] void reset() {
    ResetInternal();
  }

  // Don't reset from the std::nullptr_t.
  void reset(std::nullptr_t) = delete;

  // Resets current stack with a new error.
  [[clang::set_typestate(unconsumed)]] void reset(pointer ptr) {
    ResetInternal(std::move(ptr));
  }

  // Swaps two stacks.
  void swap(StackableError& other) noexcept { SwapInternal(other); }

  // Returns range object for range-for loops. Ensures const access to the
  // underlying pointers data.
  const_iterator_range const_range() const noexcept { return RangeInternal(); }

  // Returns range object for range-for loops. Ensures const access to the
  // underlying pointers data.
  const_iterator_range range() const noexcept { return RangeInternal(); }

  // Returns range object for range-for loops. Allows non-const access to the
  // underlying pointers data.
  iterator_range range() noexcept { return RangeInternal(); }

  // Walks the stack of objects and combines the error messages of each object
  // on the stack.
  std::string ToFullString() const noexcept {
    if (ok()) {
      return "OK";
    }

    std::string result;
    for (const auto& error_obj : const_range()) {
      if (!result.empty()) {
        result += ": ";
      }
      result += error_obj.ToString();
    }
    return result;
  }

  // Returns |true| if the object is wrapping another stack.
  // Returns |false| if the object is a stand alone error or is ok() object.
  [[clang::test_typestate(unconsumed)]] bool IsWrapping() const noexcept {
    return IsWrappingInternal();
  }

  // Make current error to wrap another stack. Do it in place without moving
  // ourselves out. Doesn't return a value, because it is not allowed to wrap
  // more than once.
  // It wouldn't break anything if the client would manually specialize the
  // template, for practically the tail would be cast to |Base| anyway, but
  // add |ExplicitArgumentBarrier| just for the safety of mind to make |_Ut|
  // automatically deducible only.
  template <int&... ExplicitArgumentBarrier, typename _Ut>
  [[clang::callable_when("unconsumed")]] void WrapInPlace(
      StackableError<_Ut> && other [[clang::param_typestate(unconsumed)]]  //
                             [[clang::return_typestate(consumed)]]) {
    static_assert(
        std::is_same_v<base_element_type, typename _Ut::BaseErrorType>,
        "|BaseErrorType| of |other| must be the same with |this|. "
        "Use |WrapTransformOnly| tag to drop previous stack.");
    CHECK(!other.ok()) << " Can't wrap an OK object.";
    CHECK(!ok()) << " OK object can't be wrapping.";
    CHECK(!IsWrapping()) << " Object can wrap only once.";

    // Call into current error's |WrapTransform| and provide it the range object
    // for the stack being wrapped. We do it before actual wrapping so the
    // current error doees not appear in the view. We provide const_view to
    // prevent the modification of previously stacked objects from transform to
    // disallow creating side effects on the stack.
    GetErrInternal()->WrapTransform(other.const_range());

    // Because the error stack is empty, move the other error stack directly.
    error_stack_ = std::move(other.error_stack_);
    error_stack_.push_front(std::move(other.head_));
  }

  // This is an overload of |WrapInPlace| that drops the previous stack. In that
  // case the code relies on a |WrapTransform| overload provided for the
  // |other|'s |BaseErrorType| to extract necessary info from the previous
  // stack.
  template <int&... ExplicitArgumentBarrier, typename _Ut>
  [[clang::callable_when("unconsumed")]] void WrapInPlace(
      StackableError<_Ut> && other [[clang::param_typestate(unconsumed)]]  //
                             [[clang::return_typestate(consumed)]],
      WrapTransformOnly tag) {
    CHECK(!other.ok()) << " Can't wrap an OK object.";
    CHECK(!ok()) << " OK object can't be wrapping.";
    CHECK(!IsWrapping()) << " Object can wrap only once.";

    // Call into current error's |WrapTransform| and provide it the range object
    // for the stack being wrapped. We do it before actual wrapping so the
    // current error doees not appear in the view. We provide const_view to
    // prevent the modification of previously stacked objects from transform to
    // disallow creating side effects on the stack.
    GetErrInternal()->WrapTransform(other.const_range());

    // Discard the prior stack.
    other.reset();
  }

  // Make current error to wrap another stack. See template arguments
  // explanation in |WrapInPlace| comments.
  template <int&... ExplicitArgumentBarrier, typename _Ut>
  [[clang::return_typestate(unconsumed)]]  //
  [[clang::callable_when("unconsumed")]]   //
  [[nodiscard]] auto&&
  Wrap(StackableError<_Ut> && other [[clang::param_typestate(unconsumed)]]  //
                              [[clang::return_typestate(consumed)]])&& {
    WrapInPlace(std::move(other));
    return std::move(*this);
  }

  // This is an overload of |Wrap| that drops the previous stack. In that case
  // the code relies on a |WrapTransform| overload provided for the |other|'s
  // |BaseErrorType| to extract necessary info from the previous stack.
  template <int&... ExplicitArgumentBarrier, typename _Ut>
  [[clang::return_typestate(unconsumed)]]  //
  [[clang::callable_when("unconsumed")]]   //
  [[nodiscard]] auto&&
  Wrap(StackableError<_Ut> && other [[clang::param_typestate(unconsumed)]]  //
                              [[clang::return_typestate(consumed)]],
       WrapTransformOnly tag)&& {
    WrapInPlace(std::move(other), tag);
    return std::move(*this);
  }

  // A workaround for the StatusChainOr that the param_typestate doesn't work
  // with the constructor.
  template <typename _Vt, typename _Et2>
  [[clang::callable_when("unconsumed")]]   //
  [[clang::return_typestate(unconsumed)]]  //
  [[clang::set_typestate(consumed)]]       //
  operator StatusChainOr<_Vt, _Et2>()&& {  // NOLINT(runtime/explicit)
    return StatusChainOr<_Vt, _Et2>::MakeFromStatusChain(std::move(*this));
  }
};

// Make |StackableError| printable.
template <typename _Et>
std::ostream& operator<<(std::ostream& os, const StackableError<_Et>& error) {
  os << error.ToFullString();
  return os;
}

}  // namespace _impl_
}  // namespace status
}  // namespace hwsec_foundation

// Make |StackableError| swappable.
namespace std {
template <typename _Et>
inline void swap(
    hwsec_foundation::status::_impl_::StackableError<_Et>& s1,
    hwsec_foundation::status::_impl_::StackableError<_Et>& s2) noexcept {
  s1.swap(s2);
}
}  // namespace std

#endif  // LIBHWSEC_FOUNDATION_STATUS_IMPL_STACKABLE_ERROR_H_
