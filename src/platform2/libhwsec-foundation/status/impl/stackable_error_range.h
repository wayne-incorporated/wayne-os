// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_STATUS_IMPL_STACKABLE_ERROR_RANGE_H_
#define LIBHWSEC_FOUNDATION_STATUS_IMPL_STACKABLE_ERROR_RANGE_H_

#include <type_traits>

#include "libhwsec-foundation/status/impl/stackable_error_forward_declarations.h"
#include "libhwsec-foundation/status/impl/stackable_error_iterator.h"

namespace hwsec_foundation {
namespace status {
namespace _impl_ {

// Range primitive is added as a transitional functionality and may be removed
// later.

template <typename _Et>
struct StackableErrorConstRangeFactory;
template <typename _Et>
struct StackableErrorRangeFactory;

template <typename _Et>
class StackableErrorConstRange {
 private:
  using head_pointer = typename StackPointerHolderType<_Et>::pointer;
  using internal_iterator =
      typename StackableErrorConstIterator<_Et>::internal_iterator;

 public:
  // Copy and move constructability is safe since the underlying iterator must
  // be copy/move constructible/assignable.
  StackableErrorConstRange(const StackableErrorConstRange&) noexcept = default;
  StackableErrorConstRange& operator=(
      const StackableErrorConstRange&) noexcept = default;
  StackableErrorConstRange(StackableErrorConstRange&&) noexcept = default;
  StackableErrorConstRange& operator=(StackableErrorConstRange&&) noexcept =
      default;

  // For-range loop traits.

  StackableErrorConstIterator<_Et> begin() const noexcept {
    return StackableErrorConstIterator<_Et>(head_, begin_);
  }

  StackableErrorConstIterator<_Et> end() const noexcept {
    return StackableErrorConstIterator<_Et>(nullptr, end_);
  }

 private:
  // Internal iterators must be explicitly supplied.
  // Private to not allow explicit construction by clients.
  StackableErrorConstRange(head_pointer head,
                           internal_iterator begin,
                           internal_iterator end) noexcept
      : head_(head), begin_(begin), end_(end) {}

  // Head pointer.
  head_pointer head_;
  // Beginning and the end of the range iterators.
  internal_iterator begin_;
  internal_iterator end_;

  // Make a factory class a friend to avoid templating for |StackableError|
  // access.
  friend struct StackableErrorConstRangeFactory<_Et>;

  // Make non-const range a friend to allow casting it const.
  friend class StackableErrorRange<_Et>;
};

// Proxy for range creation. Can be called from |StackableError|, but is not
// exposed to the client to avoid explicit creation of range objects.
template <typename _Et>
struct StackableErrorConstRangeFactory {
  StackableErrorConstRange<_Et> operator()(
      typename StackableErrorConstRange<_Et>::head_pointer head,
      typename StackableErrorConstRange<_Et>::internal_iterator begin,
      typename StackableErrorConstRange<_Et>::internal_iterator end) {
    return StackableErrorConstRange<_Et>(head, begin, end);
  }
};

template <typename _Et>
class StackableErrorRange {
 private:
  using head_pointer = typename StackPointerHolderType<_Et>::pointer;
  using internal_iterator =
      typename StackableErrorIterator<_Et>::internal_iterator;

 public:
  // Copy and move constructability is safe since the underlying iterator must
  // be copy/move constructible/assignable.
  StackableErrorRange(const StackableErrorRange&) noexcept = default;
  StackableErrorRange& operator=(const StackableErrorRange&) noexcept = default;
  StackableErrorRange(StackableErrorRange&&) noexcept = default;
  StackableErrorRange& operator=(StackableErrorRange&&) noexcept = default;

  operator StackableErrorConstRange<_Et>() noexcept {
    return StackableErrorConstRange<_Et>(head_, begin_, end_);
  }

  // For-range loop traits.

  StackableErrorIterator<_Et> begin() const noexcept {
    return StackableErrorIterator<_Et>(head_, begin_);
  }

  StackableErrorIterator<_Et> end() const noexcept {
    return StackableErrorIterator<_Et>(nullptr, end_);
  }

 private:
  // Internal iterators must be explicitly supplied.
  // Private to not allow explicit construction by clients.
  StackableErrorRange(head_pointer head,
                      internal_iterator begin,
                      internal_iterator end) noexcept
      : head_(head), begin_(begin), end_(end) {}

  // Head pointer.
  head_pointer head_;
  // Beginning and the end of the range iterators.
  internal_iterator begin_;
  internal_iterator end_;

  // Make a factory class a friend to avoid templating for |StackableError|
  // access.
  friend struct StackableErrorRangeFactory<_Et>;
};

// Proxy for range creation. Can be called from |StackableError|, but is not
// exposed to the client to avoid explicit creation of range objects.
template <typename _Et>
struct StackableErrorRangeFactory {
  StackableErrorRange<_Et> operator()(
      typename StackableErrorRange<_Et>::head_pointer head,
      typename StackableErrorRange<_Et>::internal_iterator begin,
      typename StackableErrorRange<_Et>::internal_iterator end) {
    return StackableErrorRange<_Et>(head, begin, end);
  }
};

// Make ranges comparable. We define only const comparison since non-const
// range can be cast to const.
// By providing |_Ct1| and |_Ct2| arguments which we can match against const and
// non-const version, we generate all possible pairs of the comparison.
// The following template construct allows us to generate all combinations of
// comparison operators in one go. It works as following:
// |_Ct1| and |_Ct2| are templated themselves and represent the "container".
// |_Et| is the element type of the container.
// |DisambiguationGuard| is an |ExplicitArgumentBarrier| idiom, but with the
// reference type specialized to disambiguate other broad templates like this.
// That is needed because the SFINAE guards can not disabmiguate broad templates
// against similarly formed (we have another instance of it in iterator object).
// Then the SFINAE |enable_if_t| cut any possible instantiation where the
// actual container type is not what we expect in the comparator.
template <template <typename> typename _Ct1,
          template <typename>
          typename _Ct2,
          typename _Et,
          StackableErrorRange<_Et>&... DisambiguationGuard,
          typename = std::enable_if_t<
              std::is_same_v<_Ct1<_Et>, StackableErrorConstRange<_Et>> ||
              std::is_same_v<_Ct1<_Et>, StackableErrorRange<_Et>>>,
          typename = std::enable_if_t<
              std::is_same_v<_Ct2<_Et>, StackableErrorConstRange<_Et>> ||
              std::is_same_v<_Ct2<_Et>, StackableErrorRange<_Et>>>>
inline bool operator==(const _Ct1<_Et>& range1,
                       const _Ct2<_Et>& range2) noexcept {
  return range1.begin() == range2.begin() && range1.end() == range2.end();
}

template <template <typename> typename _Ct1,
          template <typename>
          typename _Ct2,
          typename _Et,
          StackableErrorRange<_Et>&... DisambiguationGuard,
          typename = std::enable_if_t<
              std::is_same_v<_Ct1<_Et>, StackableErrorConstRange<_Et>> ||
              std::is_same_v<_Ct1<_Et>, StackableErrorRange<_Et>>>,
          typename = std::enable_if_t<
              std::is_same_v<_Ct2<_Et>, StackableErrorConstRange<_Et>> ||
              std::is_same_v<_Ct2<_Et>, StackableErrorRange<_Et>>>>
inline bool operator!=(const _Ct1<_Et>& range1,
                       const _Ct2<_Et>& range2) noexcept {
  return !(range1 == range2);
}

}  // namespace _impl_
}  // namespace status
}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_STATUS_IMPL_STACKABLE_ERROR_RANGE_H_
