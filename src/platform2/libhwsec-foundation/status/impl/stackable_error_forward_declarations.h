// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_STATUS_IMPL_STACKABLE_ERROR_FORWARD_DECLARATIONS_H_
#define LIBHWSEC_FOUNDATION_STATUS_IMPL_STACKABLE_ERROR_FORWARD_DECLARATIONS_H_

#include <list>
#include <memory>

namespace hwsec_foundation {
namespace status {
namespace _impl_ {

// Base instantiable error class.
class Error;

// The backend type definition. update the comment for |error_stack_| member of
// the |StackableError| if this changes.

// Holder type for the pointer.
template <typename _Et>
using PointerHolderType = std::unique_ptr<_Et>;
// Holder type specialization for the stack holder.
template <typename _Bt>
using StackPointerHolderType = PointerHolderType<_Bt>;
// The class to hold the stack of the objects.
template <typename _Bt>
using StackHolderType = std::list<StackPointerHolderType<_Bt>>;

// The stack of errors.
template <typename _Et>
class StackableError;

// Iterators for the errors.
template <typename _Bt>
class StackableErrorConstIterator;
template <typename _Bt>
class StackableErrorIterator;

// Iterators proxy.
template <typename _Bt>
class StackableErrorConstRange;
template <typename _Bt>
class StackableErrorRange;

}  // namespace _impl_

template <typename _Vt, typename _Et>
class StatusChainOr;

}  // namespace status
}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_STATUS_IMPL_STACKABLE_ERROR_FORWARD_DECLARATIONS_H_
