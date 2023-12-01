// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implements a simple framework for scoping TSS values.
// Based on chrome's base/memory/scoped_ptr_malloc implementation.
//
// Example usage:
//  ScopedTssContext context_handle;
//  TSS_RESULT result;
//  if (!OpenAndConnectTpm(context_handle.ptr(), &result))
//    ...
//  ScopedTssKey srk(*GetOveralls(), context_handle);
//  if (!LoadSrk(context_handle, srk_handle.ptr(), &result))
//    ...
//
// See the bottom of this file for common typedefs.
#ifndef LIBHWSEC_TSS_UTILS_SCOPED_TSS_TYPE_H_
#define LIBHWSEC_TSS_UTILS_SCOPED_TSS_TYPE_H_

#include <vector>

#include <base/logging.h>
#include <base/notreached.h>
#include <brillo/secure_string.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>

#include "libhwsec/overalls/overalls.h"

namespace hwsec {

inline void ScopedTssContextRelease(overalls::Overalls& overalls,
                                    TSS_HCONTEXT unused,
                                    TSS_HCONTEXT context) {
  // Usually, only |context| is used, but if the ScopedTssContext is
  // used slightly differently, it may end up with a context in |unused|.
  // For now, treat that as a bug.
  if (unused) {
    NOTREACHED() << "Unexpected data in the unused argument - a misuse of "
                    "ScopedTssContext. Please report to b/240880669";
    return;
  }
  if (context) {
    overalls.Ospi_Context_Close(context);
  }
}

inline void ScopedTssMemoryRelease(overalls::Overalls& overalls,
                                   TSS_HCONTEXT context,
                                   BYTE* memory) {
  if (!memory) {
    return;
  }
  if (!context) {
    NOTREACHED() << "Leaking Trousers memory due to null context. Please "
                    "report to b/240880669";
    return;
  }
  overalls.Ospi_Context_FreeMemory(context, memory);
}

inline void ScopedTssSecureMemoryRelease(overalls::Overalls& overalls,
                                         TSS_HCONTEXT context,
                                         BYTE* memory) {
  if (!memory) {
    return;
  }
  if (!context) {
    NOTREACHED() << "Leaking Trousers memory due to null context. Please "
                    "report to b/240880669";
    return;
  }
  overalls.Ospi_Context_SecureFreeMemory(context, memory);
}

inline void ScopedTssObjectRelease(overalls::Overalls& overalls,
                                   TSS_HCONTEXT context,
                                   TSS_HOBJECT handle) {
  if (!handle) {
    return;
  }
  if (!context) {
    NOTREACHED() << "Leaking Trousers handle due to null context. Please "
                    "report to b/240880669";
    return;
  }
  overalls.Ospi_Context_CloseObject(context, handle);
}

// Provide a basic scoped container for TSS managed objects.
template <typename TssType, auto ReleaseFunc>
class ScopedTssType {
 public:
  explicit ScopedTssType(overalls::Overalls& overalls,
                         TSS_HCONTEXT c = 0,
                         TssType t = 0)
      : overalls_(overalls), context_(c), type_(t) {}

  ScopedTssType(const ScopedTssType&) = delete;
  ScopedTssType& operator=(const ScopedTssType&) = delete;

  explicit ScopedTssType(ScopedTssType&& other)
      : overalls_(other.overalls_),
        context_(other.context_),
        type_(other.type_) {
    other.context_ = 0;
    other.type_ = 0;
  }

  ScopedTssType& operator=(ScopedTssType&& other) {
    ReleaseFunc(overalls_, context_, type_);
    context_ = other.context_;
    type_ = other.type_;
    other.context_ = 0;
    other.type_ = 0;
    return *this;
  }

  virtual ~ScopedTssType() { ReleaseFunc(overalls_, context_, type_); }

  // Provide a means to access the value without conversion.
  TssType value() const { return type_; }

  // Allow direct referencing of the wrapped value.
  TssType* ptr() { return &type_; }

  // Returns the assigned context.
  TSS_HCONTEXT context() const { return context_; }

  [[nodiscard]] TssType release() {
    TssType tmp = type_;
    type_ = 0;
    context_ = 0;
    return tmp;
  }

  void reset(TSS_HCONTEXT c = 0, TssType t = 0) {
    ReleaseFunc(overalls_, context_, type_);
    context_ = c;
    type_ = t;
  }

 private:
  overalls::Overalls& overalls_;
  TSS_HCONTEXT context_;
  TssType type_;
};

// Wrap ScopedTssObject to allow implicit conversion only when safe.
template <typename TssType, auto ReleaseFunc = ScopedTssObjectRelease>
class ScopedTssObject : public ScopedTssType<TssType, ReleaseFunc> {
 public:
  // Enforce a context for scoped objects.
  ScopedTssObject(overalls::Overalls& overalls, TSS_HCONTEXT c, TssType t = 0)
      : ScopedTssType<TssType, ReleaseFunc>(overalls, c, t) {}

  // Allow implicit conversion to TssType.
  operator TssType() { return this->value(); }
};

class ScopedTssContext
    : public ScopedTssObject<TSS_HCONTEXT, ScopedTssContextRelease> {
 public:
  explicit ScopedTssContext(overalls::Overalls& overalls, TSS_HCONTEXT t = 0)
      : ScopedTssObject<TSS_HCONTEXT, ScopedTssContextRelease>(overalls, 0, t) {
  }
};

// Provide clear-cut typedefs for the common cases.
using ScopedTssMemory = ScopedTssType<BYTE*, ScopedTssMemoryRelease>;
using ScopedTssSecureMemory =
    ScopedTssType<BYTE*, ScopedTssSecureMemoryRelease>;

using ScopedTssKey = ScopedTssObject<TSS_HKEY>;
using ScopedTssPolicy = ScopedTssObject<TSS_HPOLICY>;
using ScopedTssPcrs = ScopedTssObject<TSS_HPCRS>;
using ScopedTssNvStore = ScopedTssObject<TSS_HNVSTORE>;

}  // namespace hwsec

#endif  // LIBHWSEC_TSS_UTILS_SCOPED_TSS_TYPE_H_
