// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_UTIL_LEASE_H_
#define FACED_UTIL_LEASE_H_

#include <utility>

#include <base/functional/callback.h>

namespace faced {

// A Lease to an object of type T.
//
// Lease<T> objects have a pointer to an object of type T, and can be used
// like a std::unique_ptr<T>. However, the Lease object does not own the
// underlying object. Instead, when the Lease goes out of scope, a destroy
// callback is synchronously called allowing the creator of the lease to
// perform any clean up.
template <typename T>
class Lease {
 public:
  explicit Lease(T* parent) : parent_(parent) {}
  Lease(T* parent, base::OnceClosure on_destroy)
      : parent_(parent), destroy_callback_(std::move(on_destroy)) {}

  ~Lease() {
    if (destroy_callback_) {
      std::move(destroy_callback_).Run();
    }
  }

  // Allow move, disallow copy.
  Lease(const Lease&) = delete;
  Lease& operator=(const Lease&) = delete;
  Lease(Lease&&) = default;
  Lease& operator=(Lease&&) = default;

  // Access the underlying object.
  T& operator->() { return *parent_; }
  T* operator*() { return parent_; }

 private:
  T* parent_;
  base::OnceClosure destroy_callback_;
};

}  // namespace faced

#endif  // FACED_UTIL_LEASE_H_
