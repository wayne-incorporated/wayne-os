// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_UTIL_ASYNC_INIT_H_
#define CRYPTOHOME_UTIL_ASYNC_INIT_H_

#include <utility>
#include <variant>

#include <base/functional/callback.h>

namespace cryptohome {

// This class is a pointer-like abstraction for wrapping an object whose
// construction is asynchronous. The idea is that until the object is
// successfully initialized, it acts like a null pointer but once the
// initialization completes it can be used like a normal non-null pointer.
template <typename T>
class AsyncInitPtr {
 public:
  // Callback that attempts to get the underlying object if it has been
  // initialized. If it hasn't then it should return null.
  using GetterCallback = base::RepeatingCallback<T*()>;

  // Constructor that wraps a callback for the to-be-initialized object.
  explicit AsyncInitPtr(GetterCallback callback)
      : object_(std::move(callback)) {}

  // Constructor that wraps an already-initialized object. You shouldn't
  // normally use this in regular code (if the object already exists then this
  // wrapper has no purpose) but it can be useful in testing when an object
  // which is normally initiaized asynchronously instead just exists.
  explicit AsyncInitPtr(T* ptr) : object_(ptr) {}

  // The pointer is copyable. If the underlying object has already been
  // initialized then this is preserved.
  AsyncInitPtr(const AsyncInitPtr&) = default;
  AsyncInitPtr& operator=(const AsyncInitPtr&) = default;

  // Returns a pointer to the underlying object, or null if it isn't initialized
  // yet. Once this returns a non-null pointer it can be safely assumed to be
  // non-null from then on (unless you assign over it).
  T* get() const {
    if (GetterCallback* getter = std::get_if<GetterCallback>(&object_)) {
      T* object = getter->Run();
      if (object) {
        object_ = object;
      }
      return object;
    }
    return std::get<T*>(object_);
  }

  // Checks if the underlying object is not null yet.
  explicit operator bool() const { return get() != nullptr; }

  // Dereference the pointer to the underlying object. The behavior of these is
  // undefined if get() == nullptr.
  T& operator*() const {
    T** ptrptr = std::get_if<T*>(&object_);
    CHECK(ptrptr);
    return **ptrptr;
  }
  T* operator->() const {
    T** ptrptr = std::get_if<T*>(&object_);
    CHECK(ptrptr);
    return *ptrptr;
  }

 private:
  // The underlying object. If this is a callback, then the object may not be
  // initialized yet and the callback needs to be called to (attempt to) get it.
  // Once the object is successfully initialized then the pointer to it will be
  // written here and from then on it can be assumed to be valid.
  mutable std::variant<GetterCallback, T*> object_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_UTIL_ASYNC_INIT_H_
