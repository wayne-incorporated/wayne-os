// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_UTILITY_SYNCHRONIZED_H_
#define LIBHWSEC_FOUNDATION_UTILITY_SYNCHRONIZED_H_

#include <atomic>
#include <memory>
#include <utility>

#include <base/synchronization/lock.h>

namespace hwsec_foundation::utility {

template <class T>
class SynchronizedHandle;

// Wrapper that can provide synchronized access to the underlying class object.
// The Lock() method returns a SynchronizedHandle which acquires a lock to
// ensure exclusive access of the object. Note that the underlying
// implementation use locks, so you should be aware of when/how to use this as
// if you are using ordinary locks to prevent deadlock.
//
// Note: The developer should make sure there is no usage of this object after
// it had been destructed. In the other word, the destruction is not
// thread-safe, the developer should consider using it with base::NoDestructor,
// or join the other threads before calling the destructor. For the thread-safe
// destruction, the developer should consider std::shared_ptr or
// base::RefCountedThreadSafe.
//
// Example usage:
//   Synchronized<std::vector<int>> v;
//   v.Lock()->push_back(1);
//
//   SynchronizedHandle<std::vector<int>> handle = v.Lock();
//   int original_size = handle->size();
//   handle->push_back(2);
//   assert(handle->size() == original_size + 1);
template <class T>
class Synchronized {
 public:
  template <typename... Args>
  explicit Synchronized(Args&&... args) : data_(std::forward<Args>(args)...) {}

  Synchronized(const Synchronized&) = delete;
  Synchronized& operator=(const Synchronized&) = delete;

  ~Synchronized() = default;

  // Returns a SynchronizedHandle which acquires a lock to ensure exclusive
  // access of the object. The lock is released after the SynchronizedHandle is
  // out of scope. If there is already a SynchronizedHandle instance generated
  // by this method, this method blocks until that handle is out of scope.
  SynchronizedHandle<T> Lock() { return SynchronizedHandle(&lock_, &data_); }

 private:
  base::Lock lock_;
  T data_;
};

// Similar to the Synchronized object, but synchronized access to the underlying
// class object is only provided after synchronize is called. After that, it
// can't be downgraded to non-synchronized mode.
//
// Example usage:
//   MaybeSynchronized<std::vector<int>> v;
//   v.Lock()->push_back(1);
//
//   // Start the synchronize lock.
//   v.synchronize();
//
//   SynchronizedHandle<std::vector<int>> handle = v.Lock();
//   int original_size = handle->size();
//   handle->push_back(2);
//   assert(handle->size() == original_size + 1);
template <class T>
class MaybeSynchronized {
 public:
  template <typename... Args>
  explicit MaybeSynchronized(Args&&... args)
      : data_(std::forward<Args>(args)...) {}

  MaybeSynchronized(const MaybeSynchronized&) = delete;
  MaybeSynchronized& operator=(const MaybeSynchronized&) = delete;

  ~MaybeSynchronized() {
    // Move it into an unique_ptr and drop it.
    std::unique_ptr<base::Lock>(lock_.exchange(nullptr));
  }

  bool is_synchronized() { return lock_ != nullptr; }

  void synchronize() {
    base::Lock* original = lock_;
    if (original == nullptr) {
      auto new_lock = std::make_unique<base::Lock>();
      if (std::atomic_compare_exchange_strong(&lock_, &original,
                                              new_lock.get())) {
        new_lock.release();
      }
    }
  }

  // Returns a SynchronizedHandle which may acquires a lock to ensure exclusive
  // access of the object. If the lock is exits, it would be released after the
  // SynchronizedHandle is out of scope.
  SynchronizedHandle<T> Lock() { return SynchronizedHandle(lock_, &data_); }

 private:
  std::atomic<base::Lock*> lock_ = nullptr;
  T data_;
};

// Returned by the Lock() method of Synchronized. Provides exclusive
// access of the object, and derefs into it.
template <class T>
class SynchronizedHandle {
 public:
  SynchronizedHandle(const SynchronizedHandle&) = delete;
  SynchronizedHandle& operator=(const SynchronizedHandle&) = delete;

  ~SynchronizedHandle() = default;

  constexpr const T& operator*() const { return *data_; }
  constexpr T& operator*() { return *data_; }

  constexpr const T* operator->() const { return data_; }
  constexpr T* operator->() { return data_; }

  constexpr const T& value() const { return *data_; }
  constexpr T& value() { return *data_; }

 private:
  SynchronizedHandle(base::Lock* lock, T* data)
      : auto_lock_(lock), data_(data) {}

  base::AutoLockMaybe auto_lock_;
  T* data_;

  friend class Synchronized<T>;
  friend class MaybeSynchronized<T>;
};

}  // namespace hwsec_foundation::utility

#endif  // LIBHWSEC_FOUNDATION_UTILITY_SYNCHRONIZED_H_
