// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_SECURE_ALLOCATOR_H_
#define LIBBRILLO_BRILLO_SECURE_ALLOCATOR_H_

#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstddef>
#include <limits>
#include <type_traits>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <brillo/brillo_export.h>
#include <brillo/secure_string.h>

namespace brillo {
// SecureAllocator is a stateless derivation of std::allocator that clears
// the contents of the object on deallocation. Additionally, to prevent the
// memory from being leaked, we use the following defensive mechanisms:
//
// 1. Use page-aligned memory so that it can be locked (therefore, use mmap()
//    instead of malloc()). Note that mlock()s are not inherited over fork(),
//
// 2. Always allocate memory in multiples of pages: this adds a memory overhead
//    of ~1 page for each object. Moreover, the extra memory is not available
//    for the allocated object to expand into: the container expects that the
//    memory allocated to it matches the size set in reserve().
// TODO(sarthakkukreti): Figure out if it is possible to propagate the real
// capacity to the container without an intrusive change to the STL.
// [Example: allow __recommend() override in allocators for containers.]
//
// 3. Mark the memory segments as undumpable, unmergeable.
//
// 4. Use MADV_WIPEONFORK:
//    this results in a new anonymous vma instead of copying over the contents
//    of the secure object after a fork(). By default [MADV_DOFORK], the vma is
//    marked as copy-on-write, and the first process which writes to the secure
//    object after fork get a new copy. This may break the security guarantees
//    setup above. Another alternative is to use MADV_DONTFORK which results in
//    the memory mapping not getting copied over to child process at all: this
//    may result in cases where if the child process gets segmentation faults
//    on attempts to access virtual addresses in the secure object's address
//    range,
//
//    With MADV_WIPEONFORK, the child processes can access the secure object
//    memory safely, but the contents of the secure object appear as zero to
//    the child process. Note that threads share the virtual address space and
//    secure objects would be transparent across threads.
// TODO(sarthakkukreti): Figure out patterns to pass secure data over fork().
template <typename T>
class BRILLO_PRIVATE SecureAllocator {
 public:
  using value_type = T;

  // Allocators are equal if they are stateless. i.e., one allocator can
  // deallocate objects created by another allocator.
  // See https://en.cppreference.com/w/cpp/memory/allocator/operator_cmp and
  // https://en.cppreference.com/w/cpp/named_req/Allocator.
  using is_always_equal = std::true_type;

  // Constructors that wrap over std::allocator.
  // Makes sure that the allocator's static members are only allocated once.
  SecureAllocator() noexcept = default;
  SecureAllocator(const SecureAllocator& other) noexcept = default;
  template <class U>
  SecureAllocator(const SecureAllocator<U>& other) noexcept {}

  // Max theoretical count for type on system.
  std::size_t max_size() const {
    // Calculate the page size the first time we are called, and
    // afterwards use the precalculated results.
    static std::size_t result = GetMaxSizeForType(SystemPageSize());
    return result;
  }

  // Allocation: allocates ceil(size/pagesize) for holding the data.
  T* allocate(std::size_t n) {
    // Note: std::allocator is expected to throw a std::bad_alloc on failing to
    // allocate the memory correctly. Instead of returning a nullptr, which
    // confuses the standard template library, use CHECK(false) variations
    // to crash on the failure path.

    // Check if n can be theoretically allocated.
    CHECK_LT(n, max_size());
    // Check if n = 0: there's nothing to allocate;
    CHECK_GT(n, 0u);

    // Calculate the page-aligned buffer size.
    std::size_t buffer_size = CalculatePageAlignedBufferSize(n);

    // Memory locking granularity is per-page: mmap ceil(size/page size) pages.
    void* buffer = mmap(nullptr, buffer_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    PCHECK(buffer != MAP_FAILED) << "failed to allocate secure memory";

    // Lock buffer into physical memory.
    if (mlock(buffer, buffer_size)) {
      CHECK_NE(errno, ENOMEM) << "It is likely that SecureAllocator has "
                                 "exceeded the RLIMIT_MEMLOCK limit";
      PLOG(FATAL) << "Failed to lock allocated pages";
    }

    // Mark memory as non dumpable in a core dump.
    PCHECK(!madvise(buffer, buffer_size, MADV_DONTDUMP));

    // Mark memory as non mergeable with another page, even if the contents
    // are the same.
    if (madvise(buffer, buffer_size, MADV_UNMERGEABLE)) {
      // MADV_UNMERGEABLE is only available if the kernel has been configured
      // with CONFIG_KSM set. If the CONFIG_KSM flag has not been set, then
      // pages are not mergeable so this madvise option is not necessary.
      //
      // In the case where CONFIG_KSM is not set, EINVAL is the error set.
      // Since this error value is expected in some cases, don't crash.
      PCHECK(errno == EINVAL) << "Failed to mark UNMERGEABLE";
    }

    // Make this mapping available to child processes but don't copy data from
    // the secure object's pages during fork. With MADV_DONTFORK, the
    // vma is not mapped in the child process which leads to segmentation
    // faults if the child process tries to access this address. For example,
    // if the parent process creates a SecureObject, forks() and the child
    // process tries to call the destructor at the virtual address.
    PCHECK(!madvise(buffer, buffer_size, MADV_WIPEONFORK));

    // Allocation was successful.
    return reinterpret_cast<T*>(buffer);
  }

  // Destroys object before deallocation.
  // After destroying the object, clears the contents of where the object was
  // stored.
  template <class U>
  void destroy(U* p) {
    // Return if the pointer is invalid.
    if (!p)
      return;
    p->~U();
    clear_contents(p, sizeof(U));
  }

  void deallocate(T* p, std::size_t n) {
    // Check if n can be theoretically deallocated.
    CHECK_LT(n, max_size());

    // Check if n = 0 or p is a nullptr: there's nothing to deallocate;
    if (n == 0 || !p)
      return;

    // Calculate the page-aligned buffer size.
    std::size_t buffer_size = CalculatePageAlignedBufferSize(n);

    clear_contents(p, buffer_size);
    munlock(p, buffer_size);
    munmap(p, buffer_size);
  }

 protected:
  // Zero-out all bytes in the allocated buffer.
  virtual void clear_contents(T* v, std::size_t n) {
    if (!v)
      return;
    // This is guaranteed not to be optimized out.
    SecureClearBytes(v, n);
  }

 private:
  // Return the system page size.
  static std::size_t CalculateSystemPageSize() {
    long ret = sysconf(_SC_PAGESIZE);  // NOLINT [runtime/int]
    CHECK_GT(ret, 0L);
    return ret;
  }

  // Return a cached system page size.
  static std::size_t SystemPageSize() {
    // Calculate the page size the first time we are called, and afterwards
    // use the precalculated results.
    static std::size_t result = CalculateSystemPageSize();
    return result;
  }

  // Calculates the page-aligned buffer size.
  std::size_t CalculatePageAlignedBufferSize(std::size_t n) {
    std::size_t page_size = SystemPageSize();
    std::size_t real_size = n * sizeof(value_type);
    std::size_t page_aligned_remainder = real_size % page_size;
    std::size_t padding =
        page_aligned_remainder != 0 ? page_size - page_aligned_remainder : 0;
    return real_size + padding;
  }

  // Since the allocator reuses page size and max size consistently,
  // cache these values initially and reuse.
  static std::size_t GetMaxSizeForType(std::size_t page_size) {
    // Initialize max size that can be theoretically allocated.
    // Calculate the max size that is page-aligned.
    std::size_t max_theoretical_size = std::numeric_limits<std::size_t>::max();
    std::size_t max_page_aligned_size =
        max_theoretical_size - (max_theoretical_size % page_size);

    return max_page_aligned_size / sizeof(value_type);
  }
};

// Allocators are equal if they are stateless. i.e., one allocator can
// deallocate objects created by another allocator.
// See https://en.cppreference.com/w/cpp/memory/allocator/operator_cmp.
// TODO(https://issuetracker.google.com/173431121): It seems like this should be
// removed with C++17's std::allocator_traits::is_always_equal trait, but it
// is still used by std::vector:
// https://github.com/llvm/llvm-project/blob/67fa016ac1e24cd0f32a43d6d2ed43e347f1e74b/libcxx/include/vector#L1370
template <class T, class U>
bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept {
  return true;
}

template <class T, class U>
bool operator!=(const SecureAllocator<T>& x,
                const SecureAllocator<U>& y) noexcept {
  return !(x == y);
}

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_SECURE_ALLOCATOR_H_
