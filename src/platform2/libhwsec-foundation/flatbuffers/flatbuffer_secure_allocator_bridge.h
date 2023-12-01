// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_FLATBUFFERS_FLATBUFFER_SECURE_ALLOCATOR_BRIDGE_H_
#define LIBHWSEC_FOUNDATION_FLATBUFFERS_FLATBUFFER_SECURE_ALLOCATOR_BRIDGE_H_

#include <brillo/secure_allocator.h>
#include <flatbuffers/flatbuffers.h>

namespace hwsec_foundation {

// This class wraps the SecureAllocator in a flatbuffers::Allocator interface,
// allowing flatbuffers to be put into eraseable memory.
class FlatbufferSecureAllocatorBridge : public flatbuffers::Allocator {
 public:
  uint8_t* allocate(size_t size) override { return allocator_.allocate(size); }

  void deallocate(uint8_t* p, size_t size) override {
    return allocator_.deallocate(p, size);
  }

 private:
  brillo::SecureAllocator<uint8_t> allocator_;
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_FLATBUFFERS_FLATBUFFER_SECURE_ALLOCATOR_BRIDGE_H_
