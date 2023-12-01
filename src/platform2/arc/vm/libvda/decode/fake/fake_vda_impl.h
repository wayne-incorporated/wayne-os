// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_DECODE_FAKE_FAKE_VDA_IMPL_H_
#define ARC_VM_LIBVDA_DECODE_FAKE_FAKE_VDA_IMPL_H_

#include "arc/vm/libvda/decode_wrapper.h"

namespace arc {

// A fake implementation that can start fake decode sessions. Users can
// initialize this implementation to see verbose logs when each vda function is
// called.
class FakeVdaImpl : public VdaImpl {
 public:
  // VdaImpl overrides.
  VdaContext* InitDecodeSession(vda_profile_t profile) override;
  void CloseDecodeSession(VdaContext* context) override;

  // Creates and returns a pointer to a FakeVdaImpl object. This returns a raw
  // pointer instead of a unique_ptr since this will eventually be returned to a
  // C interface. This object should be destroyed with the 'delete' operator
  // when no longer used.
  static FakeVdaImpl* Create();

 private:
  FakeVdaImpl();
  FakeVdaImpl(const FakeVdaImpl&) = delete;
  FakeVdaImpl& operator=(const FakeVdaImpl&) = delete;
};

}  // namespace arc

#endif  // ARC_VM_LIBVDA_DECODE_FAKE_FAKE_VDA_IMPL_H_
