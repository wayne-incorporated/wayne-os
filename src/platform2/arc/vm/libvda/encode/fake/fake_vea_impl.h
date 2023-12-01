// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_ENCODE_FAKE_FAKE_VEA_IMPL_H_
#define ARC_VM_LIBVDA_ENCODE_FAKE_FAKE_VEA_IMPL_H_

#include "arc/vm/libvda/encode_wrapper.h"

namespace arc {

// A fake implementation that can start fake encode sessions. Users can
// initialize this implementation to see verbose logs when each vea function is
// called.
class FakeVeaImpl : public VeaImpl {
 public:
  // VeaImpl overrides.
  VeaContext* InitEncodeSession(vea_config_t* config) override;
  void CloseEncodeSession(VeaContext* context) override;

  // Creates and returns a pointer to a FakeVeaImpl object. This returns a raw
  // pointer instead of a unique_ptr since this will eventually be returned to a
  // C interface. This object should be destroyed with the 'delete' operator
  // when no longer used.
  static FakeVeaImpl* Create();

 private:
  FakeVeaImpl();
  FakeVeaImpl(const FakeVeaImpl&) = delete;
  FakeVeaImpl& operator=(const FakeVeaImpl&) = delete;

  video_pixel_format_t input_format_;
  vea_profile_t output_format_;
};

}  // namespace arc

#endif  // ARC_VM_LIBVDA_ENCODE_FAKE_FAKE_VEA_IMPL_H_
