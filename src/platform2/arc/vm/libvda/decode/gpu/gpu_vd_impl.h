// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_DECODE_GPU_GPU_VD_IMPL_H_
#define ARC_VM_LIBVDA_DECODE_GPU_GPU_VD_IMPL_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/threading/thread.h>
#include <base/threading/thread_checker.h>

#include "arc/vm/libvda/decode_wrapper.h"
#include "arc/vm/libvda/gpu/mojom/video.mojom.h"
#include "arc/vm/libvda/gpu/vaf_connection.h"

namespace base {
class WaitableEvent;
}  // namespace base

namespace arc {

// GpuVdImpl uses a mojo connection to the VideoDecoder interface to perform
// video decoding.
class GpuVdImpl : public VdaImpl {
 public:
  // Creates and returns a pointer to a GpuVdImpl object. This returns a raw
  // pointer instead of a unique_ptr since this will eventually be returned to a
  // C interface. This object should be destroyed with the 'delete' operator
  // when no longer used.
  static GpuVdImpl* Create(VafConnection* conn);

  ~GpuVdImpl();

  // VdaImpl overrides.
  VdaContext* InitDecodeSession(vda_profile_t profile) override;
  void CloseDecodeSession(VdaContext* context) override;

 private:
  explicit GpuVdImpl(VafConnection* conn);

  std::vector<vda_input_format_t> GetSupportedInputFormats();
  bool PopulateCapabilities();
  void InitDecodeSessionOnIpcThread(vda_profile_t profile,
                                    base::WaitableEvent* init_complete_event,
                                    VdaContext** out_context);
  void InitDecodeSessionAfterContextInitializedOnIpcThread(
      base::WaitableEvent* init_complete_event,
      VdaContext** out_context,
      std::unique_ptr<VdaContext> context,
      vd_decoder_status_t status);
  void CloseDecodeSessionOnIpcThread(VdaContext* context);

  arc::VafConnection* const connection_;
  std::vector<vda_input_format_t> input_formats_;
  std::vector<vda_pixel_format_t> output_formats_;
  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  THREAD_CHECKER(ipc_thread_checker_);

  base::WeakPtr<GpuVdImpl> weak_this_;
  base::WeakPtrFactory<GpuVdImpl> weak_this_factory_{this};
};

}  // namespace arc

#endif  // ARC_VM_LIBVDA_DECODE_GPU_GPU_VD_IMPL_H_
