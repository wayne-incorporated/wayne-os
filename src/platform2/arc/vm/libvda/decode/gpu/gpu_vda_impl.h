// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_DECODE_GPU_GPU_VDA_IMPL_H_
#define ARC_VM_LIBVDA_DECODE_GPU_GPU_VDA_IMPL_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/threading/thread.h>
#include <base/threading/thread_checker.h>

#include "arc/vm/libvda/decode_wrapper.h"
#include "arc/vm/libvda/gpu/mojom/video.mojom.h"
#include "arc/vm/libvda/gpu/vaf_connection.h"

namespace base {
class WaitableEvent;
}  // namespace base

namespace arc {

// GpuVdaImpl uses a mojo connection to the VideoDecodeAccelerator interface
// to perform video decoding.
class GpuVdaImpl : public VdaImpl {
 public:
  explicit GpuVdaImpl(VafConnection* conn);
  ~GpuVdaImpl();

  // VdaImpl overrides.
  VdaContext* InitDecodeSession(vda_profile_t profile) override;
  void CloseDecodeSession(VdaContext* context) override;

  // Creates and returns a pointer to a GpuVdaImpl object. This returns a raw
  // pointer instead of a unique_ptr since this will eventually be returned to a
  // C interface. This object should be destroyed with the 'delete' operator
  // when no longer used.
  static GpuVdaImpl* Create(VafConnection* conn);

 private:
  std::vector<vda_input_format_t> GetSupportedInputFormats();
  bool PopulateCapabilities();
  bool Initialize();
  void InitializeOnIpcThread(bool* init_success);
  void InitDecodeSessionOnIpcThread(vda_profile_t profile,
                                    base::WaitableEvent* init_complete_event,
                                    VdaContext** out_context);
  void InitDecodeSessionAfterContextInitializedOnIpcThread(
      base::WaitableEvent* init_complete_event,
      VdaContext** out_context,
      std::unique_ptr<VdaContext> context,
      vda_result_t result);
  void CloseDecodeSessionOnIpcThread(VdaContext* context);

  arc::VafConnection* const connection_;
  std::vector<vda_input_format_t> input_formats_;
  std::vector<vda_pixel_format_t> output_formats_;
  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  THREAD_CHECKER(ipc_thread_checker_);
};

}  // namespace arc

#endif  // ARC_VM_LIBVDA_DECODE_GPU_GPU_VDA_IMPL_H_
