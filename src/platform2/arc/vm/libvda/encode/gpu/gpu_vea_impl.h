// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_ENCODE_GPU_GPU_VEA_IMPL_H_
#define ARC_VM_LIBVDA_ENCODE_GPU_GPU_VEA_IMPL_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/threading/thread.h>
#include <base/threading/thread_checker.h>

#include "arc/vm/libvda/encode_wrapper.h"
#include "arc/vm/libvda/gpu/mojom/video.mojom.h"
#include "arc/vm/libvda/gpu/vaf_connection.h"

namespace base {
class WaitableEvent;
}  // namespace base

namespace arc {

// GpuVdaImpl connects to GpuArcVideoEncodeAccelerator using the LibvdaService
// D-Bus service LibvdaService and Mojo to perform video encoding.
class GpuVeaImpl : public VeaImpl {
 public:
  explicit GpuVeaImpl(VafConnection* conn);
  ~GpuVeaImpl();

  // VeaImpl overrides.
  VeaContext* InitEncodeSession(vea_config_t* config) override;
  void CloseEncodeSession(VeaContext* context) override;

  // Creates and returns a pointer to a GpuVeaImpl object. This returns a raw
  // pointer instead of a unique_ptr since this will eventually be returned to a
  // C interface. This object should be destroyed with the 'delete' operator
  // when no longer used.
  static GpuVeaImpl* Create(VafConnection* conn);

 private:
  bool Initialize();
  void InitializeOnIpcThread(base::WaitableEvent* init_complete_event);
  void OnGetSupportedProfiles(
      mojo::Remote<arc::mojom::VideoEncodeAccelerator> remote_vea,
      base::WaitableEvent* init_complete_event,
      std::vector<arc::mojom::VideoEncodeProfilePtr> profiles);
  void InitEncodeSessionOnIpcThread(vea_config_t* config,
                                    base::WaitableEvent* init_complete_event,
                                    VeaContext** out_context);
  void InitEncodeSessionAfterContextInitializedOnIpcThread(
      base::WaitableEvent* init_complete_event,
      VeaContext** out_context,
      std::unique_ptr<VeaContext> context,
      bool success);
  void CloseEncodeSessionOnIpcThread(VeaContext* context);

  arc::VafConnection* const connection_;
  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  THREAD_CHECKER(ipc_thread_checker_);

  std::vector<video_pixel_format_t> input_formats_;
  std::vector<vea_profile_t> output_formats_;
};

}  // namespace arc

#endif  // ARC_VM_LIBVDA_ENCODE_GPU_GPU_VEA_IMPL_H_
