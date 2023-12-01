// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_GPU_VAF_CONNECTION_H_
#define ARC_VM_LIBVDA_GPU_VAF_CONNECTION_H_

#include <memory>
#include <string>
#include <vector>

#include <base/threading/thread.h>
#include <base/threading/thread_checker.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "arc/vm/libvda/gpu/mojom/video.mojom.h"

namespace arc {

void RunTaskOnThread(scoped_refptr<base::SingleThreadTaskRunner> task_runner,
                     base::OnceClosure task);

// VafConnection provides a connection to the mojo VideoAcceleratorFactory
// interface using the LibvdaService D-Bus service. Only a single instantiated
// VafConnection object should exist at a time. Callers can use the
// GetVafConnection() function to retrieve an instance.
class VafConnection {
 public:
  ~VafConnection();
  scoped_refptr<base::SingleThreadTaskRunner> GetIpcTaskRunner();
  mojo::Remote<arc::mojom::VideoDecodeAccelerator> CreateDecodeAccelerator();
  mojo::Remote<arc::mojom::VideoDecoder> CreateVideoDecoder();
  mojo::Remote<arc::mojom::VideoEncodeAccelerator> CreateEncodeAccelerator();

  // Returns a VafConnection instance.
  static VafConnection* Get();

 private:
  VafConnection();
  bool Initialize();
  void InitializeOnIpcThread(bool* init_success);
  void CleanupOnIpcThread();
  void OnFactoryError(uint32_t custom_reason, const std::string& description);
  void CreateDecodeAcceleratorOnIpcThread(
      mojo::Remote<arc::mojom::VideoDecodeAccelerator>* remote_vda);
  void CreateVideoDecoderOnIpcThread(
      mojo::Remote<arc::mojom::VideoDecoder>* remote_vd);
  void CreateEncodeAcceleratorOnIpcThread(
      mojo::Remote<arc::mojom::VideoEncodeAccelerator>* remote_vea);

  base::Thread ipc_thread_;
  // TODO(alexlau): Use THREAD_CHECKER macro after libchrome uprev
  // (crbug.com/909719).
  THREAD_CHECKER(ipc_thread_checker_);
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  mojo::Remote<arc::mojom::VideoAcceleratorFactory> remote_factory_;
};

}  // namespace arc

#endif  // ARC_VM_LIBVDA_GPU_VAF_CONNECTION_H_
