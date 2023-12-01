/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_JPEG_JPEG_DECODE_ACCELERATOR_IMPL_H_
#define CAMERA_COMMON_JPEG_JPEG_DECODE_ACCELERATOR_IMPL_H_

#include <stdint.h>
#include <memory>
#include <set>
#include <unordered_map>

#include <base/memory/writable_shared_memory_region.h>
#include <base/threading/thread.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "camera/mojo/cros_camera_service.mojom.h"
#include "cros-camera/camera_metrics.h"
#include "cros-camera/camera_mojo_channel_manager.h"
#include "cros-camera/future.h"
#include "cros-camera/jpeg_decode_accelerator.h"

namespace cros {

namespace tests {
class JpegDecodeAcceleratorTest;
}  // namespace tests

// Encapsulates a JPEG decoder. This class is not thread-safe.
// Before using this class, make sure mojo is initialized first.
class JpegDecodeAcceleratorImpl : public JpegDecodeAccelerator {
 public:
  explicit JpegDecodeAcceleratorImpl(CameraMojoChannelManager* mojo_manager);
  JpegDecodeAcceleratorImpl(const JpegDecodeAcceleratorImpl&) = delete;
  JpegDecodeAcceleratorImpl& operator=(const JpegDecodeAcceleratorImpl&) =
      delete;

  ~JpegDecodeAcceleratorImpl() override;

  // JpegDecodeAccelerator implementation.

  bool Start() override;

  JpegDecodeAccelerator::Error DecodeSync(
      int input_fd,
      uint32_t input_buffer_size,
      uint32_t input_buffer_offset,
      buffer_handle_t output_buffer) override;

  int32_t Decode(int input_fd,
                 uint32_t input_buffer_size,
                 uint32_t input_buffer_offset,
                 buffer_handle_t output_buffer,
                 DecodeCallback callback) override;

 private:
  // IPCBridge wraps all the IPC-related calls. Most of its methods should/will
  // be run on IPC thread.
  class IPCBridge {
   public:
    IPCBridge(CameraMojoChannelManager* mojo_manager,
              CancellationRelay* cancellation_relay);

    // It should only be triggered on IPC thread to ensure thread-safety.
    ~IPCBridge();

    // Initialize Mojo channel to GPU pcorss in chrome.
    void Start(base::OnceCallback<void(bool)> callback);

    // Destroy the instance.
    void Destroy();

    // Process decode request on IPC thread with output buffer_handle_t.
    void Decode(int32_t buffer_id,
                int input_fd,
                uint32_t input_buffer_size,
                uint32_t input_buffer_offset,
                buffer_handle_t output_buffer,
                DecodeCallback callback);

    // For synced Decode API.
    void DecodeSyncCallback(base::OnceCallback<void(int)> callback,
                            int32_t buffer_id,
                            int error);

    void TestResetJDAChannel(scoped_refptr<cros::Future<void>> future);

    // Gets a weak pointer of the IPCBridge. This method can be called on
    // non-IPC thread.
    base::WeakPtr<IPCBridge> GetWeakPtr();

    // Return true if the mojo channel is ready to use. This method can be
    // called on non-IPC thread.
    bool IsReady();

   private:
    // Initialize the JpegDecodeAccelerator.
    void Initialize(base::OnceCallback<void(bool)> callback);

    // Error handler for JDA mojo channel.
    void OnJpegDecodeAcceleratorError();

    // Callback function for |jda_|->DecodeWithDmaBuf().
    void OnDecodeAck(DecodeCallback callback,
                     int32_t buffer_id,
                     cros::mojom::DecodeError error);

    // Camera Mojo channel manager.
    // We use it to create JpegDecodeAccelerator Mojo channel.
    CameraMojoChannelManager* mojo_manager_;

    // Used to cancel pending futures when error occurs.
    CancellationRelay* cancellation_relay_;

    // The Mojo IPC task runner.
    const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;

    // Pointer to local proxy of remote JpegDecodeAccelerator interface
    // implementation.
    // All the Mojo communication to |jda_| happens on |ipc_task_runner_|.
    mojo::Remote<mojom::MjpegDecodeAccelerator> jda_;

    // Tracking the buffer ids sent to decoder.
    std::set<int32_t> inflight_buffer_ids_;

    base::WeakPtrFactory<IPCBridge> weak_ptr_factory_{this};
  };

  // To let test class access private testing methods.
  // e.g. ResetJDAChannel()
  friend class tests::JpegDecodeAcceleratorTest;

  // Reset JDA Mojo channel. It is used for testing.
  void TestResetJDAChannel();

  // The id for current buffer being decoded.
  int32_t buffer_id_;

  // Mojo manager which is used for Mojo communication.
  CameraMojoChannelManager* mojo_manager_;

  // Used to cancel pending futures when error occurs.
  std::unique_ptr<CancellationRelay> cancellation_relay_;

  // The instance which deals with the IPC-related calls. It should always run
  // and be deleted on IPC thread.
  std::unique_ptr<IPCBridge> ipc_bridge_;

  // Metrics that used to record things like decoding latency.
  std::unique_ptr<CameraMetrics> camera_metrics_;
};

}  // namespace cros
#endif  // CAMERA_COMMON_JPEG_JPEG_DECODE_ACCELERATOR_IMPL_H_
