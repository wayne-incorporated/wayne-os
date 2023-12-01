/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_JPEG_JPEG_ENCODE_ACCELERATOR_IMPL_H_
#define CAMERA_COMMON_JPEG_JPEG_ENCODE_ACCELERATOR_IMPL_H_

#include <stdint.h>
#include <memory>
#include <unordered_map>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/memory/writable_shared_memory_region.h>
#include <base/threading/thread.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "camera/mojo/cros_camera_service.mojom.h"
#include "camera/mojo/gpu/jpeg_encode_accelerator.mojom.h"
#include "cros-camera/camera_mojo_channel_manager.h"
#include "cros-camera/future.h"
#include "cros-camera/jpeg_compressor.h"
#include "cros-camera/jpeg_encode_accelerator.h"

namespace cros {

// Encapsulates a converter from JPEG to YU12 format.
// Before using this class, make sure mojo is initialized first.
class JpegEncodeAcceleratorImpl : public JpegEncodeAccelerator {
 public:
  explicit JpegEncodeAcceleratorImpl(CameraMojoChannelManager* mojo_manager);
  JpegEncodeAcceleratorImpl(const JpegEncodeAcceleratorImpl&) = delete;
  JpegEncodeAcceleratorImpl& operator=(const JpegEncodeAcceleratorImpl&) =
      delete;

  ~JpegEncodeAcceleratorImpl() override;

  // JpegEncodeAccelerator implementation.

  bool Start() override;

  // To be deprecated.
  int EncodeSync(int input_fd,
                 const uint8_t* input_buffer,
                 uint32_t input_buffer_size,
                 int32_t coded_size_width,
                 int32_t coded_size_height,
                 const uint8_t* exif_buffer,
                 uint32_t exif_buffer_size,
                 int output_fd,
                 uint32_t output_buffer_size,
                 uint32_t* output_data_size) override;

  int EncodeSync(uint32_t input_format,
                 const std::vector<JpegCompressor::DmaBufPlane>& input_planes,
                 const std::vector<JpegCompressor::DmaBufPlane>& output_planes,
                 const uint8_t* exif_buffer,
                 uint32_t exif_buffer_size,
                 int width,
                 int height,
                 int quality,
                 uint64_t input_modifier,
                 uint32_t* output_data_size) override;

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

    // Process encode request in IPC thread.
    // Either |input_fd| or |input_buffer| has to be filled up.
    void EncodeLegacy(int32_t task_id,
                      int input_fd,
                      const uint8_t* input_buffer,
                      uint32_t input_buffer_size,
                      int32_t coded_size_width,
                      int32_t coded_size_height,
                      const uint8_t* exif_buffer,
                      uint32_t exif_buffer_size,
                      int output_fd,
                      uint32_t output_buffer_size,
                      EncodeWithFDCallback callback);

    // Process encode request in IPC thread.
    void Encode(int32_t task_id,
                uint32_t input_format,
                const std::vector<JpegCompressor::DmaBufPlane>& input_planes,
                const std::vector<JpegCompressor::DmaBufPlane>& output_planes,
                const uint8_t* exif_buffer,
                uint32_t exif_buffer_size,
                int coded_size_width,
                int coded_size_height,
                int quality,
                uint64_t input_modifier,
                EncodeWithDmaBufCallback callback);

    // For synced Encode API.
    void EncodeSyncCallback(base::OnceCallback<void(int)> callback,
                            uint32_t* output_data_size,
                            int32_t task_id,
                            uint32_t output_size,
                            int status);

    // Gets a weak pointer of the IPCBridge. This method can be called on
    // non-IPC thread.
    base::WeakPtr<IPCBridge> GetWeakPtr();

    // Return true if the mojo channel is ready to use. This method can be
    // called on non-IPC thread.
    bool IsReady();

   private:
    // Initialize the JpegEncodeAccelerator.
    void Initialize(base::OnceCallback<void(bool)> callback);

    // Error handler for JEA mojo channel.
    void OnJpegEncodeAcceleratorError();

    // Callback function for |jea_|->EncodeWithFD().
    void OnEncodeAck(EncodeWithFDCallback callback,
                     int32_t task_id,
                     uint32_t output_size,
                     cros::mojom::EncodeStatus status);

    // Callback function for |jea_|->EncodeWithDmaBuf().
    void OnEncodeDmaBufAck(EncodeWithDmaBufCallback callback,
                           uint32_t output_size,
                           cros::mojom::EncodeStatus status);

    // Camera Mojo channel manager.
    // We use it to create JpegEncodeAccelerator Mojo channel.
    CameraMojoChannelManager* mojo_manager_;

    // Used to cancel pending futures when error occurs.
    CancellationRelay* cancellation_relay_;

    // The Mojo IPC task runner.
    const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;

    // Pointer to local proxy of remote JpegEncodeAccelerator interface
    // implementation.
    // All the Mojo communication to |jea_| happens on |ipc_task_runner_|.
    mojo::Remote<mojom::JpegEncodeAccelerator> jea_;

    // A map from buffer id to input and exif shared memory.
    // |input_shm_map_| and |exif_shm_map_| should only be accessed on
    // |ipc_task_runner_|.
    // Since the input buffer may be from DMA buffer, we need to prepare a
    // shared memory for JpegEncodeAccelerator interface. We will send the
    // handles of the shared memory to the remote process, so we need to keep
    // the shared memory referenced until we receive EncodeAck.

    base::WeakPtrFactory<IPCBridge> weak_ptr_factory_{this};
  };

  // The id for current encode task.
  int32_t task_id_;

  // Mojo manager which is used for Mojo communication.
  CameraMojoChannelManager* mojo_manager_;

  // Used to cancel pending futures when error occurs.
  std::unique_ptr<CancellationRelay> cancellation_relay_;

  // The instance which deals with the IPC-related calls. It should always run
  // and be deleted on IPC thread.
  std::unique_ptr<IPCBridge> ipc_bridge_;
};

}  // namespace cros
#endif  // CAMERA_COMMON_JPEG_JPEG_ENCODE_ACCELERATOR_IMPL_H_
