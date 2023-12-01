// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_DECODE_TEST_DECODE_EVENT_THREAD_H_
#define ARC_VM_LIBVDA_DECODE_TEST_DECODE_EVENT_THREAD_H_

#include <stdint.h>

#include <map>
#include <memory>

#include <base/atomicops.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <base/threading/thread.h>

#include "arc/vm/libvda/gbm_util.h"
#include "arc/vm/libvda/libvda_decode.h"

namespace arc {
namespace test {

// DecodeEventThread provides a thread that will handle VDA events
// read from the session event file descriptor.
class DecodeEventThread {
 public:
  DecodeEventThread(const vda_capabilities_t* caps,
                    const vda_session_info_t* session);
  DecodeEventThread(const DecodeEventThread&) = delete;
  DecodeEventThread& operator=(const DecodeEventThread&) = delete;

  ~DecodeEventThread();

  // Starts the thread and the event loop to handle the provided capabilities.
  // The event loop is stopped in the destructor.
  void Start();

  // Returns the number of received NOTIFY_END_OF_BITSTREAM_BUFFER
  // events and resets the counter.
  uint32_t GetAndClearEndOfBitstreamBufferEventCount();

 private:
  // Stops listening for events and stops |thread_|.
  void Stop();

  // Starts watching the event pipe for VDA events. Called on |thread_|.
  void StartWatching();

  // Stops watching the event pipe. Called on |thread_|.
  void StopWatching();

  // Callback function when the event pipe is readable. Called on |thread_|.
  void OnEventPipeReadable();

  // Handles for PICTURE_READY events. Called on |thread_|.
  void OnPictureReady(const picture_ready_event_data_t& data);

  // Handles PROVIDE_PICTURE_BUFFER events. Called on |thread_|.
  void OnProvidePictureBuffers(
      const provide_picture_buffers_event_data_t& data);

  // Handles NOTIFY_END_OF_BITSTREAM_BUFFER events. Called on |thread_|.
  void OnNotifyEndOfBitstreamBuffer(int32_t bitstream_id);

  // Helper that calls vda_use_output_buffer with the |bo| object. Called on
  // |thread_|.
  void CallUseOutputBuffer(int32_t picture_buffer_id, gbm_bo* bo);

  base::Thread thread_;
  THREAD_CHECKER(thread_checker_);

  arc::ScopedGbmDevice gbm_device_;
  const vda_capabilities_t* const caps_;
  vda_pixel_format_t vda_format_;
  uint32_t gbm_format_;
  const vda_session_info_t* const session_;

  std::unique_ptr<base::FileDescriptorWatcher::Controller>
      event_pipe_fd_controller_;

  std::map<int32_t, arc::ScopedGbmBoPtr> picture_buffer_id_to_bo_map_;

  uint32_t end_of_bitstream_buffer_event_count_;
  base::Lock end_of_bitstream_buffer_event_count_lock_;

  base::WeakPtrFactory<DecodeEventThread> weak_factory_{this};
};

}  // namespace test
}  // namespace arc

#endif  // ARC_VM_LIBVDA_DECODE_TEST_DECODE_EVENT_THREAD_H_
