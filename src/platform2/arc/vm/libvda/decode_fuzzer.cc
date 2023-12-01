// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>

#include <base/check.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/weak_ptr.h>
#include <base/memory/writable_shared_memory_region.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <base/threading/thread.h>

#include "arc/vm/libvda/decode/test/decode_unittest_common.h"
#include "arc/vm/libvda/libvda_decode.h"

namespace {

// Maximum supported output buffers is 32 as set here:
// https://codesearch.chromium.org/chromium/src/components/arc/video_accelerator/gpu_arc_video_decode_accelerator.cc?rcl=df1fede89a832a708df47f329e265bb3ff3366e3&l=49
constexpr size_t kMaxNumOutputBuffers = 32;

// Maximum number of planes per output buffer.
// TODO(alexlau): Increase this limit?
constexpr size_t kMaxPlanes = 4;

}  // namespace

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
  Environment(const Environment&) = delete;
  Environment& operator=(const Environment&) = delete;
};

class ReadEventThread {
 public:
  explicit ReadEventThread(int fd) : fd_(fd), thread_("ReadEventThread") {
    CHECK(thread_.StartWithOptions(
        base::Thread::Options(base::MessagePumpType::IO, 0)));
    thread_.task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&ReadEventThread::StartWatching,
                                  base::Unretained(this)));
  }
  ReadEventThread(const ReadEventThread&) = delete;
  ReadEventThread& operator=(const ReadEventThread&) = delete;

  ~ReadEventThread() {
    thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&ReadEventThread::StopWatching, base::Unretained(this)));
  }

 private:
  void StartWatching() {
    event_pipe_fd_controller_ = base::FileDescriptorWatcher::WatchReadable(
        fd_, base::BindRepeating(&ReadEventThread::OnEventPipeReadable,
                                 weak_factory_.GetWeakPtr()));
  }

  void StopWatching() { event_pipe_fd_controller_.reset(); }

  void OnEventPipeReadable() {
    // Read the events to make sure the pipe buffer doesn't become
    // completely full.
    // TODO(alexlau): Should these events be parsed and responded to?
    vda_event_t event;
    if (!base::ReadFromFD(fd_, reinterpret_cast<char*>(&event),
                          sizeof(vda_event_t))) {
      LOG(ERROR) << "Failed to read from event pipe.";
      return;
    }

    switch (event.event_type) {
      case PICTURE_READY: {
        const picture_ready_event_data_t& picture_ready =
            event.event_data.picture_ready;
        LOG(INFO) << "Received PICTURE_READY event with"
                  << " picture_buffer_id=" << picture_ready.picture_buffer_id
                  << " bitstream_id=" << picture_ready.bitstream_id
                  << " crop_left=" << picture_ready.crop_left
                  << " crop_top=" << picture_ready.crop_top
                  << " crop_right=" << picture_ready.crop_right
                  << " crop_bottom=" << picture_ready.crop_bottom;
        break;
      }
      case PROVIDE_PICTURE_BUFFERS: {
        const provide_picture_buffers_event_data_t& provide_picture_buffers =
            event.event_data.provide_picture_buffers;
        LOG(INFO) << "Received PROVIDE_PICTURE_BUFFERS event with"
                  << " min_num_buffers="
                  << provide_picture_buffers.min_num_buffers
                  << " width=" << provide_picture_buffers.width
                  << " height=" << provide_picture_buffers.height
                  << " visible_rect_left="
                  << provide_picture_buffers.visible_rect_left
                  << " visible_rect_top="
                  << provide_picture_buffers.visible_rect_top
                  << " visible_rect_right="
                  << provide_picture_buffers.visible_rect_right
                  << " visible_rect_bottom="
                  << provide_picture_buffers.visible_rect_bottom;
        break;
      }
      case NOTIFY_END_OF_BITSTREAM_BUFFER:
        LOG(INFO) << "Received NOTIFY_END_OF_BITSTREAM_BUFFER event with"
                  << " bitstream_id=" << event.event_data.bitstream_id;
        break;
      case NOTIFY_ERROR:
        LOG(INFO) << "Received NOTIFY_ERROR event with result="
                  << event.event_data.result;
        break;
      case RESET_RESPONSE:
        LOG(INFO) << "Received RESET_RESPONSE event with result="
                  << event.event_data.result;
        break;
      case FLUSH_RESPONSE:
        LOG(INFO) << "Received FLUSH_RESPONSE event with result="
                  << event.event_data.result;
        break;
      default:
        LOG(ERROR) << "Received unknown event type " << event.event_type;
        break;
    }
  }

  // Event pipe FD. SessionManager's |impl| retains ownership and will close it
  // when the decode session is stopped.
  int fd_;
  base::Thread thread_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller>
      event_pipe_fd_controller_;

  base::WeakPtrFactory<ReadEventThread> weak_factory_{this};
};

class ScopedSession {
 public:
  ScopedSession()
      : impl_(SetupImpl(GAVDA)),
        session_(SetupSession(impl_, H264PROFILE_MIN)) {}
  ScopedSession(const ScopedSession&) = delete;
  ScopedSession& operator=(const ScopedSession&) = delete;

  ~ScopedSession() { DestroyImpl(); }

  void RecreateImplAndSession() {
    DestroyImpl();
    impl_ = SetupImpl(GAVDA);
    RecreateSession();
  }

  void RecreateSession() {
    DestroySession();
    session_ = SetupSession(impl_, H264PROFILE_MIN);
    event_thread_ = std::make_unique<ReadEventThread>(session_->event_pipe_fd);
  }

  void* impl() { return impl_.get(); }

  void* ctx() { return session_.get()->ctx; }

 private:
  void DestroySession() {
    if (session_) {
      event_thread_.reset();
      session_.reset();
    }
  }

  void DestroyImpl() {
    DestroySession();
    if (impl_) {
      impl_.reset();
    }
  }

  ImplPtr impl_;
  SessionPtr session_;
  std::unique_ptr<ReadEventThread> event_thread_;
};

class DataReader {
 public:
  DataReader(const uint8_t* data, size_t size)
      : data_(data), size_(size), index_(0) {}
  DataReader(const DataReader&) = delete;
  DataReader& operator=(const DataReader&) = delete;

  uint8_t GetUint8() {
    if (index_ >= size_) {
      index_ = 0;
    }
    return data_[index_++];
  }

  uint32_t GetUint32() {
    // We don't care about endianness here, so ordering of the
    // retrieved bytes can be the same for both, as long as the
    // 32 bit integer is populated.
    uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
      value = (value << 8) | GetUint8();
    }
    return value;
  }

  int32_t GetInt32() {
    uint32_t value = GetUint32();
    int32_t* int_ptr = reinterpret_cast<int32_t*>(&value);
    return *int_ptr;
  }

  size_t GetSize() {
    static_assert(sizeof(size_t) >= 4,
                  "size_t is unexpectedly smaller than 32 bits.");
    return static_cast<size_t>(GetUint32());
  }

 private:
  const uint8_t* data_;
  size_t size_;
  size_t index_;
};

enum class VdaCommand : uint8_t {
  RECREATE_IMPL,
  RECREATE_SESSION,
  GET_CAPABILITIES,
  DECODE,
  SET_OUTPUT_BUFFER_COUNT,
  USE_OUTPUT_BUFFER,
  FLUSH,
  RESET,
  COMMAND_MAX = RESET
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  // |session_manager| is a static variable responsible for setting up the VDA
  // session, such that the same connection can be used across different
  // invocations of LLVMFuzzerTestOneInput.
  static ScopedSession session_manager;

  if (!size)
    return 0;

  DataReader reader(data, size);
  VdaCommand command = static_cast<VdaCommand>(
      reader.GetUint8() % (static_cast<uint8_t>(VdaCommand::COMMAND_MAX) + 1));
  LOG(INFO) << "Command: " << static_cast<uint8_t>(command);
  switch (command) {
    case VdaCommand::RECREATE_IMPL:
      session_manager.RecreateImplAndSession();
      break;

    case VdaCommand::RECREATE_SESSION:
      session_manager.RecreateSession();
      break;

    case VdaCommand::GET_CAPABILITIES:
      get_vda_capabilities(session_manager.impl());
      break;

    case VdaCommand::DECODE: {
      const int32_t bitstream_id = reader.GetInt32();
      const bool no_allocate_shm = reader.GetUint8() % 2 == 0;
      uint32_t offset = reader.GetUint32();
      uint32_t bytes_used = reader.GetUint32();
      int fd;
      if (no_allocate_shm) {
        fd = HANDLE_EINTR(open("/dev/urandom", O_RDONLY));
      } else {
        // When allocating, try not to run out of memory.
        offset %= 4096;
        bytes_used %= 4096;

        const size_t data_size = offset + bytes_used;

        base::WritableSharedMemoryRegion shm_region =
            base::WritableSharedMemoryRegion::Create(data_size);
        base::WritableSharedMemoryMapping shm_mapping = shm_region.Map();

        base::ScopedFD random_fd(HANDLE_EINTR(open("/dev/urandom", O_RDONLY)));
        HANDLE_EINTR(read(random_fd.get(), shm_mapping.memory(), data_size));

        base::subtle::PlatformSharedMemoryRegion platform_shm =
            base::WritableSharedMemoryRegion::TakeHandleForSerialization(
                std::move(shm_region));
        base::subtle::ScopedPlatformSharedMemoryHandle handle =
            platform_shm.PassPlatformHandle();
        fd = handle.fd.release();
      }
      // Ownership of the FD is passed. We don't hold the fd out of the output
      // buffer as we're not interested in the buffer content when fuzzing.
      vda_decode(session_manager.ctx(), bitstream_id, fd, offset, bytes_used);
      break;
    }

    case VdaCommand::SET_OUTPUT_BUFFER_COUNT: {
      size_t num_output_buffers = reader.GetSize();
      num_output_buffers = num_output_buffers % (kMaxNumOutputBuffers + 1);
      vda_set_output_buffer_count(session_manager.ctx(), num_output_buffers);
      break;
    }

    case VdaCommand::USE_OUTPUT_BUFFER: {
      // This is the same value as DRM_FORMAT_MOD_INVALID, which is not a valid
      // modifier.
      const uint64_t kNoModifier = 0x00ffffffffffffffULL;
      const int32_t picture_buffer_id = reader.GetInt32();
      const vda_pixel_format_t format = static_cast<vda_pixel_format_t>(
          reader.GetUint32() % (PIXEL_FORMAT_MAX + 1));
      // TODO(alexlau): Consider passing a real dmabuf?
      const int fd = HANDLE_EINTR(open("/dev/urandom", O_RDWR));
      const size_t num_planes = reader.GetSize() % (kMaxPlanes + 1);
      std::vector<video_frame_plane_t> planes(num_planes);
      for (auto& plane : planes) {
        plane.offset = reader.GetInt32();
        plane.stride = reader.GetInt32();
      }
      // Ownership of the FD is passed.
      vda_use_output_buffer(session_manager.ctx(), picture_buffer_id, format,
                            fd, num_planes, planes.data(), kNoModifier);
      break;
    }
    case VdaCommand::FLUSH: {
      vda_flush(session_manager.ctx());
      break;
    }
    case VdaCommand::RESET: {
      vda_reset(session_manager.ctx());
      break;
    }
    default:
      NOTREACHED();
  }

  return 0;
}
