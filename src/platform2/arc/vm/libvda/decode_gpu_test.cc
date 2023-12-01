// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/writable_shared_memory_region.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_util.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <gtest/gtest.h>

#include "arc/vm/libvda/decode/test/decode_event_thread.h"
#include "arc/vm/libvda/decode/test/decode_unittest_common.h"
#include "arc/vm/libvda/decode/test/encoded_data_helper.h"
#include "arc/vm/libvda/libvda_decode.h"

namespace {

// Maximum number of running decodes.
constexpr uint32_t kMaxDecodes = 20;

base::FilePath GetTestVideoFilePath(const base::CommandLine* cmd_line) {
  base::FilePath path = cmd_line->GetSwitchValuePath("test_video_file");
  if (path.empty())
    path = base::FilePath("test-25fps.h264");
  if (!path.IsAbsolute())
    path = base::MakeAbsoluteFilePath(path);
  return path;
}

vda_profile_t GetVideoFileProfile(const base::FilePath& video_file) {
  const std::string& extension = video_file.Extension();

  if (base::EqualsCaseInsensitiveASCII(extension, ".h264"))
    return H264PROFILE_MAIN;
  if (base::EqualsCaseInsensitiveASCII(extension, ".vp8"))
    return VP8PROFILE_ANY;
  if (base::EqualsCaseInsensitiveASCII(extension, ".vp9"))
    return VP9PROFILE_MIN;

  LOG(ERROR) << "Unsupported file extension: " << extension;
  return VIDEO_CODEC_PROFILE_UNKNOWN;
}

bool WaitForDecodesDone(arc::test::DecodeEventThread* event_thread,
                        uint32_t* waiting_decodes,
                        uint32_t max_decodes) {
  constexpr base::TimeDelta wait_interval = base::Milliseconds(5);
  constexpr base::TimeDelta max_wait_time = base::Seconds(5);
  base::ElapsedTimer wait_timer;
  while (wait_timer.Elapsed() < max_wait_time) {
    *waiting_decodes -=
        event_thread->GetAndClearEndOfBitstreamBufferEventCount();
    if (*waiting_decodes <= max_decodes)
      return true;
    base::PlatformThread::Sleep(wait_interval);
  }
  return false;
}

}  // namespace

class LibvdaGpuTest : public ::testing::Test {
 public:
  LibvdaGpuTest() = default;
  LibvdaGpuTest(const LibvdaGpuTest&) = delete;
  LibvdaGpuTest& operator=(const LibvdaGpuTest&) = delete;

  ~LibvdaGpuTest() override = default;
};

// Test that the gpu implementation initializes and deinitializes successfully.
TEST_F(LibvdaGpuTest, InitializeGpu) {
  ImplPtr impl = SetupImpl(GAVDA);
  ASSERT_NE(impl, nullptr);
}

// Test that the GPU implementation creates and closes a decode session
// successfully.
TEST_F(LibvdaGpuTest, InitDecodeSessionGpu) {
  ImplPtr impl = SetupImpl(GAVDA);
  ASSERT_NE(impl, nullptr);
  SessionPtr session = SetupSession(impl, H264PROFILE_MAIN);
  ASSERT_NE(session, nullptr);
  EXPECT_NE(session->ctx, nullptr);
  EXPECT_GT(session->event_pipe_fd, 0);
}

// Test that the gpu implementation has valid input and output capabilities.
TEST_F(LibvdaGpuTest, GetCapabilitiesGpu) {
  ImplPtr impl = SetupImpl(GAVDA);
  ASSERT_NE(impl, nullptr);
  const vda_capabilities_t* capabilities = get_vda_capabilities(impl.get());
  EXPECT_GT(capabilities->num_input_formats, 0);
  EXPECT_NE(capabilities->input_formats, nullptr);
  EXPECT_GT(capabilities->num_output_formats, 0);
  EXPECT_NE(capabilities->output_formats, nullptr);
}

// Tests the full decode flow using a provided video file. This tests several
// things:
// - shmem data can successfully be passed using vda_decode.
// - dmabuf handles can successfully be passed using vda_use_output_buffer.
// - PictureReady, ProvidePictureBuffers, NotifyEndOfBitstreamBuffer events are
//   successfully propagated.
TEST_F(LibvdaGpuTest, DecodeFileGpu) {
  const base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  ASSERT_NE(cmd_line, nullptr);

  base::FilePath test_video_file(GetTestVideoFilePath(cmd_line));
  ASSERT_TRUE(!test_video_file.empty());

  // TODO(alexlau): Check more parameters (num frames, fragments, fps) similar
  // to VDA tests, perhaps reading from JSON file.
  vda_profile_t file_profile = GetVideoFileProfile(test_video_file);
  ASSERT_NE(file_profile, VIDEO_CODEC_PROFILE_UNKNOWN);

  int64_t file_size;
  ASSERT_EQ(base::GetFileSize(test_video_file, &file_size), true);
  ASSERT_GT(file_size, 0);

  VLOG(3) << "Test file: " << test_video_file.value()
          << ", VDA profile: " << file_profile << ", file size: " << file_size;

  std::vector<uint8_t> data(file_size);
  ASSERT_EQ(
      base::ReadFile(test_video_file, reinterpret_cast<char*>(data.data()),
                     base::checked_cast<int>(file_size)),
      file_size);

  ImplPtr impl = SetupImpl(GAVDA);
  ASSERT_NE(impl, nullptr);
  SessionPtr session = SetupSession(impl, file_profile);
  ASSERT_NE(session, nullptr);

  const vda_capabilities_t* capabilities = get_vda_capabilities(impl.get());
  EXPECT_GT(capabilities->num_input_formats, 0);
  EXPECT_NE(capabilities->input_formats, nullptr);
  EXPECT_GT(capabilities->num_output_formats, 0);
  EXPECT_NE(capabilities->output_formats, nullptr);

  arc::test::DecodeEventThread event_thread(capabilities, session.get());
  event_thread.Start();

  EncodedDataHelper encoded_data_helper(data, file_profile);

  int32_t next_bitstream_id = 1;
  uint32_t waiting_decodes = 0;
  while (!encoded_data_helper.ReachEndOfStream()) {
    std::string data = encoded_data_helper.GetBytesForNextData();
    size_t data_size = data.size();
    ASSERT_NE(data_size, 0);

    base::WritableSharedMemoryRegion shm_region =
        base::WritableSharedMemoryRegion::Create(data_size);
    base::WritableSharedMemoryMapping shm_mapping = shm_region.Map();

    base::subtle::PlatformSharedMemoryRegion platform_shm =
        base::WritableSharedMemoryRegion::TakeHandleForSerialization(
            std::move(shm_region));

    memcpy(shm_mapping.GetMemoryAs<uint8_t>(), data.data(), data_size);

    base::ScopedFD handle(std::move(platform_shm.PassPlatformHandle().fd));
    ASSERT_GT(handle.get(), 0);

    int32_t bitstream_id = next_bitstream_id;
    next_bitstream_id = (next_bitstream_id + 1) & 0x3FFFFFFF;
    // Pass ownership of handle to vda_decode.
    vda_decode(session->ctx, bitstream_id, handle.release(), 0 /* offset */,
               data_size /* bytes_used */);
    waiting_decodes++;

    if (waiting_decodes > kMaxDecodes) {
      VLOG(3) << "Waiting for some decodes to finish, currently at "
              << waiting_decodes;
      ASSERT_TRUE(
          WaitForDecodesDone(&event_thread, &waiting_decodes, kMaxDecodes));
      VLOG(3) << "Some decodes finished, currently at " << waiting_decodes;
    }
  }

  if (waiting_decodes > 0) {
    VLOG(3) << "Waiting for remaining decodes to finish.";
    ASSERT_TRUE(WaitForDecodesDone(&event_thread, &waiting_decodes, 0));
    VLOG(3) << "Remaining decodes have finished.";
  }
}

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  logging::InitLogging(logging::LoggingSettings());

  base::ShadowingAtExitManager at_exit_manager_;

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
