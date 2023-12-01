// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/decode/fake/fake_vda_impl.h"

#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/stl_util.h>

namespace arc {
namespace {

constexpr vda_input_format_t kInputFormats[] = {{.profile = VP8PROFILE_MIN,
                                                 .min_width = 1,
                                                 .min_height = 1,
                                                 .max_width = 1920,
                                                 .max_height = 1080},
                                                {.profile = VP9PROFILE_PROFILE0,
                                                 .min_width = 1,
                                                 .min_height = 1,
                                                 .max_width = 1920,
                                                 .max_height = 1080},
                                                {.profile = H264PROFILE_MAIN,
                                                 .min_width = 1,
                                                 .min_height = 1,
                                                 .max_width = 1920,
                                                 .max_height = 1080}};

constexpr vda_pixel_format_t kOutputFormats[] = {YV12, NV12};

// A fake decode session context which will propagate fake PICTURE_READY events
// in response to decode events.
// TODO(alexlau): Consider supporting testing of vda_use_output_buffer and
//                dispatching additional events, with working bitstream and
//                picture ids.
class FakeContext : public VdaContext {
 public:
  FakeContext();
  FakeContext(const FakeContext&) = delete;
  FakeContext& operator=(const FakeContext&) = delete;

  // VdaContext overrides.
  vda_result_t Decode(int32_t bitstream_id,
                      base::ScopedFD fd,
                      uint32_t offset,
                      uint32_t bytes_used) override;
  vda_result_t SetOutputBufferCount(size_t num_output_buffers) override;
  vda_result_t UseOutputBuffer(int32_t picture_buffer_id,
                               vda_pixel_format_t format,
                               base::ScopedFD fd,
                               size_t num_planes,
                               video_frame_plane_t* planes,
                               uint64_t modifier) override;
  vda_result_t ReuseOutputBuffer(int32_t picture_buffer_id) override;
  vda_result_t Reset() override;
  vda_result_t Flush() override;
};

FakeContext::FakeContext() = default;

vda_result_t FakeContext::Decode(int32_t bitstream_id,
                                 base::ScopedFD fd,
                                 uint32_t offset,
                                 uint32_t bytes_used) {
  LOG(INFO) << "FakeContext::Decode called with bitstream id=" << bitstream_id
            << " fd=" << fd.get() << " offset=" << offset
            << " bytes_used=" << bytes_used;

  DispatchPictureReady(1 /* picture_buffer_id */, bitstream_id,
                       0 /* crop_left */, 0 /* crop_top */, 0 /* crop_right */,
                       0 /* crop_bottom */);

  return SUCCESS;
}

vda_result_t FakeContext::SetOutputBufferCount(size_t num_output_buffers) {
  LOG(INFO)
      << "FakeContext::SetOutputBufferCount called with num_output_buffers "
      << num_output_buffers;
  return SUCCESS;
}

vda_result_t FakeContext::UseOutputBuffer(int32_t picture_buffer_id,
                                          vda_pixel_format_t format,
                                          base::ScopedFD fd,
                                          size_t num_planes,
                                          video_frame_plane_t* planes,
                                          uint64_t modifier) {
  LOG(INFO) << "FakeContext::UseOutputBuffer called with picture_buffer_id="
            << picture_buffer_id << " format=" << format << " fd=" << fd.get()
            << " num_planes=" << num_planes << " modifier=" << modifier;

  return SUCCESS;
}

vda_result_t FakeContext::ReuseOutputBuffer(int32_t picture_buffer_id) {
  LOG(INFO) << "FakeContext::ReuseOutputBuffer called with picture_buffer_id="
            << picture_buffer_id;
  return SUCCESS;
}

vda_result FakeContext::Reset() {
  LOG(INFO) << "FakeContext::Reset called";
  DispatchResetResponse(SUCCESS);
  return SUCCESS;
}

vda_result FakeContext::Flush() {
  LOG(INFO) << "FakeContext::Flush called";
  DispatchFlushResponse(SUCCESS);
  return SUCCESS;
}

}  // namespace

FakeVdaImpl::FakeVdaImpl() {
  LOG(INFO) << "Creating new fake implementation.";
  capabilities_.num_input_formats = std::size(kInputFormats);
  capabilities_.input_formats = kInputFormats;
  capabilities_.num_output_formats = std::size(kOutputFormats);
  capabilities_.output_formats = kOutputFormats;
}

VdaContext* FakeVdaImpl::InitDecodeSession(vda_profile_t profile) {
  LOG(INFO) << "FakeVdaImpl::InitDecodeSession called with profile=" << profile;
  return new FakeContext();
}

void FakeVdaImpl::CloseDecodeSession(VdaContext* context) {
  LOG(INFO) << "FakeVdaImpl::CloseDecodeSession";
  delete context;
}

// static
FakeVdaImpl* FakeVdaImpl::Create() {
  return new FakeVdaImpl();
}

}  // namespace arc
