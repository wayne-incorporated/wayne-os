// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/encode/fake/fake_vea_impl.h"

#include <base/files/scoped_file.h>
#include <base/logging.h>

namespace arc {
namespace {

class FakeVeaContext : public VeaContext {
 public:
  FakeVeaContext();
  FakeVeaContext(const FakeVeaContext&) = delete;
  FakeVeaContext& operator=(const FakeVeaContext&) = delete;

  // VeaContext overrides.
  int Encode(vea_input_buffer_id_t input_buffer_id,
             base::ScopedFD fd,
             size_t num_planes,
             video_frame_plane_t* planes,
             uint64_t timestamp,
             bool force_keyframe) override;

  int UseOutputBuffer(vea_output_buffer_id_t output_buffer_id,
                      base::ScopedFD fd,
                      uint32_t offset,
                      uint32_t size) override;

  int RequestEncodingParamsChange(vea_bitrate_t bitrate,
                                  uint32_t framerate) override;

  int Flush() override;
};

FakeVeaContext::FakeVeaContext() {
  LOG(INFO) << "Created new FakeVeaContext.";
}

int FakeVeaContext::Encode(vea_input_buffer_id_t input_buffer_id,
                           base::ScopedFD fd,
                           size_t num_planes,
                           video_frame_plane_t* planes,
                           uint64_t timestamp,
                           bool force_keyframe) {
  LOG(INFO) << "FakeVeaContext::Encode input_buffer_id=" << input_buffer_id
            << " fd=" << fd.get() << " num_planes=" << num_planes
            << " timestamp=" << timestamp
            << " force_keyframe=" << force_keyframe;
  DispatchProcessedInputBuffer(input_buffer_id);
  return 0;
}

int FakeVeaContext::UseOutputBuffer(vea_output_buffer_id_t output_buffer_id,
                                    base::ScopedFD fd,
                                    uint32_t offset,
                                    uint32_t size) {
  LOG(INFO) << "FakeVeaContext::UseOutputBuffer output_buffer_id="
            << output_buffer_id << " fd=" << fd.get() << " offset=" << offset
            << " size=" << size;
  DispatchProcessedOutputBuffer(output_buffer_id,
                                /* payload_size= */ 0,
                                /* key_frame= */ false,
                                /* timestamp= */ 0);
  return 0;
}

int FakeVeaContext::RequestEncodingParamsChange(vea_bitrate_t bitrate,
                                                uint32_t framerate) {
  LOG(INFO) << "FakeVeaContext::RequestEncodingParamsChange bitrate="
            << bitrate.target << " framerate=" << framerate;
  return 0;
}

int FakeVeaContext::Flush() {
  LOG(INFO) << "FakeVeaContext::Flush";
  DispatchFlushResponse(true);
  return 0;
}

}  // namespace

FakeVeaImpl::FakeVeaImpl() {
  LOG(INFO) << "Created FakeVeaImpl.";

  input_format_ = NV12;
  output_format_.profile = H264PROFILE_MAIN;
  output_format_.max_width = 1280;
  output_format_.max_height = 1080;
  output_format_.max_framerate_numerator = 60;
  output_format_.max_framerate_denominator = 1;

  capabilities_.num_input_formats = 1;
  capabilities_.input_formats = &input_format_;
  capabilities_.num_output_formats = 1;
  capabilities_.output_formats = &output_format_;
}

VeaContext* FakeVeaImpl::InitEncodeSession(vea_config_t* config) {
  LOG(INFO) << "FakeVeaImpl::InitEncodeSession";
  return new FakeVeaContext();
}

void FakeVeaImpl::CloseEncodeSession(VeaContext* ctx) {
  LOG(INFO) << "FakeVeaImpl::CloseEncodeSession";
  delete ctx;
}

// static
FakeVeaImpl* FakeVeaImpl::Create() {
  return new FakeVeaImpl();
}

}  // namespace arc
