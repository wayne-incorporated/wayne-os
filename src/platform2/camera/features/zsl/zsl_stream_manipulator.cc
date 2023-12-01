/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/zsl/zsl_stream_manipulator.h"

#include <optional>
#include <utility>

#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/common.h"
#include "features/zsl/tracing.h"
#include "features/zsl/zsl_helper.h"

namespace cros {

ZslStreamManipulator::ZslStreamManipulator() = default;

ZslStreamManipulator::~ZslStreamManipulator() = default;

// static
bool ZslStreamManipulator::UpdateVendorTags(
    VendorTagManager& vendor_tag_manager) {
  return AddVendorTags(vendor_tag_manager);
}

// static
bool ZslStreamManipulator::UpdateStaticMetadata(
    android::CameraMetadata* static_info) {
  uint8_t can_attempt_zsl = !!TryAddEnableZslKey(static_info);
  if (static_info->update(kCrosZslVendorTagCanAttempt, &can_attempt_zsl, 1) !=
      0) {
    LOGF(ERROR) << "Failed to update kCrosZslVendorTagCanAttempt";
    return false;
  }
  return true;
}

bool ZslStreamManipulator::Initialize(const camera_metadata_t* static_info,
                                      StreamManipulator::Callbacks callbacks) {
  TRACE_ZSL();

  callbacks_ = std::move(callbacks);
  std::optional<uint8_t> vendor_tag =
      GetRoMetadata<uint8_t>(static_info, kCrosZslVendorTagCanAttempt);
  can_attempt_zsl_ = vendor_tag.has_value() && *vendor_tag == 1;
  LOGF(INFO) << "Can attempt to enable ZSL by private reprocessing: "
             << can_attempt_zsl_;
  if (!can_attempt_zsl_) {
    return true;
  }

  std::optional<int32_t> partial_result_count =
      GetRoMetadata<int32_t>(static_info, ANDROID_REQUEST_PARTIAL_RESULT_COUNT);
  partial_result_count_ = partial_result_count.value_or(1);
  zsl_helper_ = std::make_unique<ZslHelper>(static_info);
  return true;
}

bool ZslStreamManipulator::ConfigureStreams(
    Camera3StreamConfiguration* stream_config,
    const StreamEffectMap* stream_effects_map) {
  TRACE_ZSL([&](perfetto::EventContext ctx) {
    stream_config->PopulateEventAnnotation(ctx);
  });

  if (!can_attempt_zsl_) {
    return true;
  }
  zsl_enabled_ = false;
  zsl_stream_attached_ = zsl_helper_->AttachZslStream(stream_config);
  if (zsl_stream_attached_) {
    zsl_stream_ = stream_config->GetStreams().back();
  }
  return true;
}

bool ZslStreamManipulator::OnConfiguredStreams(
    Camera3StreamConfiguration* stream_config) {
  TRACE_ZSL([&](perfetto::EventContext ctx) {
    stream_config->PopulateEventAnnotation(ctx);
  });

  if (!can_attempt_zsl_) {
    return true;
  }
  if (zsl_stream_attached_) {
    if (zsl_helper_->Initialize(stream_config)) {
      zsl_enabled_ = true;
      LOGF(INFO) << "Enabling ZSL";
    } else {
      LOGF(ERROR) << "Failed to initialize ZslHelper";
      return false;
    }
  }
  return true;
}

bool ZslStreamManipulator::ConstructDefaultRequestSettings(
    android::CameraMetadata* default_request_settings, int type) {
  TRACE_ZSL();

  if (!can_attempt_zsl_) {
    return true;
  }
  // Enabling ZSL by default will fail some AE compensation CTS tests. Currently
  // ZSL is only used by Chrome VCD. Enabling ZSL for Android by default is
  // still a TODO.
  uint8_t zsl_enable = ANDROID_CONTROL_ENABLE_ZSL_FALSE;
  if (default_request_settings->update(ANDROID_CONTROL_ENABLE_ZSL, &zsl_enable,
                                       1) != 0) {
    LOGF(WARNING) << "Failed to add ENABLE_ZSL to template " << type;
    return false;
  }
  LOGF(INFO) << "Added ENABLE_ZSL to template " << type;
  return true;
}

bool ZslStreamManipulator::ProcessCaptureRequest(
    Camera3CaptureDescriptor* request) {
  TRACE_ZSL("frame_number", request->frame_number());

  if (!can_attempt_zsl_) {
    return true;
  }
  if (zsl_enabled_) {
    zsl_helper_->ProcessZslCaptureRequest(
        request, ZslHelper::SelectionStrategy::CLOSEST_3A);
  }

  // We add ANDROID_CONTROL_ENABLE_ZSL to the capture templates. We need to make
  // sure it is hidden from the actual HAL.
  request->DeleteMetadata(ANDROID_CONTROL_ENABLE_ZSL);

  return true;
}

bool ZslStreamManipulator::ProcessCaptureResult(
    Camera3CaptureDescriptor result) {
  TRACE_ZSL("frame_number", result.frame_number());

  if (!can_attempt_zsl_) {
    callbacks_.result_callback.Run(std::move(result));
    return true;
  }
  bool is_input_transformed = false;
  if (zsl_enabled_) {
    zsl_helper_->ProcessZslCaptureResult(&result, &is_input_transformed);
  }
  // If we attempt ZSL, we'll add ANDROID_CONTROL_ENABLE_ZSL to the capture
  // template which will then require us to add it to capture results as well.
  if (result.partial_result() == partial_result_count_) {
    result.UpdateMetadata<uint8_t>(
        ANDROID_CONTROL_ENABLE_ZSL,
        std::array<uint8_t, 1>{ANDROID_CONTROL_ENABLE_ZSL_TRUE});
  }

  callbacks_.result_callback.Run(std::move(result));
  return true;
}

void ZslStreamManipulator::Notify(camera3_notify_msg_t msg) {
  TRACE_ZSL();

  if (!can_attempt_zsl_) {
    callbacks_.notify_callback.Run(std::move(msg));
    return;
  }
  if (msg.type == CAMERA3_MSG_ERROR) {
    zsl_helper_->OnNotifyError(msg.message.error);
  }
  callbacks_.notify_callback.Run(std::move(msg));
}

bool ZslStreamManipulator::Flush() {
  TRACE_ZSL();
  return true;
}

}  // namespace cros
