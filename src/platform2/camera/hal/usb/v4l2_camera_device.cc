/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/v4l2_camera_device.h"

#include <fcntl.h>
#include <linux/videodev2.h>
#include <poll.h>
#include <sys/ioctl.h>

#include <algorithm>
#include <limits>
#include <memory>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/containers/flat_set.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/notreached.h>
#include <base/posix/safe_strerror.h>
#include <base/strings/pattern.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <camera/camera_metadata.h>
#include <re2/re2.h>

#include "cros-camera/common.h"
#include "cros-camera/jpeg_compressor.h"
#include "cros-camera/utils/camera_config.h"
#include "hal/usb/camera_characteristics.h"
#include "hal/usb/quirks.h"

namespace cros {

namespace {

// Since cameras might report non-integer fps but in Android Camera 3 API we
// can only set fps range with integer in metadata.
constexpr float kFpsDifferenceThreshold = 1.0f;
// The following exposure type strings are from UVC driver.
constexpr char kExposureTypeMenuStringAuto[] = "Auto Mode";
constexpr char kExposureTypeMenuStringManual[] = "Manual Mode";
constexpr char kExposureTypeMenuStringShutterPriority[] =
    "Shutter Priority Mode";
constexpr char kExposureTypeMenuStringAperturePriority[] =
    "Aperture Priority Mode";

const int ControlTypeToCid(ControlType type) {
  switch (type) {
    case kControlAutoWhiteBalance:
      return V4L2_CID_AUTO_WHITE_BALANCE;

    case kControlBrightness:
      return V4L2_CID_BRIGHTNESS;

    case kControlContrast:
      return V4L2_CID_CONTRAST;

    case kControlExposureAuto:
      return V4L2_CID_EXPOSURE_AUTO;

    case kControlExposureAutoPriority:
      return V4L2_CID_EXPOSURE_AUTO_PRIORITY;

    case kControlExposureTime:
      return V4L2_CID_EXPOSURE_ABSOLUTE;

    case kControlFocusAuto:
      return V4L2_CID_FOCUS_AUTO;

    case kControlFocusDistance:
      return V4L2_CID_FOCUS_ABSOLUTE;

    case kControlPan:
      return V4L2_CID_PAN_ABSOLUTE;

    case kControlRegionOfInterestAuto:
      return V4L2_CID_REGION_OF_INTEREST_AUTO;

    case kControlSaturation:
      return V4L2_CID_SATURATION;

    case kControlSharpness:
      return V4L2_CID_SHARPNESS;

    case kControlTilt:
      return V4L2_CID_TILT_ABSOLUTE;

    case kControlZoom:
      return V4L2_CID_ZOOM_ABSOLUTE;

    case kControlWhiteBalanceTemperature:
      return V4L2_CID_WHITE_BALANCE_TEMPERATURE;

    case kControlPrivacy:
      return V4L2_CID_PRIVACY;

    case kControlPowerLineFrequency:
      return V4L2_CID_POWER_LINE_FREQUENCY;

    default:
      NOTREACHED() << "Unexpected control type " << type;
      return -1;
  }
}

const std::string ControlTypeToString(ControlType type) {
  switch (type) {
    case kControlAutoWhiteBalance:
      return "auto white balance";

    case kControlBrightness:
      return "brightness";

    case kControlContrast:
      return "contrast";

    case kControlExposureAuto:
      return "exposure auto (0,3:auto, 1,2:manual)";

    case kControlExposureAutoPriority:
      return "exposure_auto_priority";

    case kControlExposureTime:
      return "exposure time";

    case kControlFocusAuto:
      return "auto focus";

    case kControlFocusDistance:
      return "focus distance";

    case kControlPan:
      return "pan";

    case kControlRegionOfInterestAuto:
      return "region of interest auto";

    case kControlSaturation:
      return "saturation";

    case kControlSharpness:
      return "sharpness";

    case kControlTilt:
      return "tilt";

    case kControlZoom:
      return "zoom";

    case kControlWhiteBalanceTemperature:
      return "white balance temperature";

    case kControlPrivacy:
      return "privacy";

    case kControlPowerLineFrequency:
      return "power line frequency";

    default:
      NOTREACHED() << "Unexpected control type " << type;
      return "N/A";
  }
}

const std::string CidToString(int cid) {
  switch (cid) {
    case V4L2_CID_AUTO_WHITE_BALANCE:
      return "V4L2_CID_AUTO_WHITE_BALANCE";

    case V4L2_CID_BRIGHTNESS:
      return "V4L2_CID_BRIGHTNESS";

    case V4L2_CID_CONTRAST:
      return "V4L2_CID_CONTRAST";

    case V4L2_CID_EXPOSURE_ABSOLUTE:
      return "V4L2_CID_EXPOSURE_ABSOLUTE";

    case V4L2_CID_EXPOSURE_AUTO:
      return "V4L2_CID_EXPOSURE_AUTO";

    case V4L2_CID_EXPOSURE_AUTO_PRIORITY:
      return "V4L2_CID_EXPOSURE_AUTO_PRIORITY";

    case V4L2_CID_FOCUS_ABSOLUTE:
      return "V4L2_CID_FOCUS_ABSOLUTE";

    case V4L2_CID_FOCUS_AUTO:
      return "V4L2_CID_FOCUS_AUTO";

    case V4L2_CID_PAN_ABSOLUTE:
      return "V4L2_CID_PAN_ABSOLUTE";

    case V4L2_CID_REGION_OF_INTEREST_AUTO:
      return "V4L2_CID_REGION_OF_INTEREST_AUTO";

    case V4L2_CID_SATURATION:
      return "V4L2_CID_SATURATION";

    case V4L2_CID_SHARPNESS:
      return "V4L2_CID_SHARPNESS";

    case V4L2_CID_TILT_ABSOLUTE:
      return "V4L2_CID_TILT_ABSOLUTE";

    case V4L2_CID_ZOOM_ABSOLUTE:
      return "V4L2_CID_ZOOM_ABSOLUTE";

    case V4L2_CID_WHITE_BALANCE_TEMPERATURE:
      return "V4L2_CID_WHITE_BALANCE_TEMPERATURE";

    case V4L2_CID_PRIVACY:
      return "V4L2_CID_PRIVACY";

    case V4L2_CID_POWER_LINE_FREQUENCY:
      return "V4L2_CID_POWER_LINE_FREQUENCY";

    default:
      NOTREACHED() << "Unexpected cid " << cid;
      return "N/A";
  }
}

}  // namespace

V4L2CameraDevice::V4L2CameraDevice()
    : stream_on_(false), device_info_(DeviceInfo()) {}

V4L2CameraDevice::V4L2CameraDevice(
    const DeviceInfo& device_info,
    CameraPrivacySwitchMonitor* privacy_switch_monitor,
    bool sw_privacy_switch_on)
    : stream_on_(false),
      sw_privacy_switch_on_(sw_privacy_switch_on),
      device_info_(device_info),
      hw_privacy_switch_monitor_(privacy_switch_monitor) {}

V4L2CameraDevice::~V4L2CameraDevice() {
  device_fd_.reset();
}

int V4L2CameraDevice::Connect(const std::string& device_path) {
  VLOGF(1) << "Connecting device path: " << device_path;
  base::AutoLock l(lock_);
  if (device_fd_.is_valid()) {
    LOGF(ERROR) << "A camera device is opened (" << device_fd_.get()
                << "). Please close it first";
    return -EIO;
  }

  // Since device node may be changed after suspend/resume, we allow to use
  // symbolic link to access device.
  device_fd_.reset(RetryDeviceOpen(device_path, O_RDWR));
  if (!device_fd_.is_valid()) {
    const int ret = ERRNO_OR_RET(-EINVAL);
    PLOGF(ERROR) << "Failed to open " << device_path;
    return ret;
  }

  if (!IsCameraDevice(device_path)) {
    LOGF(ERROR) << device_path << " is not a V4L2 video capture device";
    device_fd_.reset();
    return -EINVAL;
  }

  // Get and set format here is used to prevent multiple camera using.
  // UVC driver will acquire lock in VIDIOC_S_FMT and VIDIOC_S_SMT will fail if
  // the camera is being used by a user. The second user will fail in Connect()
  // instead of StreamOn(). Usually apps show better error message if camera
  // open fails. If start preview fails, some apps do not handle it well.
  int ret;
  v4l2_format fmt = {};
  fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  ret = TEMP_FAILURE_RETRY(ioctl(device_fd_.get(), VIDIOC_G_FMT, &fmt));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(ERROR) << "Unable to G_FMT";
    return ret;
  }
  ret = TEMP_FAILURE_RETRY(ioctl(device_fd_.get(), VIDIOC_S_FMT, &fmt));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(WARNING)
        << "Unable to S_FMT: maybe camera is being used by another app.";
    return ret;
  }

  ret = SetPowerLineFrequency();
  if (ret < 0 && !IsExternalCamera()) {
    return -EINVAL;
  }

  // Initial autofocus state.
  int32_t value;
  focus_auto_supported_ = IsControlSupported(kControlFocusAuto) &&
                          GetControlValue(kControlFocusAuto, &value) == 0;
  if (focus_auto_supported_) {
    LOGF(INFO) << "Device supports auto focus control, current mode is "
               << (value == 0 ? "Off" : "Auto");
  }
  focus_distance_supported_ = IsControlSupported(kControlFocusDistance);
  if (focus_distance_supported_) {
    LOGF(INFO) << "Device supports focus distance control";
    // Focus distance is valid when focus mode is off.
    if (value == 0 && GetControlValue(kControlFocusDistance, &value) == 0) {
      LOGF(INFO) << "Current distance is " << value;
    }
  }

  // Query the initial auto white balance state.
  white_balance_control_supported_ =
      IsControlSupported(kControlAutoWhiteBalance) &&
      IsControlSupported(kControlWhiteBalanceTemperature);
  if (white_balance_control_supported_) {
    if (GetControlValue(kControlAutoWhiteBalance, &value) == 0) {
      if (value) {
        LOGF(INFO) << "Current white balance control is Auto";
      } else if (GetControlValue(kControlWhiteBalanceTemperature, &value) ==
                 0) {
        LOGF(INFO) << "Current white balance temperature is " << value;
      }
    }
  }

  // By default set V4L2_CID_EXPOSURE_AUTO_PRIORITY to 0 (constant frame rate),
  // since changing it from 1 to 0 later in video mode can affect the frame
  // rate.
  if (IsControlSupported(kControlExposureAutoPriority) &&
      GetControlValue(kControlExposureAutoPriority, &value) == 0 &&
      value != 0) {
    LOGF(WARNING)
        << "Set V4L2_CID_EXPOSURE_AUTO_PRIORITY to 0 (constant frame rate), "
        << "since changing it from 1 to 0 later in video mode can affect the "
        << "frame rate.";
    SetControlValue(kControlExposureAutoPriority, 0);
  }

  ControlInfo info;
  ControlRange range;
  manual_exposure_time_supported_ =
      IsManualExposureTimeSupported(device_path, &range);
  if (manual_exposure_time_supported_ &&
      QueryControl(kControlExposureAuto, &info) == 0) {
    if (GetControlValue(kControlExposureAuto, &value) == 0) {
      switch (value) {
        case V4L2_EXPOSURE_AUTO:
          LOGF(INFO) << "Current exposure type is Auto";
          auto_exposure_time_type_ = V4L2_EXPOSURE_AUTO;
          // Prefer switching between AUTO<->SHUTTER_PRIORITY
          if (base::Contains(info.menu_items,
                             kExposureTypeMenuStringShutterPriority)) {
            manual_exposure_time_type_ = V4L2_EXPOSURE_SHUTTER_PRIORITY;
          } else if (base::Contains(info.menu_items,
                                    kExposureTypeMenuStringManual)) {
            manual_exposure_time_type_ = V4L2_EXPOSURE_MANUAL;
          } else {
            NOTREACHED() << "No manual exposure time type supported";
          }
          break;

        case V4L2_EXPOSURE_MANUAL:
          LOGF(INFO) << "Current exposure type is Manual";
          manual_exposure_time_type_ = V4L2_EXPOSURE_MANUAL;
          // Prefer switching between APERTURE_PRIORITY<->MANUAL
          if (base::Contains(info.menu_items,
                             kExposureTypeMenuStringAperturePriority)) {
            auto_exposure_time_type_ = V4L2_EXPOSURE_APERTURE_PRIORITY;
          } else if (base::Contains(info.menu_items,
                                    kExposureTypeMenuStringAuto)) {
            auto_exposure_time_type_ = V4L2_EXPOSURE_AUTO;
          } else {
            NOTREACHED() << "No auto exposure time type supported";
          }
          break;

        case V4L2_EXPOSURE_SHUTTER_PRIORITY:
          LOGF(INFO) << "Current exposure type is Shutter Priority";
          manual_exposure_time_type_ = V4L2_EXPOSURE_SHUTTER_PRIORITY;
          // Prefer switching between AUTO<->SHUTTER_PRIORITY
          if (base::Contains(info.menu_items, kExposureTypeMenuStringAuto)) {
            auto_exposure_time_type_ = V4L2_EXPOSURE_AUTO;
          } else if (base::Contains(info.menu_items,
                                    kExposureTypeMenuStringAperturePriority)) {
            auto_exposure_time_type_ = V4L2_EXPOSURE_APERTURE_PRIORITY;
          } else {
            NOTREACHED() << "No auto exposure time type supported";
          }
          break;

        case V4L2_EXPOSURE_APERTURE_PRIORITY:
          LOGF(INFO) << "Current exposure type is Aperture Priority";
          auto_exposure_time_type_ = V4L2_EXPOSURE_APERTURE_PRIORITY;
          // Prefer switching between APERTURE_PRIORITY<->MANUAL
          if (base::Contains(info.menu_items, kExposureTypeMenuStringManual)) {
            manual_exposure_time_type_ = V4L2_EXPOSURE_MANUAL;
          } else if (base::Contains(info.menu_items,
                                    kExposureTypeMenuStringShutterPriority)) {
            manual_exposure_time_type_ = V4L2_EXPOSURE_SHUTTER_PRIORITY;
          } else {
            NOTREACHED() << "No manual exposure time type supported";
          }
          break;

        default:
          LOGF(WARNING) << "Unknown exposure type " << value;
          manual_exposure_time_supported_ = false;
          break;
      }
    }
  }

  if (device_info_.enable_face_detection) {
    IsRegionOfInterestSupported(device_fd_.get(), &roi_control_);
    if (roi_control_.roi_flags) {
      LOGF(INFO) << "ROI control flags:0x" << std::hex << roi_control_.roi_flags
                 << " " << std::dec
                 << "ROI bounds default:" << roi_control_.roi_bounds_default;
      LOGF(INFO) << "ROI bounds:" << roi_control_.roi_bounds
                 << ", min:" << roi_control_.min_roi_size.ToString();
      SetControlValue(kControlRegionOfInterestAuto, roi_control_.roi_flags);
    }
  }

  // Initialize the capabilities.
  if (device_info_.quirks & kQuirkDisableFrameRateSetting) {
    can_update_frame_rate_ = false;
  } else {
    v4l2_streamparm streamparm = {};
    streamparm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    can_update_frame_rate_ =
        TEMP_FAILURE_RETRY(
            ioctl(device_fd_.get(), VIDIOC_G_PARM, &streamparm)) >= 0 &&
        (streamparm.parm.capture.capability & V4L2_CAP_TIMEPERFRAME);
  }
  return 0;
}

void V4L2CameraDevice::Disconnect() {
  base::AutoLock l(lock_);
  stream_on_ = false;
  device_fd_.reset();
  buffers_at_client_.clear();
}

int V4L2CameraDevice::StreamOn(uint32_t width,
                               uint32_t height,
                               uint32_t pixel_format,
                               float frame_rate,
                               std::vector<base::ScopedFD>* fds,
                               std::vector<uint32_t>* buffer_sizes) {
  base::AutoLock l(lock_);
  if (!device_fd_.is_valid()) {
    LOGF(ERROR) << "Device is not opened";
    return -ENODEV;
  }
  if (stream_on_) {
    LOGF(ERROR) << "Device has stream already started";
    return -EIO;
  }

  int ret;

  // Some drivers use rational time per frame instead of float frame rate, this
  // constant k is used to convert between both: A fps -> [k/k*A] seconds/frame.
  v4l2_format fmt = {};
  fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  fmt.fmt.pix.width = width;
  fmt.fmt.pix.height = height;
  fmt.fmt.pix.pixelformat = pixel_format;
  ret = TEMP_FAILURE_RETRY(ioctl(device_fd_.get(), VIDIOC_S_FMT, &fmt));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(ERROR) << "Unable to S_FMT";
    return ret;
  }
  VLOGF(1) << "Actual width: " << fmt.fmt.pix.width
           << ", height: " << fmt.fmt.pix.height
           << ", pixelformat: " << std::hex << fmt.fmt.pix.pixelformat
           << std::dec;

  if (width != fmt.fmt.pix.width || height != fmt.fmt.pix.height ||
      pixel_format != fmt.fmt.pix.pixelformat) {
    LOGF(ERROR) << "Unsupported format: width " << width << ", height "
                << height << ", pixelformat " << pixel_format;
    return -EINVAL;
  }

  if (CanUpdateFrameRate()) {
    // We need to set frame rate even if it's same as the previous value, since
    // uvcvideo driver will always reset it to the default value after the
    // VIDIOC_S_FMT ioctl() call.
    ret = SetFrameRate(frame_rate);
    if (ret < 0) {
      return ret;
    }
  } else {
    // Simply assumes the frame rate is good if the device does not support
    // frame rate settings.
    frame_rate_ = frame_rate;
    LOGF(INFO) << "No fps setting support, " << frame_rate
               << " fps setting is ignored";
  }

  v4l2_requestbuffers req_buffers;
  memset(&req_buffers, 0, sizeof(req_buffers));
  req_buffers.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  req_buffers.memory = V4L2_MEMORY_MMAP;
  req_buffers.count = kNumVideoBuffers;
  ret =
      TEMP_FAILURE_RETRY(ioctl(device_fd_.get(), VIDIOC_REQBUFS, &req_buffers));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(ERROR) << "REQBUFS fails";
    return ret;
  }
  VLOGF(1) << "Requested buffer number: " << req_buffers.count;

  buffers_at_client_.resize(req_buffers.count);
  std::vector<base::ScopedFD> temp_fds;
  for (uint32_t i = 0; i < req_buffers.count; i++) {
    v4l2_exportbuffer expbuf;
    memset(&expbuf, 0, sizeof(expbuf));
    expbuf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    expbuf.index = i;
    ret = TEMP_FAILURE_RETRY(ioctl(device_fd_.get(), VIDIOC_EXPBUF, &expbuf));
    if (ret < 0) {
      ret = ERRNO_OR_RET(ret);
      PLOGF(ERROR) << "EXPBUF (" << i << ") fails";
      return ret;
    }
    VLOGF(1) << "Exported frame buffer fd: " << expbuf.fd;
    temp_fds.push_back(base::ScopedFD(expbuf.fd));

    v4l2_buffer buffer = {.index = i,
                          .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
                          .memory = V4L2_MEMORY_MMAP};
    ret = EnqueueBuffer(buffer);
    if (ret < 0) {
      return ret;
    }

    buffer_sizes->push_back(buffer.length);
  }

  if (!sw_privacy_switch_on_) {
    ret = StartStreaming();
    if (ret < 0) {
      return ret;
    }
  }

  for (size_t i = 0; i < temp_fds.size(); i++) {
    fds->push_back(std::move(temp_fds[i]));
  }

  if (hw_privacy_switch_monitor_) {
    hw_privacy_switch_monitor_->TrySubscribe(device_info_.camera_id,
                                             device_info_.device_path);
  }
  stream_on_ = true;
  return 0;
}

int V4L2CameraDevice::StreamOff() {
  base::AutoLock l(lock_);
  if (!device_fd_.is_valid()) {
    LOGF(ERROR) << "Device is not opened";
    return -ENODEV;
  }
  // Because UVC driver cannot allow STREAMOFF after REQBUF(0), adding a check
  // here to prevent it.
  if (!stream_on_) {
    return 0;
  }

  int ret = StopStreaming();
  if (ret < 0) {
    return ret;
  }
  v4l2_requestbuffers req_buffers;
  memset(&req_buffers, 0, sizeof(req_buffers));
  req_buffers.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  req_buffers.memory = V4L2_MEMORY_MMAP;
  req_buffers.count = 0;
  ret =
      TEMP_FAILURE_RETRY(ioctl(device_fd_.get(), VIDIOC_REQBUFS, &req_buffers));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(ERROR) << "REQBUFS fails";
    return ret;
  }
  buffers_at_client_.clear();
  stream_on_ = false;
  return 0;
}

int V4L2CameraDevice::GetNextFrameBuffer(uint32_t* buffer_id,
                                         uint32_t* data_size,
                                         uint64_t* v4l2_ts,
                                         uint64_t* user_ts) {
  base::AutoLock l(lock_);
  if (!device_fd_.is_valid()) {
    LOGF(ERROR) << "Device is not opened";
    return -ENODEV;
  }
  if (!stream_on_) {
    LOGF(ERROR) << "Streaming is not started";
    return -EIO;
  }

  if (device_info_.quirks & kQuirkRestartOnTimeout) {
    pollfd device_pfd = {};
    device_pfd.fd = device_fd_.get();
    device_pfd.events = POLLIN;

    constexpr int kCaptureTimeoutMs = 1000;
    int result = TEMP_FAILURE_RETRY(poll(&device_pfd, 1, kCaptureTimeoutMs));

    if (result < 0) {
      result = ERRNO_OR_RET(result);
      PLOGF(ERROR) << "Polling fails";
      return result;
    } else if (result == 0) {
      LOGF(ERROR) << "Timed out waiting for captured frame";
      return -ETIMEDOUT;
    }

    if (!(device_pfd.revents & POLLIN)) {
      LOGF(ERROR) << "Unexpected event occurred while polling";
      return -EIO;
    }
  }

  v4l2_buffer buffer;
  memset(&buffer, 0, sizeof(buffer));
  buffer.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  buffer.memory = V4L2_MEMORY_MMAP;
  int ret = TEMP_FAILURE_RETRY(ioctl(device_fd_.get(), VIDIOC_DQBUF, &buffer));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF_THROTTLED(ERROR, 60) << "DQBUF fails";
    return ret;
  }
  VLOGF(1) << "DQBUF returns index " << buffer.index << " length "
           << buffer.length;

  if (buffer.index >= buffers_at_client_.size() ||
      buffers_at_client_[buffer.index]) {
    LOGF(ERROR) << "Invalid buffer id " << buffer.index;
    return -EINVAL;
  }

  *buffer_id = buffer.index;
  *data_size = buffer.bytesused;

  struct timeval tv = buffer.timestamp;
  *v4l2_ts = tv.tv_sec * 1'000'000'000LL + tv.tv_usec * 1000;

  struct timespec ts;
  ret = GetUserSpaceTimestamp(ts);
  if (ret < 0) {
    return ret;
  }

  *user_ts = ts.tv_sec * 1'000'000'000LL + ts.tv_nsec;

  buffers_at_client_[buffer.index] = true;

  return 0;
}

int V4L2CameraDevice::ReuseFrameBuffer(uint32_t buffer_id) {
  base::AutoLock l(lock_);
  if (!device_fd_.is_valid()) {
    LOGF(ERROR) << "Device is not opened";
    return -ENODEV;
  }
  if (!stream_on_) {
    LOGF(ERROR) << "Streaming is not started";
    return -EIO;
  }

  VLOGF(1) << "Reuse buffer id: " << buffer_id;
  if (buffer_id >= buffers_at_client_.size() ||
      !buffers_at_client_[buffer_id]) {
    LOGF(ERROR) << "Invalid buffer id: " << buffer_id;
    return -EINVAL;
  }
  v4l2_buffer buffer = {.index = buffer_id,
                        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
                        .memory = V4L2_MEMORY_MMAP};
  return EnqueueBuffer(buffer);
}

bool V4L2CameraDevice::IsBufferFilled(uint32_t buffer_id) {
  v4l2_buffer buffer = {};
  buffer.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  buffer.memory = V4L2_MEMORY_MMAP;
  buffer.index = buffer_id;
  if (TEMP_FAILURE_RETRY(ioctl(device_fd_.get(), VIDIOC_QUERYBUF, &buffer)) <
      0) {
    PLOGF(ERROR) << "QUERYBUF fails";
    return false;
  }
  return buffer.flags & V4L2_BUF_FLAG_DONE;
}

int V4L2CameraDevice::SetAutoFocus(bool enable) {
  if (!focus_auto_supported_) {
    // Off mode is default supported
    if (enable) {
      LOGF(WARNING)
          << "Setting auto focus while device doesn't support. Ignored";
    }
    return 0;
  }

  if (enable && control_values_.count(kControlFocusDistance)) {
    control_values_.erase(kControlFocusDistance);
  }

  return SetControlValue(kControlFocusAuto, enable ? 1 : 0);
}

int V4L2CameraDevice::SetFocusDistance(int32_t distance) {
  if (!focus_distance_supported_) {
    LOGF(WARNING) << "Setting focus distance while devcie doesn't support. "
                  << "Ignored.";
    return 0;
  }

  return SetControlValue(kControlFocusDistance, distance);
}

int V4L2CameraDevice::SetExposureTimeHundredUs(uint32_t exposure_time) {
  if (!manual_exposure_time_supported_) {
    if (exposure_time != kExposureTimeAuto) {
      LOGF(WARNING)
          << "Setting manual exposure time when device doesn't support";
    }
    return 0;
  }

  if (exposure_time == kExposureTimeAuto) {
    if (control_values_.count(kControlExposureTime))
      control_values_.erase(kControlExposureTime);
    return SetControlValue(kControlExposureAuto, auto_exposure_time_type_);
  }

  int ret = SetControlValue(kControlExposureAuto, manual_exposure_time_type_);
  if (ret != 0)
    return ret;

  return SetControlValue(kControlExposureTime, exposure_time);
}

bool V4L2CameraDevice::CanUpdateFrameRate() {
  return can_update_frame_rate_;
}

float V4L2CameraDevice::GetFrameRate() {
  return frame_rate_;
}

int V4L2CameraDevice::SetFrameRate(float frame_rate) {
  const int kFrameRatePrecision = 10000;

  if (!device_fd_.is_valid()) {
    LOGF(ERROR) << "Device is not opened";
    return -ENODEV;
  }

  v4l2_streamparm streamparm = {};
  streamparm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

  // The following line checks that the driver knows about framerate get/set.
  if (TEMP_FAILURE_RETRY(ioctl(device_fd_.get(), VIDIOC_G_PARM, &streamparm)) >=
      0) {
    // |frame_rate| is float, approximate by a fraction.
    streamparm.parm.capture.timeperframe.numerator = kFrameRatePrecision;
    streamparm.parm.capture.timeperframe.denominator =
        (frame_rate * kFrameRatePrecision);

    int ret =
        TEMP_FAILURE_RETRY(ioctl(device_fd_.get(), VIDIOC_S_PARM, &streamparm));
    if (ret < 0) {
      ret = ERRNO_OR_RET(ret);
      LOGF(ERROR) << "Failed to set camera framerate";
      return ret;
    }
    VLOGF(1) << "Actual camera driver framerate: "
             << streamparm.parm.capture.timeperframe.denominator << "/"
             << streamparm.parm.capture.timeperframe.numerator;
    float fps =
        static_cast<float>(streamparm.parm.capture.timeperframe.denominator) /
        streamparm.parm.capture.timeperframe.numerator;
    if (std::fabs(fps - frame_rate) > kFpsDifferenceThreshold) {
      LOGF(ERROR) << "Unsupported frame rate " << frame_rate;
      return -EINVAL;
    }

    VLOGF(1) << "Successfully set the frame rate to: " << fps;
    frame_rate_ = frame_rate;
  }

  return 0;
}

int V4L2CameraDevice::SetColorTemperature(uint32_t color_temperature) {
  if (!white_balance_control_supported_) {
    if (color_temperature != kColorTemperatureAuto) {
      LOGF(WARNING) << "Setting color temperature when device doesn't support";
    }
    return 0;
  }

  if (color_temperature == kColorTemperatureAuto) {
    if (control_values_.count(kControlWhiteBalanceTemperature))
      control_values_.erase(kControlWhiteBalanceTemperature);
    return SetControlValue(kControlAutoWhiteBalance, 1);
  }

  int ret = SetControlValue(kControlAutoWhiteBalance, 0);
  if (ret != 0) {
    LOGF(WARNING) << "Failed to set white_balance_control to manual";
    return ret;
  }

  return SetControlValue(kControlWhiteBalanceTemperature, color_temperature);
}

int V4L2CameraDevice::SetControlValue(ControlType type, int32_t value) {
  auto it = control_values_.find(type);
  // Has cached value
  if (it != control_values_.end()) {
    if (it->second == value)
      return 0;
    else
      control_values_.erase(type);
  }

  int ret = SetControlValue(device_fd_.get(), type, value);
  if (ret != 0)
    return ret;

  int32_t current_value;

  ret = GetControlValue(type, &current_value);
  if (ret != 0)
    return ret;
  if (value == current_value) {
    LOGF(INFO) << "Set " << ControlTypeToString(type) << " to " << value;
  } else {
    LOGF(WARNING) << "Set " << ControlTypeToString(type) << " to " << value
                  << " but got " << current_value;
  }

  return 0;
}

int V4L2CameraDevice::GetControlValue(ControlType type, int32_t* value) {
  auto it = control_values_.find(type);
  // Has cached value
  if (it != control_values_.end()) {
    *value = it->second;
    return 0;
  }

  int ret = GetControlValue(device_fd_.get(), type, value);
  if (ret != 0)
    return ret;

  control_values_[type] = *value;
  return 0;
}

bool V4L2CameraDevice::IsControlSupported(ControlType type) {
  ControlInfo info;

  return QueryControl(device_fd_.get(), type, &info) == 0;
}

int V4L2CameraDevice::QueryControl(ControlType type, ControlInfo* info) {
  return QueryControl(device_fd_.get(), type, info);
}

int V4L2CameraDevice::SetRegionOfInterest(const Rect<int>& rectangle) {
  if (roi_control_.roi_flags == 0) {
    return -EINVAL;
  }
  int left = std::max(rectangle.left, roi_control_.roi_bounds.left);
  int top = std::max(rectangle.top, roi_control_.roi_bounds.top);
  int width = std::max(rectangle.width,
                       static_cast<int>(roi_control_.min_roi_size.width));
  int height = std::max(rectangle.height,
                        static_cast<int>(roi_control_.min_roi_size.height));
  // if the right and bottom size is excess the max range, we have 2
  // adjustments, to shrink width/height and to adjust left/top.
  int rightmost = roi_control_.roi_bounds.left + roi_control_.roi_bounds.width;
  if (left + width > rightmost) {
    int offset =
        std::min(left + width - rightmost, left - roi_control_.roi_bounds.left);
    left -= offset;
    width = rightmost - left;
  }
  int bottommost = roi_control_.roi_bounds.top + roi_control_.roi_bounds.height;
  if (top + height > bottommost) {
    int offset =
        std::min(top + height - bottommost, top - roi_control_.roi_bounds.top);
    top -= offset;
    height = bottommost - top;
  }
  v4l2_selection current = {
      .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
      .target = static_cast<__u32>(V4L2_SEL_TGT_ROI),
      .r =
          {
              .left = static_cast<__s32>(rectangle.left),
              .top = static_cast<__s32>(rectangle.top),
              .width = static_cast<__u32>(width),
              .height = static_cast<__u32>(height),
          },
  };

  int ret = HANDLE_EINTR(ioctl(device_fd_.get(), VIDIOC_S_SELECTION, &current));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(WARNING) << "Failed to set selection(" << rectangle.left << ","
                   << rectangle.top << "," << width << "," << height << ")";
    return ret;
  }

  return 0;
}

int V4L2CameraDevice::SetPrivacySwitchState(bool on) {
  base::AutoLock l(lock_);
  if (sw_privacy_switch_on_ == on) {
    return 0;
  }

  sw_privacy_switch_on_ = on;

  // If this method is called while not streaming, just update
  // |sw_privacy_switch_on_|.
  if (!stream_on_) {
    return 0;
  }

  int ret = 0;
  if (on) {
    ret = StopStreaming();
    if (ret < 0) {
      return ret;
    }
    std::fill(buffers_at_client_.begin(), buffers_at_client_.end(), true);
  } else {
    for (uint32_t i = 0; i < buffers_at_client_.size(); ++i) {
      if (!buffers_at_client_[i]) {
        continue;
      }
      v4l2_buffer buffer = {.index = i,
                            .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
                            .memory = V4L2_MEMORY_MMAP};
      ret = EnqueueBuffer(buffer);
      if (ret < 0) {
        return ret;
      }
    }
    ret = StartStreaming();
  }
  return ret;
}

// static
const SupportedFormats V4L2CameraDevice::GetDeviceSupportedFormats(
    const std::string& device_path) {
  VLOGF(1) << "Query supported formats for " << device_path;

  base::ScopedFD fd(RetryDeviceOpen(device_path, O_RDONLY));
  if (!fd.is_valid()) {
    PLOGF(ERROR) << "Failed to open " << device_path;
    return {};
  }

  std::unique_ptr<CameraConfig> camera_config =
      CameraConfig::Create(constants::kCrosCameraConfigPathString);

  std::vector<Size> filter_out_resolutions;
  if (camera_config != nullptr) {
    std::vector<std::string> filter_out_resolution_strings =
        camera_config->GetStrings(constants::kCrosUsbFilteredOutResolutions,
                                  std::vector<std::string>());
    for (const auto& filter_out_resolution_string :
         filter_out_resolution_strings) {
      int width, height;
      CHECK(RE2::FullMatch(filter_out_resolution_string, R"((\d+)x(\d+))",
                           &width, &height));
      filter_out_resolutions.emplace_back(width, height);
    }
  }

  SupportedFormats formats;
  v4l2_fmtdesc v4l2_format = {};
  v4l2_format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  for (;
       TEMP_FAILURE_RETRY(ioctl(fd.get(), VIDIOC_ENUM_FMT, &v4l2_format)) == 0;
       ++v4l2_format.index) {
    base::flat_set<Size> supported_frame_sizes;
    v4l2_frmsizeenum frame_size = {};
    frame_size.pixel_format = v4l2_format.pixelformat;
    for (; HANDLE_EINTR(ioctl(fd.get(), VIDIOC_ENUM_FRAMESIZES, &frame_size)) ==
           0;
         ++frame_size.index) {
      switch (frame_size.type) {
        case V4L2_FRMSIZE_TYPE_DISCRETE:
          supported_frame_sizes.emplace(frame_size.discrete.width,
                                        frame_size.discrete.height);
          break;
        case V4L2_FRMSIZE_TYPE_STEPWISE:
        case V4L2_FRMSIZE_TYPE_CONTINUOUS:
          // Simply choose the maximum and minimum sizes for non-discrete types.
          supported_frame_sizes.emplace(frame_size.stepwise.max_width,
                                        frame_size.stepwise.max_height);
          supported_frame_sizes.emplace(frame_size.stepwise.min_width,
                                        frame_size.stepwise.min_height);
          break;
        default:
          LOGF(WARNING) << "Unknown v4l2_frmsizetypes: " << frame_size.type;
          continue;
      }
    }

    for (const Size& size : supported_frame_sizes) {
      if (base::Contains(filter_out_resolutions, size)) {
        LOGF(INFO) << "Filter out " << size.ToString() << " by config";
        continue;
      }
      if (!JpegCompressor::IsSizeSupported(
              base::checked_cast<int>(size.width),
              base::checked_cast<int>(size.height))) {
        LOGF(INFO) << "Filter out " << size.ToString()
                   << " by JPEG compression capability";
        continue;
      }
      formats.push_back(SupportedFormat{
          .width = size.width,
          .height = size.height,
          .fourcc = v4l2_format.pixelformat,
          .frame_rates = GetFrameRateList(fd.get(), v4l2_format.pixelformat,
                                          size.width, size.height),
      });
    }
  }
  return formats;
}

// static
int V4L2CameraDevice::QueryControl(int fd,
                                   ControlType type,
                                   ControlInfo* info) {
  DCHECK(info);

  info->menu_items.clear();

  int control_id = ControlTypeToCid(type);
  v4l2_queryctrl query_ctrl = {.id = static_cast<__u32>(control_id)};

  int ret = HANDLE_EINTR(ioctl(fd, VIDIOC_QUERYCTRL, &query_ctrl));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    VLOGF(1) << "Unsupported control:" << CidToString(control_id);
    return ret;
  }

  if (query_ctrl.flags & V4L2_CTRL_FLAG_DISABLED) {
    LOGF(WARNING) << "Disabled control:" << CidToString(control_id);
    return -EPERM;
  }

  switch (query_ctrl.type) {
    case V4L2_CTRL_TYPE_INTEGER:
    case V4L2_CTRL_TYPE_BOOLEAN:
    case V4L2_CTRL_TYPE_MENU:
    case V4L2_CTRL_TYPE_STRING:
    case V4L2_CTRL_TYPE_INTEGER_MENU:
    case V4L2_CTRL_TYPE_U8:
    case V4L2_CTRL_TYPE_U16:
    case V4L2_CTRL_TYPE_U32:
      break;

    case V4L2_CTRL_TYPE_INTEGER64:
      LOGF(WARNING) << "Unsupported query V4L2_CTRL_TYPE_INTEGER64:"
                    << CidToString(control_id);
      return -EINVAL;

    default:
      info->range.minimum = query_ctrl.minimum;
      info->range.maximum = query_ctrl.maximum;
      info->range.step = query_ctrl.step;
      info->range.default_value = query_ctrl.default_value;
      return 0;
  }

  if (query_ctrl.minimum > query_ctrl.maximum) {
    LOGF(WARNING) << CidToString(control_id) << " min " << query_ctrl.minimum
                  << " > max " << query_ctrl.maximum;
    return -EINVAL;
  }

  if (query_ctrl.minimum > query_ctrl.default_value) {
    LOGF(WARNING) << CidToString(control_id) << " min " << query_ctrl.minimum
                  << " > default " << query_ctrl.default_value;
    return -EINVAL;
  }

  if (query_ctrl.maximum < query_ctrl.default_value) {
    LOGF(WARNING) << CidToString(control_id) << " max " << query_ctrl.maximum
                  << " < default " << query_ctrl.default_value;
    return -EINVAL;
  }

  if (query_ctrl.step <= 0) {
    LOGF(WARNING) << CidToString(control_id) << " step " << query_ctrl.step
                  << " <= 0";
    return -EINVAL;
  }

  if ((query_ctrl.default_value - query_ctrl.minimum) % query_ctrl.step != 0) {
    LOGF(WARNING) << CidToString(control_id) << " step " << query_ctrl.step
                  << " can't divide minimum " << query_ctrl.minimum
                  << " default_value " << query_ctrl.default_value;
    return -EINVAL;
  }

  if ((query_ctrl.maximum - query_ctrl.minimum) % query_ctrl.step != 0) {
    LOGF(WARNING) << CidToString(control_id) << " step " << query_ctrl.step
                  << " can't divide minimum " << query_ctrl.minimum
                  << " maximum " << query_ctrl.maximum;
    return -EINVAL;
  }

  // Fill the query info
  info->range.minimum = query_ctrl.minimum;
  info->range.maximum = query_ctrl.maximum;
  info->range.step = query_ctrl.step;
  info->range.default_value = query_ctrl.default_value;
  if (query_ctrl.type == V4L2_CTRL_TYPE_MENU) {
    for (int i = query_ctrl.minimum; i <= query_ctrl.maximum; i++) {
      v4l2_querymenu qmenu = {};
      qmenu.id = query_ctrl.id;
      qmenu.index = i;
      if (HANDLE_EINTR(ioctl(fd, VIDIOC_QUERYMENU, &qmenu)) == 0) {
        info->menu_items.emplace_back(
            reinterpret_cast<const char*>(qmenu.name));
      }
    }
  }

  return 0;
}

// static
int V4L2CameraDevice::SetControlValue(int fd, ControlType type, int32_t value) {
  int control_id = ControlTypeToCid(type);
  VLOGF(1) << "Set " << CidToString(control_id) << ", value:" << value;

  v4l2_control current = {.id = static_cast<__u32>(control_id), .value = value};
  int ret = HANDLE_EINTR(ioctl(fd, VIDIOC_S_CTRL, &current));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(WARNING) << "Failed to set " << CidToString(control_id) << " to "
                   << value;
    return ret;
  }

  return 0;
}

// static
int V4L2CameraDevice::GetControlValue(int fd,
                                      ControlType type,
                                      int32_t* value) {
  DCHECK(value);

  int control_id = ControlTypeToCid(type);
  v4l2_control current = {.id = static_cast<__u32>(control_id)};

  int ret = HANDLE_EINTR(ioctl(fd, VIDIOC_G_CTRL, &current));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(WARNING) << "Failed to get " << CidToString(control_id);
    return ret;
  }
  *value = current.value;

  VLOGF(1) << "Get " << CidToString(control_id) << ", value:" << *value;

  return 0;
}

// static
std::vector<float> V4L2CameraDevice::GetFrameRateList(int fd,
                                                      uint32_t fourcc,
                                                      uint32_t width,
                                                      uint32_t height) {
  constexpr uint64_t kPrecisionFactor = 1'000'000u;
  base::flat_set<uint64_t> frame_rates;

  v4l2_frmivalenum frame_interval = {};
  frame_interval.pixel_format = fourcc;
  frame_interval.width = width;
  frame_interval.height = height;
  for (; TEMP_FAILURE_RETRY(
             ioctl(fd, VIDIOC_ENUM_FRAMEINTERVALS, &frame_interval)) == 0;
       ++frame_interval.index) {
    switch (frame_interval.type) {
      case V4L2_FRMIVAL_TYPE_DISCRETE:
        if (frame_interval.discrete.numerator != 0) {
          frame_rates.insert(kPrecisionFactor *
                             frame_interval.discrete.denominator /
                             frame_interval.discrete.numerator);
        }
        break;
      case V4L2_FRMIVAL_TYPE_CONTINUOUS:
      case V4L2_FRMIVAL_TYPE_STEPWISE:
        // Simply choose the maximum and minimum frame rates for non-discrete
        // types.
        if (frame_interval.stepwise.min.numerator != 0) {
          frame_rates.insert(kPrecisionFactor *
                             frame_interval.stepwise.min.denominator /
                             frame_interval.stepwise.min.numerator);
        }
        if (frame_interval.stepwise.max.numerator != 0) {
          frame_rates.insert(kPrecisionFactor *
                             frame_interval.stepwise.max.denominator /
                             frame_interval.stepwise.max.numerator);
        }
        break;
      default:
        LOGF(WARNING) << "Unknown v4l2_frmivaltypes: " << frame_interval.type;
        continue;
    }
  }
  // Some devices, e.g. Kinect, do not enumerate any frame rates, see
  // http://crbug.com/412284. Set their frame rate to zero.
  if (frame_rates.empty()) {
    frame_rates.insert(0);
  }

  std::vector<float> result;
  for (uint64_t frame_rate : frame_rates) {
    result.push_back(static_cast<float>(frame_rate) / kPrecisionFactor);
  }
  return result;
}

// static
bool V4L2CameraDevice::IsRegionOfInterestSupported(int fd,
                                                   RoiControl* roi_control) {
  DCHECK(roi_control);
  ControlInfo info;

  roi_control->roi_flags = 0;

  v4l2_selection current = {
      .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
      .target = static_cast<__u32>(V4L2_SEL_TGT_ROI_DEFAULT),
  };
  if (HANDLE_EINTR(ioctl(fd, VIDIOC_G_SELECTION, &current)) < 0) {
    PLOGF(WARNING) << "Failed to get selection: " << base::safe_strerror(errno);
    return false;
  }
  roi_control->roi_bounds_default = Rect<int>(
      current.r.left, current.r.top, current.r.width, current.r.height);

  current.target = V4L2_SEL_TGT_ROI_BOUNDS_MIN;
  if (HANDLE_EINTR(ioctl(fd, VIDIOC_G_SELECTION, &current)) < 0) {
    PLOGF(WARNING) << "Failed to get selection: " << base::safe_strerror(errno);
    return false;
  }
  roi_control->min_roi_size = Size(current.r.width, current.r.height);

  current.target = V4L2_SEL_TGT_ROI_BOUNDS_MAX;
  if (HANDLE_EINTR(ioctl(fd, VIDIOC_G_SELECTION, &current)) < 0) {
    PLOGF(WARNING) << "Failed to get selection: " << base::safe_strerror(errno);
    return false;
  }
  roi_control->roi_bounds = Rect<int>(current.r.left, current.r.top,
                                      current.r.width, current.r.height);

  if (QueryControl(fd, kControlRegionOfInterestAuto, &info) != 0) {
    return false;
  }
  // enable max auto controls.
  roi_control->roi_flags = info.range.maximum;

  return true;
}

// static
bool V4L2CameraDevice::IsCameraDevice(const std::string& device_path) {
  // RetryDeviceOpen() assumes the device is a camera and waits until the camera
  // is ready, so we use open() instead of RetryDeviceOpen() here.
  base::ScopedFD fd(TEMP_FAILURE_RETRY(open(device_path.c_str(), O_RDONLY)));
  if (!fd.is_valid()) {
    PLOGF(ERROR) << "Failed to open " << device_path;
    return false;
  }

  v4l2_capability v4l2_cap;
  if (TEMP_FAILURE_RETRY(ioctl(fd.get(), VIDIOC_QUERYCAP, &v4l2_cap)) != 0) {
    return false;
  }

  auto check_mask = [](uint32_t caps) {
    const uint32_t kCaptureMask =
        V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_VIDEO_CAPTURE_MPLANE;
    // Old drivers use (CAPTURE | OUTPUT) for memory-to-memory video devices.
    const uint32_t kOutputMask =
        V4L2_CAP_VIDEO_OUTPUT | V4L2_CAP_VIDEO_OUTPUT_MPLANE;
    const uint32_t kM2mMask = V4L2_CAP_VIDEO_M2M | V4L2_CAP_VIDEO_M2M_MPLANE;
    return (caps & kCaptureMask) && !(caps & kOutputMask) && !(caps & kM2mMask);
  };

  // Prefer to use available capabilities of that specific device node instead
  // of the physical device as a whole, so we can properly ignore the metadata
  // device node.
  if (v4l2_cap.capabilities & V4L2_CAP_DEVICE_CAPS) {
    return check_mask(v4l2_cap.device_caps);
  } else {
    return check_mask(v4l2_cap.capabilities);
  }
}

// static
std::string V4L2CameraDevice::GetModelName(const std::string& device_path) {
  auto get_by_interface = [&](std::string* name) {
    base::FilePath real_path;
    if (!base::NormalizeFilePath(base::FilePath(device_path), &real_path)) {
      return false;
    }
    if (!base::MatchPattern(real_path.value(), "/dev/video*")) {
      return false;
    }
    // /sys/class/video4linux/video{N}/device is a symlink to the corresponding
    // USB device info directory.
    auto interface_path = base::FilePath("/sys/class/video4linux")
                              .Append(real_path.BaseName())
                              .Append("device/interface");
    return base::ReadFileToString(interface_path, name);
  };

  auto get_by_cap = [&](std::string* name) {
    base::ScopedFD fd(RetryDeviceOpen(device_path, O_RDONLY));
    if (!fd.is_valid()) {
      PLOGF(WARNING) << "Failed to open " << device_path;
      return false;
    }

    v4l2_capability cap;
    if (TEMP_FAILURE_RETRY(ioctl(fd.get(), VIDIOC_QUERYCAP, &cap)) != 0) {
      PLOGF(WARNING) << "Failed to query capability of " << device_path;
      return false;
    }
    *name = std::string(reinterpret_cast<const char*>(cap.card));
    return true;
  };

  std::string name;
  if (get_by_interface(&name)) {
    return name;
  }
  if (get_by_cap(&name)) {
    return name;
  }
  return "USB Camera";
}

// static
bool V4L2CameraDevice::IsControlSupported(const std::string& device_path,
                                          ControlType type) {
  ControlInfo info;
  return QueryControl(device_path, type, &info) == 0;
}

// static
int V4L2CameraDevice::QueryControl(const std::string& device_path,
                                   ControlType type,
                                   ControlInfo* info) {
  base::ScopedFD fd(RetryDeviceOpen(device_path, O_RDONLY));
  if (!fd.is_valid()) {
    const int ret = ERRNO_OR_RET(-EINVAL);
    PLOGF(ERROR) << "Failed to open " << device_path;
    return ret;
  }

  int ret = QueryControl(fd.get(), type, info);
  if (ret != 0) {
    return ret;
  }

  VLOGF(1) << ControlTypeToString(type) << "(min,max,step,default) = "
           << "(" << info->range.minimum << "," << info->range.maximum << ","
           << info->range.step << "," << info->range.default_value << ")";

  if (!info->menu_items.empty()) {
    VLOGF(1) << ControlTypeToString(type) << " " << info->menu_items.size()
             << " menu items:";
    for (const auto& item : info->menu_items)
      VLOGF(1) << "    " << item;
  }

  return 0;
}

// static
int V4L2CameraDevice::GetControlValue(const std::string& device_path,
                                      ControlType type,
                                      int32_t* value) {
  base::ScopedFD fd(RetryDeviceOpen(device_path, O_RDONLY));
  if (!fd.is_valid()) {
    const int ret = ERRNO_OR_RET(-EINVAL);
    PLOGF(ERROR) << "Failed to open " << device_path;
    return ret;
  }

  return GetControlValue(fd.get(), type, value);
}

// static
int V4L2CameraDevice::SetControlValue(const std::string& device_path,
                                      ControlType type,
                                      int32_t value) {
  base::ScopedFD fd(RetryDeviceOpen(device_path, O_RDONLY));
  if (!fd.is_valid()) {
    const int ret = ERRNO_OR_RET(-EINVAL);
    PLOGF(ERROR) << "Failed to open " << device_path;
    return ret;
  }

  return SetControlValue(fd.get(), type, value);
}

// static
bool V4L2CameraDevice::IsRegionOfInterestSupported(std::string device_path,
                                                   RoiControl* roi_control) {
  base::ScopedFD fd(RetryDeviceOpen(device_path, O_RDONLY));
  if (!fd.is_valid()) {
    PLOGF(ERROR) << "Failed to open " << device_path;
    return false;
  }

  return IsRegionOfInterestSupported(fd.get(), roi_control);
}

// static
int V4L2CameraDevice::RetryDeviceOpen(const std::string& device_path,
                                      int flags) {
  constexpr base::TimeDelta kDeviceOpenTimeOut = base::Milliseconds(2000);
  constexpr base::TimeDelta kSleepTime = base::Milliseconds(100);
  int fd;
  base::ElapsedTimer timer;
  base::TimeDelta elapsed_time = timer.Elapsed();
  while (elapsed_time < kDeviceOpenTimeOut) {
    fd = TEMP_FAILURE_RETRY(open(device_path.c_str(), flags));
    if (fd != -1) {
      // Make sure ioctl is ok. Once ioctl failed, we have to re-open the
      // device.
      struct v4l2_fmtdesc v4l2_format = {};
      v4l2_format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
      int ret = TEMP_FAILURE_RETRY(ioctl(fd, VIDIOC_ENUM_FMT, &v4l2_format));
      if (ret == -1) {
        close(fd);
        if (errno != EPERM) {
          break;
        } else {
          VLOGF(1) << "Camera ioctl is not ready";
        }
      } else {
        // Only return fd when ioctl is ready.
        if (elapsed_time >= kSleepTime) {
          LOGF(INFO) << "Opened the camera device after waiting for "
                     << elapsed_time << " ms";
        }
        return fd;
      }
    } else if (errno != EACCES && errno != EBUSY && errno != ENOENT) {
      break;
    }
    base::PlatformThread::Sleep(kSleepTime);
    elapsed_time = timer.Elapsed();
  }
  PLOGF(ERROR) << "Failed to open " << device_path;
  return -1;
}

// static
clockid_t V4L2CameraDevice::GetUvcClock() {
  static const clockid_t kUvcClock = [] {
    const base::FilePath kClockPath("/sys/module/uvcvideo/parameters/clock");
    std::string clock;
    if (base::ReadFileToString(kClockPath, &clock)) {
      if (clock.find("REALTIME") != std::string::npos) {
        return CLOCK_REALTIME;
      } else if (clock.find("BOOTTIME") != std::string::npos) {
        return CLOCK_BOOTTIME;
      } else {
        return CLOCK_MONOTONIC;
      }
    }
    // Use UVC default clock.
    return CLOCK_MONOTONIC;
  }();
  return kUvcClock;
}

// static
int V4L2CameraDevice::GetUserSpaceTimestamp(timespec& ts) {
  int ret = clock_gettime(V4L2CameraDevice::GetUvcClock(), &ts);
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    LOGF(ERROR) << "Get clock time fails";
  }
  return ret;
}

// static
bool V4L2CameraDevice::IsFocusDistanceSupported(
    const std::string& device_path, ControlRange* focus_distance_range) {
  DCHECK(focus_distance_range != nullptr);

  if (!IsControlSupported(device_path, kControlFocusAuto))
    return false;

  ControlInfo info;
  if (QueryControl(device_path, kControlFocusDistance, &info) != 0) {
    return false;
  }

  *focus_distance_range = info.range;

  return true;
}

// static
bool V4L2CameraDevice::IsManualExposureTimeSupported(
    const std::string& device_path, ControlRange* exposure_time_range) {
  ControlInfo info;

  DCHECK(exposure_time_range);

  if (QueryControl(device_path, kControlExposureAuto, &info) != 0)
    return false;

  bool found_manual_type = false;
  bool found_auto_type = false;
  for (const auto& item : info.menu_items) {
    if (item == kExposureTypeMenuStringManual) {
      found_manual_type = true;
    } else if (item == kExposureTypeMenuStringShutterPriority) {
      found_manual_type = true;
    } else if (item == kExposureTypeMenuStringAuto) {
      found_auto_type = true;
    } else if (item == kExposureTypeMenuStringAperturePriority) {
      found_auto_type = true;
    }
  }

  if (!found_manual_type || !found_auto_type)
    return false;

  if (QueryControl(device_path, kControlExposureTime, &info) != 0) {
    LOGF(WARNING) << "Can't get exposure time range";
    return false;
  }
  *exposure_time_range = info.range;

  return true;
}

int V4L2CameraDevice::SetPowerLineFrequency() {
  ControlInfo info;
  if (QueryControl(device_fd_.get(), kControlPowerLineFrequency, &info) < 0) {
    LOGF(ERROR) << "Failed to query power line frequency";
    return -EINVAL;
  }

  // Prefer auto setting if camera module supports auto mode.
  if (info.range.maximum == V4L2_CID_POWER_LINE_FREQUENCY_AUTO &&
      SetControlValue(device_fd_.get(), kControlPowerLineFrequency,
                      V4L2_CID_POWER_LINE_FREQUENCY_AUTO) == 0) {
    LOGF(INFO) << "Set power line frequency("
               << static_cast<int>(V4L2_CID_POWER_LINE_FREQUENCY_AUTO)
               << ") successfully";
    return 0;
  }
  if (info.range.minimum >= V4L2_CID_POWER_LINE_FREQUENCY_60HZ) {
    // TODO(shik): Handle this more gracefully for external camera
    LOGF(ERROR) << "Camera module should at least support 50/60Hz";
    return -EINVAL;
  }

  // Set power line frequency for location.
  std::optional<v4l2_power_line_frequency> location_frequency =
      GetPowerLineFrequencyForLocation();
  if (location_frequency.has_value() &&
      SetControlValue(device_fd_.get(), kControlPowerLineFrequency,
                      location_frequency.value()) == 0) {
    LOGF(INFO) << "Set power line frequency(" << location_frequency.value()
               << ") successfully";
    return 0;
  }

  // Set device default power line frequency.
  if ((!location_frequency.has_value() ||
       info.range.default_value != location_frequency.value()) &&
      SetControlValue(device_fd_.get(), kControlPowerLineFrequency,
                      info.range.default_value) == 0) {
    LOGF(INFO) << "Set power line frequency("
               << static_cast<int>(info.range.default_value)
               << ") successfully";
    return 0;
  }

  LOGF(ERROR) << "Error setting power line frequency";
  return -EINVAL;
}

bool V4L2CameraDevice::IsExternalCamera() {
  return device_info_.lens_facing == LensFacing::kExternal;
}

int V4L2CameraDevice::EnqueueBuffer(v4l2_buffer& buffer) {
  int ret = TEMP_FAILURE_RETRY(ioctl(device_fd_.get(), VIDIOC_QBUF, &buffer));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(ERROR) << "QBUF (" << buffer.index << ") fails";
    return ret;
  }
  buffers_at_client_[buffer.index] = false;
  return 0;
}

int V4L2CameraDevice::StartStreaming() {
  v4l2_buf_type capture_type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  int ret = ioctl(device_fd_.get(), VIDIOC_STREAMON, &capture_type);
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(ERROR) << "STREAMON fails";
  }
  return ret;
}

int V4L2CameraDevice::StopStreaming() {
  v4l2_buf_type capture_type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  int ret = TEMP_FAILURE_RETRY(
      ioctl(device_fd_.get(), VIDIOC_STREAMOFF, &capture_type));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(ERROR) << "STREAMOFF fails";
  }
  return ret;
}

}  // namespace cros
