// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hal/usb/tests/media_v4l2_device.h"

#include <poll.h>
#include <sys/stat.h>

#include <cassert>
#include <ctime>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/strings/stringprintf.h>

#include "cros-camera/common.h"

#define MAJOR(dev) (((uint32_t)(dev)) >> 8)
#define MINOR(dev) (((uint32_t)(dev)) & 0xff)
#define V4L2_VIDEO_CAPTURE_MAJOR 81
#define V4L2_VIDEO_CAPTURE_MINOR_MIN 0
#define V4L2_VIDEO_CAPTURE_MINOR_MAX 64

V4L2Device::V4L2Device(const char* dev_name, uint32_t buffers)
    : dev_name_(dev_name),
      io_(IO_METHOD_UNDEFINED),
      fd_(-1),
      v4l2_buffers_(NULL),
      num_buffers_(0),
      min_buffers_(buffers),
      stopped_(false),
      initialized_(false) {}

V4L2Device::~V4L2Device() {
  if (initialized_) {
    if (stream_on_) {
      StopCapture();
    }
    UninitDevice();
  }
  CloseDevice();
}

bool V4L2Device::OpenDevice(bool show_err) {
  struct stat st;
  if (-1 == stat(dev_name_, &st)) {
    if (show_err) {
      PLOGF(ERROR) << base::StringPrintf("Could not find v4l2 device %s",
                                         dev_name_);
    }
    return false;
  }

  if (!S_ISCHR(st.st_mode)) {
    if (show_err) {
      LOGF(ERROR) << base::StringPrintf(
          "Specified v4l2 device %s is not char device", dev_name_);
    }
    return false;
  }

  if (MAJOR(st.st_rdev) != V4L2_VIDEO_CAPTURE_MAJOR ||
      MINOR(st.st_rdev) >= V4L2_VIDEO_CAPTURE_MINOR_MAX) {
    if (show_err) {
      LOGF(ERROR) << base::StringPrintf(
          "Specified v4l2 device %s is not v4l2 device", dev_name_);
    }
    return false;
  }

  fd_ = open(dev_name_, O_RDWR | O_NONBLOCK, 0);
  if (-1 == fd_) {
    if (show_err) {
      LOGF(ERROR) << base::StringPrintf(
          "Specified v4l2 device %s could not be opened", dev_name_);
    }
    return false;
  }

  v4l2_capability cap;
  if (!ProbeCaps(&cap))
    return false;

  if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
    if (show_err) {
      LOGF(ERROR) << base::StringPrintf("%s does not support video capture",
                                        dev_name_);
    }
    return false;
  }

  return true;
}

void V4L2Device::CloseDevice() {
  if (fd_ != -1)
    close(fd_);
  fd_ = -1;
}

bool V4L2Device::InitDevice(IOMethod io,
                            uint32_t width,
                            uint32_t height,
                            uint32_t pixfmt,
                            float fps,
                            ConstantFramerate constant_framerate,
                            uint32_t num_skip_frames) {
  io_ = io;

  v4l2_format fmt;
  if (!GetV4L2Format(&fmt))
    return false;

  fmt.fmt.pix.width = width;
  fmt.fmt.pix.height = height;
  fmt.fmt.pix.pixelformat = pixfmt;
  fmt.fmt.pix.field = V4L2_FIELD_NONE;

  if (-1 == DoIoctl(VIDIOC_S_FMT, &fmt)) {
    LOGF(ERROR) << base::StringPrintf("VIDIOC_S_FMT on %s", dev_name_);
    return false;
  }

  v4l2_capability cap;
  if (!ProbeCaps(&cap))
    return false;

  switch (io_) {
    case IO_METHOD_MMAP:
    case IO_METHOD_USERPTR:
      if (!(cap.capabilities & V4L2_CAP_STREAMING)) {
        LOGF(ERROR) << base::StringPrintf("%s does not support streaming",
                                          dev_name_);
        return false;
      }
      break;
    default:
      LOGF(ERROR) << "IO method should be defined";
      return false;
  }

  v4l2_streamparm param;
  if (!GetParam(&param))
    return false;

  if (param.parm.capture.capability & V4L2_CAP_TIMEPERFRAME) {
    if (fps > 0) {
      SetFrameRate(fps);
    } else {
      LOGF(ERROR) << base::StringPrintf("Fps %f should be a positive number",
                                        fps);
      return false;
    }
  }
  float actual_fps = GetFrameRate();

  int32_t constant_framerate_setting;
  std::string constant_framerate_msg = "";
  switch (constant_framerate) {
    case DEFAULT_FRAMERATE_SETTING:
      constant_framerate_setting = 1;
      break;
    case ENABLE_CONSTANT_FRAMERATE:
      constant_framerate_setting = 0;
      constant_framerate_msg = " with constant framerate";
      break;
    case DISABLE_CONSTANT_FRAMERATE:
      constant_framerate_setting = 1;
      constant_framerate_msg = " without constant framerate";
      break;
    default:
      LOGF(ERROR) << base::StringPrintf(
          "Invalid constant framerate setting: %d", constant_framerate);
      return false;
  }
  SetControl(V4L2_CID_EXPOSURE_AUTO_PRIORITY, constant_framerate_setting);

  LOGF(INFO) << base::StringPrintf(
      "Actual format for capture %dx%d %c%c%c%c picture at %.2f fps%s",
      fmt.fmt.pix.width, fmt.fmt.pix.height, (pixfmt >> 0) & 0xff,
      (pixfmt >> 8) & 0xff, (pixfmt >> 16) & 0xff, (pixfmt >> 24) & 0xff,
      actual_fps, constant_framerate_msg.c_str());
  frame_timestamps_.clear();
  num_skip_frames_ = num_skip_frames;

  bool ret = false;
  switch (io_) {
    case IO_METHOD_MMAP:
      ret = InitMmapIO();
      break;
    case IO_METHOD_USERPTR:
      ret = InitUserPtrIO(fmt.fmt.pix.sizeimage);
      break;
    default:
      LOGF(ERROR) << "IO method should be defined";
      return false;
  }
  if (ret)
    initialized_ = true;
  return ret;
}

bool V4L2Device::UninitDevice() {
  if (!initialized_) {
    return true;
  }
  v4l2_requestbuffers req;
  memset(&req, 0, sizeof(req));
  req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  switch (io_) {
    case IO_METHOD_MMAP:
      for (uint32_t i = 0; i < num_buffers_; ++i)
        if (-1 == munmap(v4l2_buffers_[i].start, v4l2_buffers_[i].length)) {
          PLOGF(ERROR) << base::StringPrintf("munmap() on %s failed",
                                             dev_name_);
          return false;
        }

      req.memory = V4L2_MEMORY_MMAP;
      if (-1 == DoIoctl(VIDIOC_REQBUFS, &req)) {
        PLOGF(ERROR) << base::StringPrintf(
            "VIDIOC_REQBUFS for MMAP failed on %s", dev_name_);
        return false;
      }
      break;
    case IO_METHOD_USERPTR:
      req.memory = V4L2_MEMORY_USERPTR;
      if (-1 == DoIoctl(VIDIOC_REQBUFS, &req)) {
        PLOGF(ERROR) << base::StringPrintf(
            "VIDIOC_REQBUFS for USERPTR failed on %s", dev_name_);
        return false;
      }

      for (uint32_t i = 0; i < num_buffers_; ++i)
        free(v4l2_buffers_[i].start);
      break;
    default:
      LOGF(ERROR) << "IO method should be defined";
      return false;
  }
  FreeBuffer();
  initialized_ = false;
  return true;
}

bool V4L2Device::StartCapture() {
  for (uint32_t i = 0; i < num_buffers_; ++i) {
    if (!EnqueueBuffer(i))
      return false;
  }
  v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  if (-1 == DoIoctl(VIDIOC_STREAMON, &type)) {
    LOGF(ERROR) << base::StringPrintf("VIDIOC_STREAMON on %s", dev_name_);
    return false;
  }
  stream_on_ = true;

  uint32_t buf_index, data_size;
  for (size_t i = 0; i < num_skip_frames_; i++) {
    int ret;
    do {
      ret = ReadOneFrame(&buf_index, &data_size);
    } while (ret == 0);
    if (ret < 0)
      return false;
    if (!EnqueueBuffer(buf_index))
      return false;
  }

  return true;
}

bool V4L2Device::StopCapture() {
  if (!stream_on_) {
    return true;
  }
  v4l2_buf_type type;
  switch (io_) {
    case IO_METHOD_MMAP:
    case IO_METHOD_USERPTR:
      type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
      if (-1 == DoIoctl(VIDIOC_STREAMOFF, &type)) {
        LOGF(ERROR) << base::StringPrintf("VIDIOC_STREAMOFF on %s", dev_name_);
        return false;
      }
      break;
    default:
      LOGF(ERROR) << "IO method should be defined";
      return false;
  }
  stream_on_ = false;
  return true;
}

// Do capture for duration of |time_in_sec|.
bool V4L2Device::Run(uint32_t time_in_sec) {
  stopped_ = false;
  if (!time_in_sec)
    return false;

  uint64_t start_in_nanosec = 0;
  uint32_t buffer_index, data_size;
  while (!stopped_) {
    int32_t r = ReadOneFrame(&buffer_index, &data_size);
    if (r < 0)
      return false;
    if (r) {
      if (start_in_nanosec == 0)
        start_in_nanosec = Now();
      ProcessImage(v4l2_buffers_[buffer_index].start);
      if (!EnqueueBuffer(buffer_index))
        return false;
    }
    if (start_in_nanosec) {
      uint64_t end_in_nanosec = Now();
      if (end_in_nanosec - start_in_nanosec >= time_in_sec * 1000000000ULL)
        break;
    }
  }
  // All resolutions should have at least 1 fps.
  float actual_fps = static_cast<float>(GetNumFrames() - 1) / time_in_sec;
  LOGF(INFO) << base::StringPrintf("Actual fps is %f on %s", actual_fps,
                                   dev_name_);
  return true;
}

bool V4L2Device::Stop() {
  stopped_ = true;
  return true;
}

int32_t V4L2Device::DoIoctl(int32_t request, void* arg) {
  int32_t r;
  do {
    r = ioctl(fd_, request, arg);
  } while (-1 == r && EINTR == errno);
  return r;
}

// return 1 : successful to retrieve a frame from device
// return 0 : EAGAIN
// negative : error
int32_t V4L2Device::ReadOneFrame(uint32_t* buffer_index, uint32_t* data_size) {
  const int kCaptureTimeoutMs = 1000;
  pollfd device_pfd = {};
  device_pfd.fd = fd_;
  device_pfd.events = POLLIN;
  const int result = poll(&device_pfd, 1, kCaptureTimeoutMs);
  if (result < 0) {
    PLOGF(ERROR) << base::StringPrintf("poll() failed on %s", dev_name_);
    return -1;
  }
  if (result == 0) {
    return 0;
  }

  v4l2_buffer buf;
  int64_t ts;
  memset(&buf, 0, sizeof(buf));
  switch (io_) {
    case IO_METHOD_MMAP:
      buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
      buf.memory = V4L2_MEMORY_MMAP;
      if (-1 == DoIoctl(VIDIOC_DQBUF, &buf)) {
        switch (errno) {
          case EAGAIN:
            return 0;
          case EIO:
            // Could ignore EIO, see spec.
            // Fall through.
          default:
            LOGF(ERROR) << base::StringPrintf("VIDIOC_DQBUF failed on %s",
                                              dev_name_);
            return -2;
        }
      }
      // For checking constant frame rate, we have to use HW timestamp from
      // v4l2_buffer to get more stable timestamp.
      // Since kerenel after 3.18 have a fix to disable hardware timestamp
      // (https://patchwork.kernel.org/patch/6874491/), we have to manually
      // enable HW timestamp via /sys/module/uvcvideo/parameters/hwtimestamps.
      ts = buf.timestamp.tv_sec * 1000000000LL + buf.timestamp.tv_usec * 1000;
      frame_timestamps_.push_back(ts);
      CHECK(buf.index < num_buffers_);
      // TODO(henryhsu): uvcvideo driver ignores this field. This is negligible,
      // so disabling this for now until we get a fix into the upstream driver.
      // CHECK(buf.field == V4L2_FIELD_NONE);  // progressive only.
      break;
    case IO_METHOD_USERPTR:
      buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
      buf.memory = V4L2_MEMORY_USERPTR;
      if (-1 == DoIoctl(VIDIOC_DQBUF, &buf)) {
        switch (errno) {
          case EAGAIN:
            return 0;
          case EIO:
            // Could ignore EIO, see spec.
            // Fall through.
          default:
            LOGF(ERROR) << base::StringPrintf("VIDIOC_DQBUF failed on %s",
                                              dev_name_);
            return -2;
        }
      }
      ts = buf.timestamp.tv_sec * 1000000000LL + buf.timestamp.tv_usec * 1000;
      frame_timestamps_.push_back(ts);
      CHECK(buf.index < num_buffers_);
      break;
    default:
      LOGF(ERROR) << "IO method should be defined";
      return -1;
  }
  if (buffer_index)
    *buffer_index = buf.index;
  if (data_size)
    *data_size = buf.bytesused;
  return 1;
}

bool V4L2Device::EnqueueBuffer(uint32_t buffer_index) {
  v4l2_buffer buf;
  memset(&buf, 0, sizeof(buf));
  switch (io_) {
    case IO_METHOD_MMAP:
      buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
      buf.memory = V4L2_MEMORY_MMAP;
      buf.index = buffer_index;
      if (-1 == DoIoctl(VIDIOC_QBUF, &buf)) {
        LOGF(ERROR) << base::StringPrintf("VIDIOC_QBUF failed on %s",
                                          dev_name_);
        return false;
      }
      break;
    case IO_METHOD_USERPTR:
      buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
      buf.memory = V4L2_MEMORY_USERPTR;
      buf.index = buffer_index;
      buf.m.userptr =
          reinterpret_cast<uintptr_t>(v4l2_buffers_[buffer_index].start);
      buf.length = v4l2_buffers_[buffer_index].length;
      if (-1 == DoIoctl(VIDIOC_QBUF, &buf)) {
        LOGF(ERROR) << base::StringPrintf("VIDIOC_QBUF failed on %s",
                                          dev_name_);
        return false;
      }
      break;
    default:
      LOGF(ERROR) << "IO method should be defined";
      return false;
  }
  return true;
}

bool V4L2Device::AllocateBuffer(uint32_t buffer_count) {
  v4l2_buffers_ = new Buffer[buffer_count];
  if (!v4l2_buffers_) {
    LOGF(ERROR) << "Out of memory";
    return false;
  }
  return true;
}

bool V4L2Device::FreeBuffer() {
  free(v4l2_buffers_);
  v4l2_buffers_ = NULL;
  return true;
}

bool V4L2Device::InitMmapIO() {
  v4l2_requestbuffers req;
  memset(&req, 0, sizeof(req));
  req.count = min_buffers_;
  req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  req.memory = V4L2_MEMORY_MMAP;
  if (-1 == DoIoctl(VIDIOC_REQBUFS, &req)) {
    if (EINVAL == errno)
      LOGF(ERROR) << base::StringPrintf("mmap() io is not supported on %s",
                                        dev_name_);
    else
      PLOGF(ERROR) << base::StringPrintf(
          "VIDIOC_REQBUFS for MMAP(%d) failed on %s", min_buffers_, dev_name_);
    return false;
  }

  if (req.count < min_buffers_) {
    LOGF(ERROR) << base::StringPrintf("Insufficient buffer memory on %s",
                                      dev_name_);
    return false;
  }

  if (!AllocateBuffer(req.count))
    return false;

  for (num_buffers_ = 0; num_buffers_ < req.count; ++num_buffers_) {
    v4l2_buffer buf;
    memset(&buf, 0, sizeof(buf));
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = num_buffers_;
    if (-1 == DoIoctl(VIDIOC_QUERYBUF, &buf)) {
      LOGF(ERROR) << base::StringPrintf("VIDIOC_QUERYBUF failed on %s",
                                        dev_name_);
      return false;
    }
    v4l2_buffers_[num_buffers_].length = buf.length;
    v4l2_buffers_[num_buffers_].start =
        mmap(NULL,  // Start anywhere.
             buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, buf.m.offset);
    if (MAP_FAILED == v4l2_buffers_[num_buffers_].start) {
      LOGF(ERROR) << base::StringPrintf("mmap() failed on %s", dev_name_);
      return false;
    }
  }
  return true;
}

bool V4L2Device::InitUserPtrIO(uint32_t buffer_size) {
  v4l2_requestbuffers req;
  memset(&req, 0, sizeof(req));
  req.count = min_buffers_;
  req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  req.memory = V4L2_MEMORY_USERPTR;

  // Align up buffer_size to page size boundary.
  uint32_t page_size = getpagesize();
  buffer_size = (buffer_size + page_size - 1) & ~(page_size - 1);
  if (-1 == DoIoctl(VIDIOC_REQBUFS, &req)) {
    if (EINVAL == errno)
      LOGF(ERROR) << base::StringPrintf("User pointer is not supported on %s",
                                        dev_name_);
    else
      PLOGF(ERROR) << base::StringPrintf(
          "VIDIOC_REQBUFS for USERPTR(%d) failed on %s", min_buffers_,
          dev_name_);
    return false;
  }

  if (!AllocateBuffer(req.count))
    return false;

  for (num_buffers_ = 0; num_buffers_ < req.count; ++num_buffers_) {
    v4l2_buffers_[num_buffers_].length = buffer_size;
    v4l2_buffers_[num_buffers_].start = memalign(page_size, buffer_size);

    if (!v4l2_buffers_[num_buffers_].start) {
      LOGF(ERROR) << "Out of memory";
      return false;
    }
  }
  return true;
}

bool V4L2Device::EnumInput() {
  v4l2_input input;
  int32_t index;
  if (-1 == DoIoctl(VIDIOC_G_INPUT, &index)) {
    LOGF(INFO) << "VIDIOC_G_INPUT not supported";
    return false;
  }

  for (int32_t i = 0;; ++i) {
    memset(&input, 0, sizeof(input));
    input.index = i;
    if (-1 == DoIoctl(VIDIOC_ENUMINPUT, &input)) {
      if (i == 0) {
        LOGF(INFO) << "VIDIOC_ENUMINPUT not supported";
        return false;
      } else {
        break;
      }
    }
    LOGF(INFO) << base::StringPrintf("Current input: %s %s", input.name,
                                     i == index ? "*" : "");
  }
  return true;
}

bool V4L2Device::EnumStandard() {
  v4l2_input input;
  v4l2_standard standard;
  memset(&input, 0, sizeof(input));
  if (-1 == DoIoctl(VIDIOC_G_INPUT, &input.index)) {
    LOGF(INFO) << "VIDIOC_G_INPUT not supported";
    return false;
  }

  if (-1 == DoIoctl(VIDIOC_ENUMINPUT, &input)) {
    LOGF(INFO) << "VIDIOC_ENUMINPUT not supported";
    return false;
  }

  LOGF(INFO) << base::StringPrintf("Current input %s supports:", input.name);
  memset(&standard, 0, sizeof(standard));
  standard.index = 0;
  while (0 == DoIoctl(VIDIOC_ENUMSTD, &standard)) {
    if (standard.id & input.std)
      LOGF(INFO) << base::StringPrintf("%s", standard.name);
    standard.index++;
  }
  // EINVAL indicates the end of the enumeration, which cannot be
  // empty unless this device falls under the USB exception.
  if (errno != EINVAL || standard.index == 0) {
    LOGF(INFO) << "VIDIOC_ENUMSTD not supported";
    return false;
  }
  return true;
}

bool V4L2Device::EnumControl(bool show_menu) {
  v4l2_queryctrl query_ctrl;
  memset(&query_ctrl, 0, sizeof(query_ctrl));
  // Query V4L2_CID_CAMERA_CLASS_BASE is for V4L2_CID_EXPOSURE_AUTO_PRIORITY.
  std::vector<std::pair<uint32_t, uint32_t>> query_ctrl_sets;
  query_ctrl_sets.push_back(std::make_pair(V4L2_CID_BASE, V4L2_CID_LASTP1));
  query_ctrl_sets.push_back(
      std::make_pair(V4L2_CID_CAMERA_CLASS_BASE, V4L2_CID_TILT_SPEED));

  for (int i = 0; i < query_ctrl_sets.size(); i++) {
    for (query_ctrl.id = query_ctrl_sets[i].first;
         query_ctrl.id < query_ctrl_sets[i].second; ++query_ctrl.id) {
      if (0 == DoIoctl(VIDIOC_QUERYCTRL, &query_ctrl)) {
        if (query_ctrl.flags & V4L2_CTRL_FLAG_DISABLED) {
          LOGF(INFO) << base::StringPrintf("Control %s is disabled",
                                           query_ctrl.name);
        } else {
          LOGF(INFO) << base::StringPrintf(
              "Control %s is enabled(%d-%d:%d)", query_ctrl.name,
              query_ctrl.minimum, query_ctrl.maximum, query_ctrl.default_value);
        }
        if (query_ctrl.type == V4L2_CTRL_TYPE_MENU && show_menu)
          EnumControlMenu(query_ctrl);
      } else if (errno != EINVAL) {
        LOGF(INFO) << "VIDIOC_query_ctrl not supported";
        return false;
      }
    }
  }

  for (query_ctrl.id = V4L2_CID_PRIVATE_BASE;; query_ctrl.id++) {
    if (0 == DoIoctl(VIDIOC_QUERYCTRL, &query_ctrl)) {
      if (query_ctrl.flags & V4L2_CTRL_FLAG_DISABLED)
        LOGF(INFO) << base::StringPrintf("Private Control %s is disabled",
                                         query_ctrl.name);
      else
        LOGF(INFO) << base::StringPrintf("Private Control %s is enabled",
                                         query_ctrl.name);
      if (query_ctrl.type == V4L2_CTRL_TYPE_MENU && show_menu)
        EnumControlMenu(query_ctrl);
    } else {
      // Assume private control ids are contiguous.
      if (errno == EINVAL)
        break;
      LOGF(INFO) << "VIDIOC_query_ctrl not supported";
      return false;
    }
  }
  return true;
}

bool V4L2Device::EnumControlMenu(const v4l2_queryctrl& query_ctrl) {
  v4l2_querymenu query_menu;
  memset(&query_menu, 0, sizeof(query_menu));
  LOGF(INFO) << "Menu items:";
  query_menu.id = query_ctrl.id;
  for (query_menu.index = query_ctrl.minimum;
       query_menu.index <= query_ctrl.maximum; ++query_menu.index) {
    if (0 == DoIoctl(VIDIOC_QUERYMENU, &query_menu)) {
      LOGF(INFO) << base::StringPrintf("\t%s", query_menu.name);
    } else {
      LOGF(INFO) << "VIDIOC_QUERYMENU not supported";
      return false;
    }
  }
  return true;
}

bool V4L2Device::EnumFormat(uint32_t* num_formats, bool show_fmt) {
  uint32_t i;
  for (i = 0;; ++i) {
    v4l2_fmtdesc format_desc;
    memset(&format_desc, 0, sizeof(format_desc));
    format_desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    format_desc.index = i;
    if (-1 == DoIoctl(VIDIOC_ENUM_FMT, &format_desc)) {
      if (i == 0) {
        LOGF(INFO) << "VIDIOC_ENUM_FMT not supported";
        return false;
      } else {
        break;
      }
    }
    if (show_fmt)
      LOGF(INFO) << base::StringPrintf("Supported format #%d: %s (%c%c%c%c)",
                                       i + 1, format_desc.description,
                                       (format_desc.pixelformat >> 0) & 0xff,
                                       (format_desc.pixelformat >> 8) & 0xff,
                                       (format_desc.pixelformat >> 16) & 0xff,
                                       (format_desc.pixelformat >> 24) & 0xff);
  }

  if (num_formats)
    *num_formats = i;
  return true;
}

bool V4L2Device::GetPixelFormat(uint32_t index, uint32_t* pixfmt) {
  v4l2_fmtdesc format_desc;
  memset(&format_desc, 0, sizeof(format_desc));
  format_desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  format_desc.index = index;
  if (-1 == DoIoctl(VIDIOC_ENUM_FMT, &format_desc))
    return false;
  if (pixfmt)
    *pixfmt = format_desc.pixelformat;
  return true;
}

bool V4L2Device::EnumFrameSize(uint32_t pixfmt,
                               uint32_t* num_sizes,
                               bool show_frmsize) {
  uint32_t i;
  for (i = 0;; ++i) {
    v4l2_frmsizeenum frmsize_desc;
    memset(&frmsize_desc, 0, sizeof(frmsize_desc));
    frmsize_desc.pixel_format = pixfmt;
    frmsize_desc.index = i;
    if (-1 == DoIoctl(VIDIOC_ENUM_FRAMESIZES, &frmsize_desc)) {
      if (i == 0) {
        LOGF(INFO) << "VIDIOC_ENUM_FRAMESIZES not supported";
        return false;
      } else {
        break;
      }
    }
    if (show_frmsize) {
      switch (frmsize_desc.type) {
        case V4L2_FRMSIZE_TYPE_DISCRETE:
          LOGF(INFO) << base::StringPrintf(
              "Supported discrete frame size #%d: for pixel format(%c%c%c%c): "
              "%dx%d",
              i + 1, (pixfmt >> 0) & 0xff, (pixfmt >> 8) & 0xff,
              (pixfmt >> 16) & 0xff, (pixfmt >> 24) & 0xff,
              frmsize_desc.discrete.width, frmsize_desc.discrete.height);
          break;
        case V4L2_FRMSIZE_TYPE_CONTINUOUS:
          LOGF(INFO) << base::StringPrintf(
              "Supported discrete frame size #%d: for pixel format(%c%c%c%c): "
              "from %dx%d to %dx%d",
              i + 1, (pixfmt >> 0) & 0xff, (pixfmt >> 8) & 0xff,
              (pixfmt >> 16) & 0xff, (pixfmt >> 24) & 0xff,
              frmsize_desc.stepwise.min_width, frmsize_desc.stepwise.min_height,
              frmsize_desc.stepwise.max_width,
              frmsize_desc.stepwise.max_height);
          break;
        case V4L2_FRMSIZE_TYPE_STEPWISE:
          LOGF(INFO) << base::StringPrintf(
              "Supported discrete frame size #%d: for pixel format(%c%c%c%c): "
              "from %dx%d to %dx%d step(%d,%d)",
              i + 1, (pixfmt >> 0) & 0xff, (pixfmt >> 8) & 0xff,
              (pixfmt >> 16) & 0xff, (pixfmt >> 24) & 0xff,
              frmsize_desc.stepwise.min_width, frmsize_desc.stepwise.min_height,
              frmsize_desc.stepwise.max_width, frmsize_desc.stepwise.max_height,
              frmsize_desc.stepwise.step_width,
              frmsize_desc.stepwise.step_height);
          break;
      }
    }
  }
  if (num_sizes)
    *num_sizes = i;
  return true;
}

bool V4L2Device::GetFrameSize(uint32_t index,
                              uint32_t pixfmt,
                              uint32_t* width,
                              uint32_t* height) {
  v4l2_frmsizeenum frmsize_desc;
  memset(&frmsize_desc, 0, sizeof(frmsize_desc));
  frmsize_desc.pixel_format = pixfmt;
  frmsize_desc.index = index;
  if (-1 == DoIoctl(VIDIOC_ENUM_FRAMESIZES, &frmsize_desc)) {
    LOGF(ERROR) << "VIDIOC_ENUM_FRAMESIZES not supported";
    return false;
  }
  if (frmsize_desc.type != V4L2_FRMSIZE_TYPE_DISCRETE) {
    LOGF(ERROR) << base::StringPrintf("Frame size type %d not supported",
                                      frmsize_desc.type);
    return false;
  }

  if (width && height) {
    *width = frmsize_desc.discrete.width;
    *height = frmsize_desc.discrete.height;
  }
  return true;
}

bool V4L2Device::EnumFrameInterval(uint32_t pixfmt,
                                   uint32_t width,
                                   uint32_t height,
                                   uint32_t* num_intervals,
                                   bool show_intervals) {
  uint32_t i;
  for (i = 0;; ++i) {
    v4l2_frmivalenum frm_interval;
    memset(&frm_interval, 0, sizeof(frm_interval));
    frm_interval.pixel_format = pixfmt;
    frm_interval.width = width;
    frm_interval.height = height;
    frm_interval.index = i;
    if (-1 == DoIoctl(VIDIOC_ENUM_FRAMEINTERVALS, &frm_interval)) {
      if (i == 0) {
        LOGF(ERROR) << "VIDIOC_ENUM_FRAMEINTERVALS not supported";
        return false;
      } else {
        break;
      }
    }
    if (show_intervals) {
      switch (frm_interval.type) {
        case V4L2_FRMIVAL_TYPE_DISCRETE:
          LOGF(INFO) << base::StringPrintf(
              "Supported discrete frame interval #%d: for pixel "
              "format(%c%c%c%c): %dx%d: %d/%d",
              i + 1, (pixfmt >> 0) & 0xff, (pixfmt >> 8) & 0xff,
              (pixfmt >> 16) & 0xff, (pixfmt >> 24) & 0xff, width, height,
              frm_interval.discrete.numerator,
              frm_interval.discrete.denominator);
          break;
        case V4L2_FRMIVAL_TYPE_CONTINUOUS:
          LOGF(INFO) << base::StringPrintf(
              "Supported continuous frame interval #%d: for pixel "
              "format(%c%c%c%c): %dx%d: from %d/%d to %d/%d",
              i + 1, (pixfmt >> 0) & 0xff, (pixfmt >> 8) & 0xff,
              (pixfmt >> 16) & 0xff, (pixfmt >> 24) & 0xff, width, height,
              frm_interval.stepwise.min.numerator,
              frm_interval.stepwise.min.denominator,
              frm_interval.stepwise.max.numerator,
              frm_interval.stepwise.max.denominator);
          break;
        case V4L2_FRMIVAL_TYPE_STEPWISE:
          LOGF(INFO) << base::StringPrintf(
              "Supported stepwise frame interval #%d: for pixel "
              "format(%c%c%c%c): %dx%d: from %d/%d to %d/%d step(%d,%d)",
              i + 1, (pixfmt >> 0) & 0xff, (pixfmt >> 8) & 0xff,
              (pixfmt >> 16) & 0xff, (pixfmt >> 24) & 0xff, width, height,
              frm_interval.stepwise.min.numerator,
              frm_interval.stepwise.min.denominator,
              frm_interval.stepwise.max.numerator,
              frm_interval.stepwise.max.denominator,
              frm_interval.stepwise.step.numerator,
              frm_interval.stepwise.step.denominator);
          break;
        default:
          LOGF(ERROR) << base::StringPrintf(
              "Unsupported frame interval type %d: for index %d pixel "
              "format(%c%c%c%c): %dx%d",
              frm_interval.type, i + 1, (pixfmt >> 0) & 0xff,
              (pixfmt >> 8) & 0xff, (pixfmt >> 16) & 0xff,
              (pixfmt >> 24) & 0xff, width, height);
          return false;
      }
    }
  }
  if (num_intervals)
    *num_intervals = i;
  return true;
}

bool V4L2Device::OneCapture() {
  int ret;
  uint32_t buf_index, data_size;
  do {
    ret = ReadOneFrame(&buf_index, &data_size);
  } while (ret == 0);
  if (ret < 0)
    return false;
  if (ret) {
    ProcessImage(v4l2_buffers_[buf_index].start);
    if (!EnqueueBuffer(buf_index))
      return false;
  }
  return true;
}

bool V4L2Device::GetFrameInterval(uint32_t index,
                                  uint32_t pixfmt,
                                  uint32_t width,
                                  uint32_t height,
                                  float* frame_rate) {
  v4l2_frmivalenum frm_interval;
  memset(&frm_interval, 0, sizeof(frm_interval));
  frm_interval.pixel_format = pixfmt;
  frm_interval.width = width;
  frm_interval.height = height;
  frm_interval.index = index;
  if (-1 == DoIoctl(VIDIOC_ENUM_FRAMEINTERVALS, &frm_interval)) {
    LOGF(ERROR) << "VIDIOC_ENUM_FRAMEINTERVALS not supported";
    return false;
  }
  if (frm_interval.type != V4L2_FRMIVAL_TYPE_DISCRETE) {
    LOGF(ERROR) << base::StringPrintf("Frame interval type %d not supported",
                                      frm_interval.type);
    return false;
  }

  if (frame_rate) {
    *frame_rate = static_cast<float>(frm_interval.discrete.denominator) /
                  frm_interval.discrete.numerator;
  }
  return true;
}

bool V4L2Device::QueryControl(uint32_t id, v4l2_queryctrl* ctrl) {
  memset(ctrl, 0, sizeof(*ctrl));
  ctrl->id = id;
  if (-1 == DoIoctl(VIDIOC_QUERYCTRL, ctrl)) {
    if (errno != EINVAL)
      return false;
    LOGF(INFO) << base::StringPrintf("%d is not supported", id);
    return false;
  }
  if (ctrl->flags & V4L2_CTRL_FLAG_DISABLED) {
    LOGF(INFO) << base::StringPrintf("%d is not supported", id);
    return false;
  }
  return true;
}

bool V4L2Device::SetControl(uint32_t id, int32_t value) {
  v4l2_control control;
  control.id = id;
  control.value = value;
  if (-1 == DoIoctl(VIDIOC_S_CTRL, &control)) {
    PLOGF(ERROR) << base::StringPrintf("VIDIOC_S_CTRL failed");
    return false;
  }
  return true;
}

bool V4L2Device::GetCropCap(v4l2_cropcap* cropcap) {
  if (-1 == DoIoctl(VIDIOC_CROPCAP, cropcap)) {
    LOGF(WARNING) << "VIDIOC_CROPCAP not supported";
    return false;
  }
  return true;
}

bool V4L2Device::GetCrop(v4l2_crop* crop) {
  if (-1 == DoIoctl(VIDIOC_G_CROP, crop)) {
    LOGF(WARNING) << "VIDIOC_G_CROP not supported";
    return false;
  }
  LOGF(INFO) << base::StringPrintf("Crop: %d, %d, %d, %d", crop->c.left,
                                   crop->c.top, crop->c.width, crop->c.height);
  return true;
}

bool V4L2Device::SetCrop(v4l2_crop* crop) {
  if (-1 == DoIoctl(VIDIOC_S_CROP, crop)) {
    LOGF(WARNING) << "VIDIOC_S_CROP not supported";
    return false;
  }
  return true;
}

bool V4L2Device::ProbeCaps(v4l2_capability* cap, bool show_caps) {
  if (-1 == DoIoctl(VIDIOC_QUERYCAP, cap)) {
    LOGF(ERROR) << base::StringPrintf("VIDIOC_QUERYCAP on %s", dev_name_);
    return false;
  }

  if (show_caps) {
    auto ShowCaps = [&](uint32_t caps) {
      if (caps & V4L2_CAP_VIDEO_CAPTURE)
        LOGF(INFO) << base::StringPrintf("%s support video capture interface",
                                         dev_name_);
      if (caps & V4L2_CAP_VIDEO_OUTPUT)
        LOGF(INFO) << base::StringPrintf("%s support video output interface",
                                         dev_name_);
      if (caps & V4L2_CAP_VIDEO_OVERLAY)
        LOGF(INFO) << base::StringPrintf("%s support video overlay interface",
                                         dev_name_);
      if (caps & V4L2_CAP_AUDIO)
        LOGF(INFO) << base::StringPrintf("%s support audio i/o interface",
                                         dev_name_);
      if (caps & V4L2_CAP_STREAMING)
        LOGF(INFO) << base::StringPrintf("%s support streaming i/o interface",
                                         dev_name_);
    };
    ShowCaps(cap->capabilities);
    if (cap->capabilities & V4L2_CAP_DEVICE_CAPS) {
      LOGF(INFO) << base::StringPrintf(
          "%s support per device capabilities. Dump it as well", dev_name_);
      ShowCaps(cap->device_caps);
    }
  }

  return true;
}

uint32_t V4L2Device::MapFourCC(const char* fourcc) {
  return v4l2_fourcc(fourcc[0], fourcc[1], fourcc[2], fourcc[3]);
}

bool V4L2Device::GetParam(v4l2_streamparm* param) {
  param->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  if (-1 == DoIoctl(VIDIOC_G_PARM, param)) {
    LOGF(WARNING) << "VIDIOC_G_PARM not supported";
    return false;
  }

  return true;
}

bool V4L2Device::SetParam(v4l2_streamparm* param) {
  if (-1 == DoIoctl(VIDIOC_S_PARM, param)) {
    LOGF(WARNING) << "VIDIOC_S_PARM not supported";
    return false;
  }
  return true;
}

bool V4L2Device::SetFrameRate(float fps) {
  v4l2_streamparm param;
  if (!GetParam(&param))
    return false;

  const int kFrameRatePrecision = 10000;
  param.parm.capture.timeperframe.numerator = kFrameRatePrecision;
  param.parm.capture.timeperframe.denominator = fps * kFrameRatePrecision;
  return SetParam(&param);
}

float V4L2Device::GetFrameRate() {
  v4l2_streamparm param;
  if (!GetParam(&param))
    return -1;
  return static_cast<float>(param.parm.capture.timeperframe.denominator) /
         param.parm.capture.timeperframe.numerator;
}

bool V4L2Device::GetV4L2Format(v4l2_format* format) {
  memset(format, 0, sizeof(v4l2_format));
  format->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

  if (-1 == DoIoctl(VIDIOC_G_FMT, format)) {
    LOGF(ERROR) << base::StringPrintf("VIDIOC_G_FMT on %s", dev_name_);
    return false;
  }
  return true;
}

bool V4L2Device::GetSelection(uint32_t target, v4l2_selection* selection) {
  memset(selection, 0, sizeof(v4l2_selection));
  selection->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  selection->target = target;
  if (-1 == DoIoctl(VIDIOC_G_SELECTION, selection)) {
    LOGF(ERROR) << base::StringPrintf("VIDIOC_G_SELECTION on %s", dev_name_);
    return false;
  }
  return true;
}

bool V4L2Device::SetSelection(uint32_t target, const v4l2_rect& rect) {
  v4l2_selection selection = {
      .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
      .target = target,
      .r = rect,
  };
  if (-1 == DoIoctl(VIDIOC_S_SELECTION, &selection)) {
    LOGF(ERROR) << base::StringPrintf("VIDIOC_S_SELECTION on %s", dev_name_);
    return false;
  }
  return true;
}

uint64_t V4L2Device::Now() {
  struct timespec ts;
  int res = clock_gettime(CLOCK_MONOTONIC, &ts);
  CHECK_EQ(res, 0);
  return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
