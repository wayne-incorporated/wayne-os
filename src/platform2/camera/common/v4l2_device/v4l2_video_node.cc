/*
 * Copyright (C) 2013-2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-camera/v4l2_device.h"

#include <fcntl.h>
#include <limits.h>
#include <linux/media.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "cros-camera/common.h"

#include <base/check.h>
#include <base/check_op.h>

static inline bool IsValidV4L2BufferType(uint32_t type) {
  return (type == V4L2_BUF_TYPE_VIDEO_CAPTURE) ||
         (type == V4L2_BUF_TYPE_VIDEO_OUTPUT) ||
         (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
         (type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) ||
         (type == V4L2_BUF_TYPE_META_OUTPUT) ||
         (type == V4L2_BUF_TYPE_META_CAPTURE);
}

namespace cros {

#define V4L2_TYPE_IS_META(type) \
  ((type) == V4L2_BUF_TYPE_META_OUTPUT || (type) == V4L2_BUF_TYPE_META_CAPTURE)

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

V4L2Buffer::V4L2Buffer() : v4l2_buf_{} {
  v4l2_buf_.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
  planes_.resize(VIDEO_MAX_PLANES);
  v4l2_buf_.m.planes = planes_.data();
  v4l2_buf_.length = planes_.size();
}

V4L2Buffer::V4L2Buffer(const V4L2Buffer& buf) : v4l2_buf_(buf.v4l2_buf_) {
  if (V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type)) {
    planes_ = buf.planes_;
    v4l2_buf_.m.planes = planes_.data();
  }
}

void V4L2Buffer::SetType(uint32_t type) {
  DCHECK(IsValidV4L2BufferType(type));

  v4l2_buf_.type = type;
}

uint32_t V4L2Buffer::Offset(uint32_t plane) const {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  return mp ? v4l2_buf_.m.planes[plane].m.mem_offset : v4l2_buf_.m.offset;
}

void V4L2Buffer::SetOffset(uint32_t offset, uint32_t plane) {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  if (mp)
    v4l2_buf_.m.planes[plane].m.mem_offset = offset;
  else
    v4l2_buf_.m.offset = offset;
}

uint32_t V4L2Buffer::DataOffset(uint32_t plane) const {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  return mp ? v4l2_buf_.m.planes[plane].data_offset : 0;
}

void V4L2Buffer::SetDataOffset(uint32_t offset, uint32_t plane) {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  if (mp)
    v4l2_buf_.m.planes[plane].data_offset = offset;
}

uintptr_t V4L2Buffer::Userptr(uint32_t plane) const {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  return mp ? v4l2_buf_.m.planes[plane].m.userptr : v4l2_buf_.m.userptr;
}

void V4L2Buffer::SetUserptr(uintptr_t userptr, uint32_t plane) {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  if (mp)
    v4l2_buf_.m.planes[plane].m.userptr = userptr;
  else
    v4l2_buf_.m.userptr = userptr;
}

int V4L2Buffer::RequestFd() const {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));

  return (v4l2_buf_.flags & V4L2_BUF_FLAG_REQUEST_FD) ? v4l2_buf_.request_fd
                                                      : -1;
}

int V4L2Buffer::SetRequestFd(int fd) {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));

  if (fd <= 0) {
    return -EINVAL;
  }

  v4l2_buf_.flags |= V4L2_BUF_FLAG_REQUEST_FD;
  v4l2_buf_.request_fd = fd;

  return 0;
}

int V4L2Buffer::ResetRequestFd() {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));

  v4l2_buf_.flags &= ~V4L2_BUF_FLAG_REQUEST_FD;
  v4l2_buf_.request_fd = 0;

  return 0;
}

int V4L2Buffer::Fd(uint32_t plane) const {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  return mp ? v4l2_buf_.m.planes[plane].m.fd : v4l2_buf_.m.fd;
}

void V4L2Buffer::SetFd(int fd, uint32_t plane) {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  if (mp)
    v4l2_buf_.m.planes[plane].m.fd = fd;
  else
    v4l2_buf_.m.fd = fd;
}

uint32_t V4L2Buffer::BytesUsed(uint32_t plane) const {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  return mp ? v4l2_buf_.m.planes[plane].bytesused : v4l2_buf_.bytesused;
}

void V4L2Buffer::SetBytesUsed(uint32_t bytesused, uint32_t plane) {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  if (mp)
    v4l2_buf_.m.planes[plane].bytesused = bytesused;
  else
    v4l2_buf_.bytesused = bytesused;
}

uint32_t V4L2Buffer::Length(uint32_t plane) const {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  return mp ? v4l2_buf_.m.planes[plane].length : v4l2_buf_.length;
}

void V4L2Buffer::SetLength(uint32_t length, uint32_t plane) {
  DCHECK(IsValidV4L2BufferType(v4l2_buf_.type));
  bool mp = V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type);
  DCHECK((!mp && plane == 0) || (mp && plane < planes_.size()));

  if (mp)
    v4l2_buf_.m.planes[plane].length = length;
  else
    v4l2_buf_.length = length;
}

const V4L2Buffer& V4L2Buffer::operator=(const V4L2Buffer& buf) {
  v4l2_buf_ = buf.v4l2_buf_;
  if (V4L2_TYPE_IS_MULTIPLANAR(v4l2_buf_.type)) {
    planes_ = buf.planes_;
    v4l2_buf_.m.planes = planes_.data();
  }
  return *this;
}

V4L2Format::V4L2Format()
    : type_(0),
      width_(0),
      height_(0),
      pixel_fmt_(0),
      field_(V4L2_FIELD_NONE),
      v4l2_fmt_() {}

V4L2Format::V4L2Format(const v4l2_format& fmt) {
  DCHECK(IsValidV4L2BufferType(fmt.type));
  type_ = fmt.type;
  if (V4L2_TYPE_IS_META(fmt.type)) {
    pixel_fmt_ = fmt.fmt.meta.dataformat;
    plane_size_image_.push_back(fmt.fmt.meta.buffersize);
  } else if (V4L2_TYPE_IS_MULTIPLANAR(fmt.type)) {
    width_ = fmt.fmt.pix_mp.width;
    height_ = fmt.fmt.pix_mp.height;
    pixel_fmt_ = fmt.fmt.pix_mp.pixelformat;
    field_ = fmt.fmt.pix_mp.field;
    color_space_ = fmt.fmt.pix_mp.colorspace;
    quantization_ = fmt.fmt.pix_mp.quantization;
    for (uint8_t plane = 0; plane < fmt.fmt.pix_mp.num_planes; plane++) {
      plane_bytes_per_line_.push_back(
          fmt.fmt.pix_mp.plane_fmt[plane].bytesperline);
      plane_size_image_.push_back(fmt.fmt.pix_mp.plane_fmt[plane].sizeimage);
    }
  } else {
    width_ = fmt.fmt.pix.width;
    height_ = fmt.fmt.pix.height;
    pixel_fmt_ = fmt.fmt.pix.pixelformat;
    field_ = fmt.fmt.pix.field;
    color_space_ = fmt.fmt.pix.colorspace;
    quantization_ = fmt.fmt.pix.quantization;
    plane_bytes_per_line_.push_back(fmt.fmt.pix.bytesperline);
    plane_size_image_.push_back(fmt.fmt.pix.sizeimage);
  }
}

void V4L2Format::SetType(uint32_t type) {
  DCHECK(IsValidV4L2BufferType(type));
  type_ = type;
}

uint32_t V4L2Format::Width() const {
  return width_;
}

void V4L2Format::SetWidth(uint32_t width) {
  width_ = width;
}

uint32_t V4L2Format::Height() const {
  return height_;
}

void V4L2Format::SetHeight(uint32_t height) {
  height_ = height;
}

uint32_t V4L2Format::PixelFormat() const {
  return pixel_fmt_;
}

void V4L2Format::SetPixelFormat(uint32_t format) {
  pixel_fmt_ = format;
}

uint32_t V4L2Format::Field() const {
  return field_;
}

void V4L2Format::SetField(uint32_t field) {
  field_ = field;
}

uint32_t V4L2Format::BytesPerLine(uint32_t plane) const {
  DCHECK(plane < plane_bytes_per_line_.size());
  return plane_bytes_per_line_[plane];
}

void V4L2Format::SetBytesPerLine(uint32_t bytesperline, uint32_t plane) {
  if (plane >= VIDEO_MAX_PLANES) {
    LOGF(ERROR) << "Invalid plane " << plane;
    return;
  }
  if (plane >= plane_bytes_per_line_.size()) {
    plane_bytes_per_line_.resize(plane + 1);
  }
  plane_bytes_per_line_[plane] = bytesperline;
}

uint32_t V4L2Format::SizeImage(uint32_t plane) const {
  DCHECK(plane < plane_size_image_.size());
  return plane_size_image_[plane];
}

void V4L2Format::SetSizeImage(uint32_t size, uint32_t plane) {
  if (plane >= VIDEO_MAX_PLANES) {
    LOGF(ERROR) << "Invalid plane " << plane;
    return;
  }
  if (plane >= plane_size_image_.size()) {
    plane_size_image_.resize(plane + 1);
  }
  plane_size_image_[plane] = size;
}

uint32_t V4L2Format::ColorSpace() const {
  return color_space_;
}

void V4L2Format::SetColorSpace(uint32_t profile) {
  color_space_ = profile;
}

uint32_t V4L2Format::Quantization() const {
  return quantization_;
}

void V4L2Format::SetQuantization(uint32_t quantization) {
  quantization_ = quantization;
}

v4l2_format* V4L2Format::Get() {
  DCHECK(IsValidV4L2BufferType(type_));

  v4l2_fmt_.type = type_;
  if (V4L2_TYPE_IS_META(v4l2_fmt_.type)) {
    DCHECK_EQ(plane_size_image_.size(), 1);

    v4l2_fmt_.fmt.meta.dataformat = pixel_fmt_;
    v4l2_fmt_.fmt.meta.buffersize = plane_size_image_[0];
  } else if (V4L2_TYPE_IS_MULTIPLANAR(v4l2_fmt_.type)) {
    // TODO(hywu): add DCHECK_EQ(plane_bytes_per_line_.size(),
    // plane_size_image_.size())
    v4l2_fmt_.fmt.pix_mp.width = width_;
    v4l2_fmt_.fmt.pix_mp.height = height_;
    v4l2_fmt_.fmt.pix_mp.pixelformat = pixel_fmt_;
    v4l2_fmt_.fmt.pix_mp.field = field_;
    v4l2_fmt_.fmt.pix_mp.colorspace = color_space_;
    v4l2_fmt_.fmt.pix_mp.quantization = quantization_;
    v4l2_fmt_.fmt.pix_mp.num_planes = plane_bytes_per_line_.size();
    for (size_t plane = 0; plane < plane_bytes_per_line_.size(); plane++) {
      v4l2_fmt_.fmt.pix_mp.plane_fmt[plane].bytesperline =
          plane_bytes_per_line_[plane];
    }
    for (size_t plane = 0; plane < plane_size_image_.size(); plane++) {
      v4l2_fmt_.fmt.pix_mp.plane_fmt[plane].sizeimage =
          plane_size_image_[plane];
    }
  } else {
    DCHECK_EQ(plane_bytes_per_line_.size(), 1);
    DCHECK_EQ(plane_size_image_.size(), 1);

    v4l2_fmt_.fmt.pix.width = width_;
    v4l2_fmt_.fmt.pix.height = height_;
    v4l2_fmt_.fmt.pix.pixelformat = pixel_fmt_;
    v4l2_fmt_.fmt.pix.field = field_;
    v4l2_fmt_.fmt.pix.colorspace = color_space_;
    v4l2_fmt_.fmt.pix.quantization = quantization_;
    v4l2_fmt_.fmt.pix.bytesperline = plane_bytes_per_line_[0];
    v4l2_fmt_.fmt.pix.sizeimage = plane_size_image_[0];
  }
  return &v4l2_fmt_;
}

V4L2VideoNode::V4L2VideoNode(const std::string name)
    : V4L2Device(name), state_(VideoNodeState::CLOSED) {}

V4L2VideoNode::~V4L2VideoNode() {
  {
    base::AutoLock l(state_lock_);
    if (state_ == VideoNodeState::CLOSED) {
      return;
    }
  }
  Close();
}

int V4L2VideoNode::Open(int flags) {
  VLOGF(1) << "Opening device " << name_;
  base::AutoLock l(state_lock_);
  int ret = V4L2Device::Open(flags);
  if (ret != 0) {
    LOGF(ERROR) << "Failed to open video device node " << name_;
    return ret;
  }

  struct v4l2_capability cap = {};
  ret = QueryCap(&cap);
  if (ret != 0) {
    LOGF(ERROR) << "Failed to query device " << name_ << " capabilities";
    V4L2Device::Close();
    return ret;
  }
  std::pair<uint32_t, enum v4l2_buf_type> buffer_type_mapper[] = {
      {V4L2_CAP_VIDEO_CAPTURE, V4L2_BUF_TYPE_VIDEO_CAPTURE},
      {V4L2_CAP_VIDEO_CAPTURE_MPLANE, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE},
      {V4L2_CAP_VIDEO_OUTPUT, V4L2_BUF_TYPE_VIDEO_OUTPUT},
      {V4L2_CAP_VIDEO_OUTPUT_MPLANE, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE},
      {V4L2_CAP_META_CAPTURE, V4L2_BUF_TYPE_META_CAPTURE},
      {V4L2_CAP_META_OUTPUT, V4L2_BUF_TYPE_META_OUTPUT}};
  size_t i = 0;
  for (; i < ARRAY_SIZE(buffer_type_mapper); i++) {
    if (cap.capabilities & buffer_type_mapper[i].first) {
      buffer_type_ = buffer_type_mapper[i].second;
      break;
    }
  }
  if (i == ARRAY_SIZE(buffer_type_mapper)) {
    LOGF(ERROR) << "Unsupported device " << name_ << " capabilities 0x"
                << std::hex << cap.capabilities;
    V4L2Device::Close();
    return -EINVAL;
  }

  state_ = VideoNodeState::OPEN;
  return ret;
}

int V4L2VideoNode::Close() {
  VLOGF(1) << "Closing device " << name_;
  base::AutoLock l(state_lock_);
  if (state_ == VideoNodeState::STARTED || state_ == VideoNodeState::PREPARED) {
    StopLocked();
  }

  int ret = V4L2Device::Close();
  state_ = (ret == 0) ? VideoNodeState::CLOSED : VideoNodeState::ERROR;

  return ret;
}

enum v4l2_memory V4L2VideoNode::GetMemoryType() {
  return memory_type_;
}

enum v4l2_buf_type V4L2VideoNode::GetBufferType() {
  return buffer_type_;
}

int V4L2VideoNode::Stop(bool releaseBuffers) {
  VLOGF(1) << "Stoping device " << name_;
  base::AutoLock l(state_lock_);
  if (state_ != VideoNodeState::STARTED && state_ != VideoNodeState::PREPARED) {
    LOGF(WARNING) << "Trying to stop a device not started";
    return -EINVAL;
  }
  return StopLocked(releaseBuffers);
}

int V4L2VideoNode::StopLocked(bool releaseBuffers) {
  if (state_ == VideoNodeState::STARTED) {
    // stream off
    int ret = ::ioctl(fd_, VIDIOC_STREAMOFF, &buffer_type_);
    if (ret < 0) {
      PLOGF(ERROR) << name_ << " VIDIOC_STREAMOFF returned: " << ret;
      return ret;
    }
    state_ = VideoNodeState::PREPARED;
  }

  if (!releaseBuffers) {
    return 0;
  }

  if (state_ == VideoNodeState::PREPARED) {
    unsigned int flags;
    if (is_buffer_cached_)
      flags = V4L2_MEMORY_FLAG_NON_COHERENT;
    else
      flags = 0;
    RequestBuffers(0, memory_type_, flags);
    state_ = VideoNodeState::CONFIGURED;
  }

  return 0;
}

int V4L2VideoNode::Start() {
  VLOGF(1) << "Starting device " << name_;
  base::AutoLock l(state_lock_);
  if (state_ != VideoNodeState::PREPARED) {
    LOGF(ERROR) << "Invalid device state " << static_cast<int>(state_);
    return -1;
  }

  // stream on
  int ret = ::ioctl(fd_, VIDIOC_STREAMON, &buffer_type_);
  if (ret < 0) {
    PLOGF(ERROR) << name_ << " VIDIOC_STREAMON returned: " << ret;
    return ret;
  }

  state_ = VideoNodeState::STARTED;

  return 0;
}

int V4L2VideoNode::SetFormat(const V4L2Format& format) {
  base::AutoLock l(state_lock_);
  if ((state_ != VideoNodeState::OPEN) &&
      (state_ != VideoNodeState::CONFIGURED) &&
      (state_ != VideoNodeState::PREPARED)) {
    LOGF(ERROR) << "Invalid device state " << static_cast<int>(state_);
    return -EINVAL;
  }

  V4L2Format fmt(format);
  fmt.SetType(buffer_type_);
  if (V4L2_TYPE_IS_META(buffer_type_)) {
    VLOGF(1) << "Device " << name_ << ": before VIDIOC_S_FMT  fourcc: "
             << FormatToString(fmt.PixelFormat())
             << ", size: " << fmt.SizeImage(0);
  } else {
    VLOGF(1) << "Device " << name_ << ": VIDIOC_S_FMT width: " << fmt.Width()
             << ", height: " << fmt.Height() << ", bpl: " << fmt.BytesPerLine(0)
             << ", fourcc: " << FormatToString(fmt.PixelFormat())
             << ", field: " << fmt.Field();
  }

  if (V4L2_TYPE_IS_META(buffer_type_)) {
    fmt.SetSizeImage(0, 0);
  }

  int ret = ::ioctl(fd_, VIDIOC_S_FMT, fmt.Get());
  if (ret < 0) {
    PLOGF(ERROR) << "VIDIOC_S_FMT returned: " << ret;
    return ret;
  }

  if (V4L2_TYPE_IS_META(buffer_type_)) {
    VLOGF(2) << "Device " << name_ << ": after VIDIOC_S_FMT  fourcc: "
             << FormatToString(fmt.PixelFormat())
             << ", size: " << fmt.SizeImage(0);
  } else {
    VLOGF(2) << "Device " << name_
             << ": after VIDIOC_S_FMT width: " << fmt.Width()
             << ", height: " << fmt.Height() << ", bpl: " << fmt.BytesPerLine(0)
             << ", fourcc: " << FormatToString(fmt.PixelFormat())
             << ", field: " << fmt.Field();
  }

  // Update current configuration with the new one
  format_ = fmt;

  state_ = VideoNodeState::CONFIGURED;
  return 0;
}

int V4L2VideoNode::SetSelection(const struct v4l2_selection& selection) {
  base::AutoLock l(state_lock_);
  if ((state_ != VideoNodeState::OPEN) &&
      (state_ != VideoNodeState::CONFIGURED)) {
    LOGF(ERROR) << "Invalid device state " << static_cast<int>(state_);
    return -EINVAL;
  }

  struct v4l2_selection* sel = const_cast<struct v4l2_selection*>(&selection);
  sel->type = buffer_type_;
  VLOGF(1) << "Device " << name_
           << ": VIDIOC_S_SELECTION type: " << selection.type << ", target: 0x"
           << std::hex << selection.target << ", flags: " << selection.flags
           << ", rect left: " << std::dec << selection.r.left
           << ", rect top: " << selection.r.top
           << ", width: " << selection.r.width
           << ", height: " << selection.r.height;

  int ret = ::ioctl(fd_, VIDIOC_S_SELECTION, sel);
  if (ret < 0) {
    PLOGF(ERROR) << "VIDIOC_S_SELECTION returned: " << ret;
  }
  return ret;
}

int V4L2VideoNode::MapMemory(unsigned int index,
                             int prot,
                             int flags,
                             std::vector<void*>* mapped) {
  base::AutoLock l(state_lock_);
  if ((state_ != VideoNodeState::OPEN) &&
      (state_ != VideoNodeState::CONFIGURED) &&
      (state_ != VideoNodeState::PREPARED)) {
    LOGF(ERROR) << "Invalid device state " << static_cast<int>(state_);
    return -EINVAL;
  }
  if (memory_type_ != V4L2_MEMORY_MMAP) {
    LOGF(ERROR) << "Invalid memory type " << memory_type_;
    return -EINVAL;
  }
  if (!mapped) {
    return -EINVAL;
  }

  V4L2Buffer buffer;
  int ret = QueryBuffer(index, memory_type_, &buffer);
  if (ret < 0) {
    LOGF(ERROR) << name_ << " error querying buffers status";
    state_ = VideoNodeState::ERROR;
    return ret;
  }
  uint32_t num_planes =
      V4L2_TYPE_IS_MULTIPLANAR(buffer.Type()) ? buffer.Get()->length : 1;
  for (uint32_t i = 0; i < num_planes; i++) {
    void* res =
        ::mmap(nullptr, buffer.Length(i), prot, flags, fd_, buffer.Offset(i));
    if (res == MAP_FAILED) {
      PLOGF(ERROR) << "mmap failed";
      return -EINVAL;
    }
    mapped->push_back(res);
  }
  return 0;
}

int V4L2VideoNode::GrabFrame(V4L2Buffer* buf) {
  base::AutoLock l(state_lock_);
  if (state_ != VideoNodeState::STARTED) {
    LOGF(ERROR) << name_ << " invalid device state "
                << static_cast<int>(state_);
    return -EINVAL;
  }
  if (!buf) {
    LOGF(ERROR) << name_ << " invalid parameter buf is nullptr";
    return -EINVAL;
  }

  int ret = Dqbuf(buf);
  if (ret < 0)
    return ret;

  PrintBufferInfo(__FUNCTION__, *buf);
  return buf->Index();
}

int V4L2VideoNode::PutFrame(V4L2Buffer* buf) {
  int ret = Qbuf(buf);
  PrintBufferInfo(__FUNCTION__, *buf);

  return ret;
}

int V4L2VideoNode::ExportFrame(unsigned int index, std::vector<int>* fds) {
  if (memory_type_ != V4L2_MEMORY_MMAP) {
    LOGF(ERROR) << name_ << " cannot export non-mmap buffers";
    return -EINVAL;
  }
  if (!fds) {
    return -EINVAL;
  }

  V4L2Buffer buffer;
  int ret = QueryBuffer(index, memory_type_, &buffer);
  if (ret < 0) {
    LOGF(ERROR) << name_ << " error querying buffers status";
    state_ = VideoNodeState::ERROR;
    return ret;
  }
  uint32_t num_planes =
      V4L2_TYPE_IS_MULTIPLANAR(buffer.Type()) ? buffer.Get()->length : 1;
  struct v4l2_exportbuffer ebuf = {};
  ebuf.type = buffer_type_;
  ebuf.index = index;
  ebuf.flags = O_RDWR;
  for (uint32_t i = 0; i < num_planes; i++) {
    ret = ::ioctl(fd_, VIDIOC_EXPBUF, &ebuf);
    if (ret < 0) {
      PLOGF(ERROR) << name_ << " VIDIOC_EXPBUF failed ret " << ret;
      return ret;
    } else {
      fds->push_back(ebuf.fd);
    }
    VLOGF(2) << name_ << " idx " << index << " plane " << i << " fd "
             << ebuf.fd;
  }
  return 0;
}

int V4L2VideoNode::SetupBuffers(size_t num_buffers,
                                bool is_cached,
                                enum v4l2_memory memory_type,
                                std::vector<V4L2Buffer>* buffers) {
  if (num_buffers == 0 || !buffers || !buffers->empty()) {
    return -EINVAL;
  }

  base::AutoLock l(state_lock_);
  if ((state_ != VideoNodeState::CONFIGURED)) {
    LOGF(ERROR) << name_
                << " invalid operation, device not configured (state = "
                << static_cast<int>(state_) << ")";
    return -EINVAL;
  }

  unsigned int flags;
  if (is_cached)
    flags = V4L2_MEMORY_FLAG_NON_COHERENT;
  else
    flags = 0;
  int ret = RequestBuffers(num_buffers, memory_type, flags);
  if (ret <= 0) {
    LOGF(ERROR) << name_ << " could not complete buffer request";
    return -EINVAL;
  }

  for (size_t i = 0; i < num_buffers; i++) {
    V4L2Buffer buffer;
    int ret = QueryBuffer(i, memory_type, &buffer);
    if (ret < 0) {
      LOGF(ERROR) << name_ << " error querying buffers status";
      state_ = VideoNodeState::ERROR;
      return ret;
    }
    buffers->push_back(std::move(buffer));
  }

  is_buffer_cached_ = is_cached;
  memory_type_ = memory_type;
  state_ = VideoNodeState::PREPARED;
  return 0;
}

int V4L2VideoNode::QueryCap(struct v4l2_capability* cap) {
  int ret = ::ioctl(fd_, VIDIOC_QUERYCAP, cap);

  if (ret < 0) {
    PLOGF(ERROR) << name_ << " VIDIOC_QUERYCAP returned: " << ret;
    return ret;
  }

  VLOGF(1) << "driver: " << cap->driver;
  VLOGF(1) << "card: " << cap->card;
  VLOGF(1) << "bus_info: " << cap->bus_info;
  VLOGF(1) << "version: " << std::hex << cap->version;
  VLOGF(1) << "capabilities: " << std::hex << cap->capabilities;
  VLOGF(1) << "device caps: " << cap->device_caps;
  VLOGF(1) << "buffer type " << buffer_type_;

  return 0;
}

int V4L2VideoNode::RequestBuffers(size_t num_buffers,
                                  enum v4l2_memory memory_type,
                                  unsigned int flags) {
  if (state_ == VideoNodeState::CLOSED)
    return 0;

  struct v4l2_requestbuffers req_buf = {};
  req_buf.memory = memory_type;
  req_buf.count = num_buffers;
  req_buf.type = buffer_type_;
  req_buf.flags = flags;

  VLOGF(1) << "Device " << name_ << ": VIDIOC_REQBUFS, count=" << req_buf.count
           << ", memory=" << req_buf.memory << ", type=" << req_buf.type
           << ", flags=" << req_buf.flags;
  int ret = ::ioctl(fd_, VIDIOC_REQBUFS, &req_buf);

  if (ret < 0) {
    PLOGF(ERROR) << name_ << " VIDIOC_REQBUFS(" << num_buffers
                 << ") returned: " << ret;
    return ret;
  }

  if (req_buf.count < num_buffers)
    LOGF(WARNING) << name_ << " got less buffers than requested! "
                  << req_buf.count << " < " << num_buffers;

  memory_type_ = memory_type;
  state_ = VideoNodeState::PREPARED;
  return req_buf.count;
}

void V4L2VideoNode::PrintBufferInfo(const std::string func,
                                    const V4L2Buffer& buf) {
  switch (memory_type_) {
    case V4L2_MEMORY_USERPTR:
      VLOGF(2) << func << " idx:" << buf.Index() << " addr:" << buf.Userptr(0);
      break;
    case V4L2_MEMORY_MMAP:
      VLOGF(2) << func << " idx:" << buf.Index() << " offset:0x" << std::hex
               << buf.Offset(0);
      break;
    case V4L2_MEMORY_DMABUF:
      VLOGF(2) << func << " idx:" << buf.Index() << " fd:" << buf.Fd(0);
      break;
    default:
      VLOGF(2) << func << " unknown memory type " << memory_type_;
      break;
  }
}

int V4L2VideoNode::Qbuf(V4L2Buffer* buf) {
  int ret = ::ioctl(fd_, VIDIOC_QBUF, buf->Get());
  if (ret < 0) {
    PLOGF(ERROR) << name_ << " VIDIOC_QBUF failed";
  }
  return ret;
}

int V4L2VideoNode::Dqbuf(V4L2Buffer* buf) {
  buf->SetMemory(memory_type_);
  buf->SetType(buffer_type_);

  int ret = ::ioctl(fd_, VIDIOC_DQBUF, buf->Get());
  if (ret < 0) {
    PLOGF(ERROR) << name_ << " VIDIOC_DQBUF failed";
  }
  return ret;
}

int V4L2VideoNode::QueryBuffer(int index,
                               enum v4l2_memory memory_type,
                               V4L2Buffer* buf) {
  buf->SetFlags(0x0);
  buf->SetMemory(memory_type);
  buf->SetType(buffer_type_);
  buf->SetIndex(index);
  int ret = ::ioctl(fd_, VIDIOC_QUERYBUF, buf->Get());

  if (ret < 0) {
    PLOGF(ERROR) << name_ << " VIDIOC_QUERYBUF failed";
    return ret;
  }

  VLOGF(1) << "Device " << name_ << ":";
  VLOGF(1) << "    index " << buf->Index();
  VLOGF(1) << "    type " << buf->Type();
  VLOGF(1) << "    bytesused " << buf->BytesUsed(0);
  VLOGF(1) << "    flags 0x" << std::hex << buf->Flags();
  if (memory_type == V4L2_MEMORY_MMAP) {
    VLOGF(1) << "    memory MMAP: offset 0x" << std::hex << buf->Offset(0);
  } else if (memory_type == V4L2_MEMORY_USERPTR) {
    VLOGF(1) << "    memory USRPTR: " << buf->Userptr(0);
  }
  VLOGF(1) << "    length " << buf->Length(0);
  return 0;
}

int V4L2VideoNode::GetFormat(V4L2Format* format) {
  if (!format) {
    return -EINVAL;
  }

  base::AutoLock l(state_lock_);
  if ((state_ != VideoNodeState::OPEN) &&
      (state_ != VideoNodeState::CONFIGURED)) {
    LOGF(ERROR) << name_ << " invalid device state "
                << static_cast<int>(state_);
    return -EINVAL;
  }

  v4l2_format fmt;
  fmt.type = buffer_type_;
  int ret = ::ioctl(fd_, VIDIOC_G_FMT, &fmt);

  if (ret < 0) {
    PLOGF(ERROR) << name_ << " VIDIOC_G_FMT failed";
    return -EINVAL;
  }

  *format = V4L2Format(fmt);
  if (V4L2_TYPE_IS_META(buffer_type_)) {
    VLOGF(1) << "Device " << name_ << ": VIDIOC_G_FMT fourcc: "
             << FormatToString(format->PixelFormat())
             << ", size: " << format->SizeImage(0);
  } else {
    VLOGF(1) << "Device " << name_
             << ": VIDIOC_G_FMT width: " << format->Width()
             << ", height: " << format->Height()
             << ", bpl: " << format->BytesPerLine(0)
             << ", fourcc: " << FormatToString(format->PixelFormat())
             << ", field: " << format->Field();
  }

  return 0;
}

}  // namespace cros
