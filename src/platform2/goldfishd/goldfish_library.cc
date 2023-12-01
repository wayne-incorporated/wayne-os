// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "goldfishd/goldfish_library.h"

#include <stdlib.h>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

namespace {

const int kFrameHeaderLen = 4;
const int kMaxMessageLen = 1024;

}  // namespace

namespace goldfishd {

bool ReadOneMessage(int fd, std::string* message) {
  char buf[kFrameHeaderLen + 1];
  buf[kFrameHeaderLen] = 0;
  if (!base::ReadFromFD(fd, buf, kFrameHeaderLen)) {
    PLOG(ERROR) << "Couldn't read message header";
    return false;
  }
  int len;
  if (strlen(buf) != kFrameHeaderLen || !base::HexStringToInt(buf, &len)) {
    LOG(ERROR) << "Couldn't parse message header: " << buf;
    return false;
  }
  if (len > kMaxMessageLen || len <= 0) {
    LOG(ERROR) << "Wrong message sized at " << len;
    return false;
  }
  char tmp[kMaxMessageLen];
  if (!base::ReadFromFD(fd, tmp, len)) {
    PLOG(ERROR) << "Couldn't read full message sized at " << len;
    return false;
  }
  message->assign(tmp, len);
  return true;
}

}  // namespace goldfishd
