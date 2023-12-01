/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_COMMON_H_
#define CAMERA_INCLUDE_CROS_CAMERA_COMMON_H_

#include <fcntl.h>
#include <time.h>

#include <string>
#include <vector>

#include <base/containers/span.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/stringprintf.h>
#include <base/threading/thread.h>

inline bool IsLogThrottled(timespec* last_ts, int interval_seconds) {
  timespec ts_current;
  clock_gettime(CLOCK_MONOTONIC, &ts_current);
  if (ts_current.tv_sec - last_ts->tv_sec >= interval_seconds) {
    *last_ts = ts_current;
    return false;
  }
  return true;
}

#define LOGF(level) LOG(level) << __FUNCTION__ << "(): "
#define LOGFID(level, id) LOG(level) << __FUNCTION__ << "(): id: " << id << ": "
#define LOGF_IF(level, res) LOG_IF(level, res) << __FUNCTION__ << "(): "
#define LOGF_THROTTLED(level, interval_seconds) \
  static timespec ts_##__FILE__##__LINE__ = {}; \
  LOGF_IF(level, !IsLogThrottled(&ts_##__FILE__##__LINE__, interval_seconds))
#define LOGFID_THROTTLED(level, id, interval_seconds) \
  LOGF_THROTTLED(level, interval_seconds) << "id: " << id << ": "

#define PLOGF(level) PLOG(level) << __FUNCTION__ << "(): "
#define PLOGFID(level, id) \
  PLOG(level) << __FUNCTION__ << "(): id: " << id << ": "
#define PLOGF_IF(level, res) PLOG_IF(level, res) << __FUNCTION__ << "(): "
#define PLOGF_THROTTLED(level, interval_seconds) \
  static timespec ts_##__FILE__##__LINE__ = {};  \
  PLOGF_IF(level, !IsLogThrottled(&ts_##__FILE__##__LINE__, interval_seconds))

#define VLOGF(level) VLOG(level) << __FUNCTION__ << "(): "
#define VLOGFID(level, id) \
  VLOG(level) << __FUNCTION__ << "(): id: " << id << ": "

#define ERRNO_OR_RET(ret) (errno ? -errno : (ret))

// To keep compatibility with the existing code paths enabled by NDEBUG or
// DCHECK_ALWAYS_ON, we still enable the DVLOGF*() macros when DCHECK_IS_ON().
// The ENABLE_VERBOSE_DEBUG_LOGS is for when the image is built without NDEBUG
// (i.e. without the cros-debug USE flag). We can still turn on the debug logs
// by recompiling the binaries with ENABLE_VERBOSE_DEBUG_LOGS defined in
// //camera/build/BUILD.gn without breaking ABI compatibility with the libchrome
// in the image.
#if DCHECK_IS_ON() || ENABLE_VERBOSE_DEBUG_LOGS

#define DVLOGF(level) VLOG(level) << __FUNCTION__ << "(): "
#define DVLOGFID(level, id) \
  VLOG(level) << __FUNCTION__ << "(): id: " << id << ": "

#else

#define DVLOGF(level) EAT_STREAM_PARAMETERS
#define DVLOGFID(level, id) EAT_STREAM_PARAMETERS

#endif  // DCHECK_IS_ON() || ENABLE_VERBOSE_DEBUG_LOGS

inline std::string FormatToString(int32_t format) {
  return std::string(reinterpret_cast<char*>(&format), 4);
}

// Duplicate the file descriptor |fd| with O_CLOEXEC flag set.
inline base::ScopedFD DupWithCloExec(int fd) {
  if (fd < 0) {
    return base::ScopedFD();
  }
  return base::ScopedFD(HANDLE_EINTR(fcntl(fd, F_DUPFD_CLOEXEC, 0)));
}

template <class T>
inline std::vector<T> CopyToVector(base::span<const T> src) {
  return std::vector<T>(src.begin(), src.end());
}

#endif  // CAMERA_INCLUDE_CROS_CAMERA_COMMON_H_
