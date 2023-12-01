// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <sstream>
#include <string>

#include <sysexits.h>
#include <sys/types.h>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>
#include <brillo/daemons/daemon.h>
#include "timberslide/log_listener_factory.h"
#include "timberslide/timberslide.h"

namespace timberslide {
namespace {

const char kCurrentLogExt[] = ".log";
const char kPreviousLogExt[] = ".previous";
const int kMaxCurrentLogSize = 10 * 1024 * 1024;

// String proxy class for dealing with lines.
class LineExtractor {
 public:
  // Extract one line from beginning of string stream.
  friend std::istream& operator>>(std::istream& is, LineExtractor& l) {
    std::getline(is, l.str_);
    return is;
  }

  // Transparently convert to std::string.
  operator std::string() const { return str_; }

 private:
  std::string str_;
};

}  // namespace

TimberSlide::TimberSlide(const std::string& ec_type,
                         base::File device_file,
                         base::File uptime_file,
                         const base::FilePath& log_dir)
    : device_file_(std::move(device_file)),
      total_size_(0),
      uptime_file_(std::move(uptime_file)),
      uptime_file_valid_(uptime_file_.IsValid()) {
  current_log_ = log_dir.Append(ec_type + kCurrentLogExt);
  previous_log_ = log_dir.Append(ec_type + kPreviousLogExt);
  log_listener_ = LogListenerFactory::Create(ec_type);
  xfrm_ = std::make_unique<StringTransformer>();
}

TimberSlide::TimberSlide(std::unique_ptr<LogListener> log_listener,
                         std::unique_ptr<StringTransformer> xfrm)
    : log_listener_(std::move(log_listener)), xfrm_(std::move(xfrm)) {}

int TimberSlide::OnInit() {
  LOG(INFO) << "Starting timberslide daemon";
  int ret = brillo::Daemon::OnInit();
  if (ret != EX_OK)
    return ret;

  int64_t ec_uptime_ms;
  if (uptime_file_valid_) {
    LOG(INFO) << "EC uptime file is valid";
    if (GetEcUptime(&ec_uptime_ms))
      xfrm_->UpdateTimestamps(ec_uptime_ms, base::Time::Now());
  } else {
    LOG(WARNING) << "EC uptime file is not valid; ignoring";
  }

  RotateLogs(previous_log_, current_log_);

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      device_file_.GetPlatformFile(),
      base::BindRepeating(&TimberSlide::OnEventReadable,
                          base::Unretained(this)));

  return watcher_ ? EX_OK : EX_OSERR;
}

//
// From kernel's Documentation/filesystems/sysfs.txt: If userspace seeks back
// to zero or does a pread(2) with an offset of '0' the show() method will
// be called again, rearmed, to fill the buffer.
//
// Therefore, the 'uptime' file will be kept open and just seeked back to
// 0 when new uptime is needed.
//
bool TimberSlide::GetEcUptime(int64_t* ec_uptime_ms) {
  char uptime_buf[64] = {0};

  if (!uptime_file_valid_ || uptime_file_.Seek(base::File::FROM_BEGIN, 0) != 0)
    return false;

  // Read single line from file and parse as a number.
  int count = uptime_file_.ReadAtCurrentPos(uptime_buf, sizeof(uptime_buf) - 1);

  if (count <= 0)
    return false;

  uptime_buf[count] = '\0';
  base::StringToInt64(uptime_buf, ec_uptime_ms);

  // If the 'uptime' file contains zero, that means the kernel patch is
  // available, but the EC doesn't support EC_CMD_GET_UPTIME_INFO.  In
  // that case, this returns false so that incorrect times aren't reported
  // in the EC log file.
  return (*ec_uptime_ms > 0);
}

std::string TimberSlide::ProcessLogBuffer(const std::string& buffer,
                                          const base::Time& now) {
  int64_t ec_current_uptime_ms = 0;
  std::istringstream iss(buffer);

  if (GetEcUptime(&ec_current_uptime_ms))
    xfrm_->UpdateTimestamps(ec_current_uptime_ms, now);

  auto fn_xfrm = [this](const std::string& line) {
    if (log_listener_) {
      log_listener_->OnLogLine(line);
    }
    return xfrm_->AddHostTs(line);
  };

  // Iterate over each line and prepend the corresponding host timestamp if we
  // have it
  std::ostringstream oss;
  std::transform(std::istream_iterator<LineExtractor>(iss),
                 std::istream_iterator<LineExtractor>(),
                 std::ostream_iterator<std::string>(oss, "\n"), fn_xfrm);

  return oss.str();
}

void TimberSlide::OnEventReadable() {
  char buffer[4096];
  int ret;

  ret = TEMP_FAILURE_RETRY(
      device_file_.ReadAtCurrentPosNoBestEffort(buffer, sizeof(buffer)));
  if (ret == 0)
    return;

  if (ret < 0) {
    PLOG(ERROR) << "Read error";
    Quit();
    return;
  }

  std::string str =
      ProcessLogBuffer(std::string(buffer, ret), base::Time::Now());
  ret = str.size();

  if (!base::AppendToFile(current_log_, str)) {
    PLOG(ERROR) << "Could not append to log file";
    Quit();
    return;
  }

  total_size_ += ret;
  if (total_size_ >= kMaxCurrentLogSize) {
    RotateLogs(previous_log_, current_log_);
    total_size_ = 0;
  }
}

void TimberSlide::RotateLogs(const base::FilePath& previous_log,
                             const base::FilePath& current_log) {
  CHECK(base::DeleteFile(previous_log));

  if (base::PathExists(current_log))
    CHECK(base::Move(current_log, previous_log));

  base::WriteFile(current_log, "", 0);
}

}  // namespace timberslide
