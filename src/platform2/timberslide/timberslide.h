// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TIMBERSLIDE_TIMBERSLIDE_H_
#define TIMBERSLIDE_TIMBERSLIDE_H_

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_util.h>
#include <base/time/time.h>
#include <brillo/daemons/daemon.h>
#include "timberslide/log_listener.h"
#include "timberslide/string_transformer.h"

namespace timberslide {

class TimberSlide : public brillo::Daemon {
 public:
  TimberSlide(const std::string& ec_type,
              base::File device_file,
              base::File uptime_file,
              const base::FilePath& log_dir);

  std::string ProcessLogBuffer(const std::string& buffer,
                               const base::Time& now);

 protected:
  // For testing
  explicit TimberSlide(std::unique_ptr<LogListener> log_listener,
                       std::unique_ptr<StringTransformer> xfrm);

 private:
  int OnInit() override;

  void OnEventReadable();

  virtual bool GetEcUptime(int64_t* ec_uptime_ms);

  void RotateLogs(const base::FilePath& previous_log,
                  const base::FilePath& current_log);

  base::File device_file_;
  base::FilePath current_log_;
  base::FilePath previous_log_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
  int total_size_ = 0;
  base::File uptime_file_;
  bool uptime_file_valid_ = false;
  std::unique_ptr<LogListener> log_listener_;
  std::unique_ptr<StringTransformer> xfrm_;
};

}  // namespace timberslide

#endif  // TIMBERSLIDE_TIMBERSLIDE_H_
