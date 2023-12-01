// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "feedback/feedback_daemon.h"

#include <unistd.h>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/strings/string_util.h>
#include <brillo/syslog_logging.h>
#include <dbus/bus.h>

#include "components/feedback/feedback_report.h"
#include "feedback/feedback_uploader_http.h"

namespace {

// string, set to "test" to use the sandbox server, otherwise a url
// to send the report to.
static const char kSwitchCustomServer[] = "url";

static const char kWorkerThreadName[] = "FeedbackWorkerThread";

static const char kFeedbackReportPath[] = "/run/";

static const char kFeedbackTestUrl[] =
    "http://sandbox.google.com/tools/feedback/chrome/__submit";
static const char kFeedbackPostUrl[] =
    "https://www.google.com/tools/feedback/chrome/__submit";

}  // namespace

namespace feedback {

Daemon::Daemon(const std::string& url)
    : worker_thread_(kWorkerThreadName), watcher_(loop_.task_runner()) {
  worker_thread_.Start();
  uploader_ = std::make_unique<FeedbackUploaderHttp>(
      base::FilePath(kFeedbackReportPath), worker_thread_.task_runner(), url);
}

Daemon::~Daemon() = default;

void Daemon::Run() {
  base::RunLoop loop;
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;

  scoped_refptr<dbus::Bus> bus = new dbus::Bus(options);
  scoped_refptr<DBusFeedbackServiceImpl> impl =
      new DBusFeedbackServiceImpl(uploader_.get());

  // Load all reports currently on disk and queue them for sending.
  FeedbackReport::LoadReportsAndQueue(
      uploader_->GetFeedbackReportsPath(),
      base::BindRepeating(&FeedbackService::QueueExistingReport, impl.get()));

  CHECK(impl->Start(bus.get())) << "Failed to start feedback service";

  loop.Run();
}

}  // namespace feedback

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* args = base::CommandLine::ForCurrentProcess();

  // Some libchrome calls need this.
  base::AtExitManager at_exit_manager;

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  std::string url = args->GetSwitchValueASCII(kSwitchCustomServer);
  if (url.empty()) {
    url = kFeedbackPostUrl;
  } else if (!url.compare("test")) {
    url = kFeedbackTestUrl;
    LOG(INFO) << "Using test feedback server";
  } else {
    LOG(INFO) << "Using feedback server at: " << url;
  }

  feedback::Daemon daemon(url);
  daemon.Run();

  return 0;
}
