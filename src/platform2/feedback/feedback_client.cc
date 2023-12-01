// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "feedback/feedback_daemon.h"

#include <memory>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/containers/ring_buffer.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/synchronization/waitable_event.h"
#include "base/uuid.h"
#include <brillo/process/process.h>
#include "brillo/syslog_logging.h"
#include "components/feedback/feedback_common.h"
#include "feedback/feedback_service_interface.h"

#include <sysexits.h>

namespace {

static const char kSwitchProductId[] = "product_id";  // int
static const char kSwitchDescription[] = "desc";      // string
static const char kSwitchBucket[] = "bucket";         // string
static const char kSwitchUserEmail[] = "user_email";  // string
static const char kSwitchPageUrl[] = "page_url";      // string
static const char kSwitchRawFiles[] = "raw_files";    // colon-separated strings

const char kListSeparator[] = ":";

// Buffer size for feedback attachment files in bytes. Given that maximum
// feedback report size is ~7M and that majority of log files are under 1M, we
// set a per-file limit of 1MiB.
const int64_t kMaxFileSize = 1024 * 1024;
const int64_t kChunkSize = 64 * 1024;

bool ReadFileFromBack(const base::FilePath path, std::string* contents) {
  if (!contents) {
    LOG(ERROR) << "contents buffer is null.";
    return false;
  }

  if (path.ReferencesParent()) {
    LOG(ERROR) << "ReadFileFromBack can't be called on file paths with parent "
                  "references.";
    return false;
  }

  base::ScopedFILE fp(base::OpenFile(path, "r"));
  if (!fp) {
    PLOG(ERROR) << "Failed to open file " << path.value();
    return false;
  }

  std::unique_ptr<char[]> chunk(new char[kChunkSize]);
  base::RingBuffer<std::string, kMaxFileSize / kChunkSize> buf;
  size_t bytes_read = 0;

  // Since most logs are not seekable, read until the end with a circular
  // buffer. Note that logs will not always be kMaxFileSize even if the file
  // exceeds kMaxFileSize, depending on kChunkSize and the size of the file. It
  // could vary anywhere from (kMaxFileSize - kChunkSize + 1) to kMaxFileSize.
  while ((bytes_read = fread(chunk.get(), 1, kChunkSize, fp.get())) != 0) {
    if (bytes_read < kChunkSize) {
      chunk[bytes_read] = '\0';
    }
    buf.SaveToBuffer(std::string(chunk.get()));
  }

  contents->clear();
  for (auto it = buf.Begin(); it == buf.End(); ++it)
    contents->append(**it);

  return true;
}

void CommandlineReportStatus(base::WaitableEvent* event,
                             bool* status,
                             bool result) {
  *status = result;
  event->Signal();
}

bool FillReportFromCommandline(FeedbackCommon* report) {
  base::CommandLine* args = base::CommandLine::ForCurrentProcess();
  if (!args->HasSwitch(kSwitchProductId)) {
    LOG(ERROR) << "No product id provided";
    return false;
  }
  std::string product_id_string = args->GetSwitchValueASCII(kSwitchProductId);
  int product_id;
  if (!base::StringToInt(product_id_string, &product_id) || product_id <= 0) {
    LOG(ERROR) << "Invalid product id provided, must be a positive number";
    return false;
  }
  if (!args->HasSwitch(kSwitchDescription)) {
    LOG(ERROR) << "No description provided";
    return false;
  }

  report->AddLog("unique_guid",
                 base::Uuid::GenerateRandomV4().AsLowercaseString());
  report->set_product_id(product_id);
  report->set_description(args->GetSwitchValueASCII(kSwitchDescription));
  report->set_user_email(args->GetSwitchValueASCII(kSwitchUserEmail));
  report->set_page_url(args->GetSwitchValueASCII(kSwitchPageUrl));
  report->set_category_tag(args->GetSwitchValueASCII(kSwitchBucket));

  std::vector<std::string> raw_files = base::SplitString(
      args->GetSwitchValueNative(kSwitchRawFiles), kListSeparator,
      base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  for (const std::string& path : raw_files) {
    auto content = std::make_unique<std::string>();

    if (!base::ReadFileToStringWithMaxSize(base::FilePath(path), content.get(),
                                           kMaxFileSize)) {
      if (content->empty()) {
        LOG(ERROR) << "Could not read raw file: " << path;
        return false;
      }
      // Skip files that are too large as it doesn't make sense to send partial
      // raw/binary files.
      LOG(WARNING) << "Skipping raw file. Exceeds max file size: " << path;
      continue;
    }

    report->AddFile(path, std::move(content));
  }

  std::vector<std::string> log_files = args->GetArgs();
  for (const std::string& path : log_files) {
    std::string content;
    if (ReadFileFromBack(base::FilePath(path), &content)) {
      report->AddLog(path, content);
    } else {
      LOG(ERROR) << "Could not read log file: " << path;
      return false;
    }
  }
  return true;
}

bool SendReport(FeedbackServiceInterface* interface, FeedbackCommon* report) {
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool status;

  report->CompressLogs();
  interface->SendFeedback(
      *report, base::BindOnce(&CommandlineReportStatus, &event, &status));
  event.Wait();
  return status;
}

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);

  // Some libchrome calls need this.
  base::AtExitManager at_exit_manager;

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);
  scoped_refptr<FeedbackServiceInterface> itf =
      new DBusFeedbackServiceInterface();
  scoped_refptr<FeedbackCommon> report = new FeedbackCommon();

  if (!FillReportFromCommandline(report.get())) {
    LOG(ERROR) << "Not sending report";
    return EX_USAGE;
  }

  return SendReport(itf.get(), report.get()) ? EX_OK : EX_UNAVAILABLE;
}
