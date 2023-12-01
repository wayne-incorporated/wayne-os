// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/common/util.h"

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <string>

#include <base/logging.h>

// NOTE: the coding style asks for syslog.h ("C system header") to be
// included before base/logging.h ("Library .h file") but
// unfortunately this is not possible because of a bug in the latter.
#include <syslog.h>

using std::string;

namespace p2p {

namespace util {

static bool SyslogFunc(int severity,
                       const char* file,
                       int line,
                       size_t message_start,
                       const string& str) {
  static_assert(logging::LOGGING_INFO == 0);
  static_assert(logging::LOGGING_WARNING == 1);
  static_assert(logging::LOGGING_ERROR == 2);
  static_assert(logging::LOGGING_FATAL == 3);
  static_assert(logging::LOGGING_NUM_SEVERITIES == 4);
  int base_severity_to_syslog_priority[logging::LOGGING_NUM_SEVERITIES] = {
      LOG_INFO,     // logging::LOGGING_INFO
      LOG_WARNING,  // logging::LOGGING_WARNING
      LOG_ERR,      // logging::LOGGING_ERROR
      LOG_ALERT,    // logging::LOGGING_FATAL
  };

  int priority = LOG_NOTICE;
  if (severity >= 0 && severity < logging::LOGGING_NUM_SEVERITIES)
    priority = base_severity_to_syslog_priority[severity];

  // The logging infrastructure includes a terminating newline at the
  // end of the message. We don't want that. Strip it.
  char* message = strdupa(str.c_str() + message_start);
  size_t message_len = strlen(message);
  for (int n = message_len - 1; n >= 0; --n) {
    if (isspace(message[n]))
      message[n] = 0;
    else
      break;
  }
  syslog(priority, "%s [%s:%d]", message, file, line);

  return false;  // also send message to other logging destinations
}

void SetupSyslog(const char* program_name, bool include_pid) {
  int option = LOG_NDELAY | LOG_CONS;
  if (include_pid)
    option |= LOG_PID;
  openlog(program_name, option, LOG_DAEMON);
  logging::SetLogMessageHandler(SyslogFunc);
}

bool IsXAttrSupported(const base::FilePath& dir_path) {
  char* path = strdup(dir_path.Append("xattr_test_XXXXXX").value().c_str());

  int fd = mkstemp(path);
  if (fd == -1) {
    PLOG(ERROR) << "Error creating temporary file in " << dir_path.value();
    free(path);
    return false;
  }

  if (unlink(path) != 0) {
    PLOG(ERROR) << "Error unlinking temporary file " << path;
    close(fd);
    free(path);
    return false;
  }

  int xattr_res = fsetxattr(fd, "user.xattr-test", "value", strlen("value"), 0);
  if (xattr_res != 0) {
    if (errno == ENOTSUP) {
      // Leave it to call-sites to warn about non-support.
    } else {
      PLOG(ERROR) << "Error setting xattr on " << path;
    }
  }
  close(fd);
  free(path);
  return xattr_res == 0;
}

}  // namespace util

}  // namespace p2p
