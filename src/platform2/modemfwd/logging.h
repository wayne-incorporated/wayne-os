// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_LOGGING_H_
#define MODEMFWD_LOGGING_H_

#include <base/logging.h>

#define ELOG_IS_ON() (DCHECK_IS_ON() || ::modemfwd::g_extra_logging)
#define ELOG(level) LOG_IF(level, ELOG_IS_ON())
#define EVLOG(level) VLOG_IF(level, ELOG_IS_ON())

namespace modemfwd {

extern bool g_extra_logging;

}  // namespace modemfwd

#endif  // MODEMFWD_LOGGING_H_
