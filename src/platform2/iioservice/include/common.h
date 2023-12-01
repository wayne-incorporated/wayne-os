/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef IIOSERVICE_INCLUDE_COMMON_H_
#define IIOSERVICE_INCLUDE_COMMON_H_

#include <string>

#include <base/logging.h>
#include <base/threading/thread.h>

#define LOGF(level)                                              \
  LOG(level) << "(" << base::PlatformThread::CurrentId() << ") " \
             << __FUNCTION__ << "(): "

#define PLOGF(level) PLOG(level) << __FUNCTION__ << "(): "

#endif  // IIOSERVICE_INCLUDE_COMMON_H_
