// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_LOGGING_H_
#define SHILL_LOGGING_H_

#include <base/logging.h>

#include "shill/scope_logger.h"

// How to use:
//
// The SLOG macro and its variants are similar to the VLOG macros
// defined in base/logging.h, except that the SLOG macros take an additional
// |scope| argument to enable logging only if |scope| is enabled.
//
// Like VLOG, SLOG macros internally map verbosity to LOG severity using
// negative values, i.e. SLOG(scope, 1) corresponds to LOG(-1).
//
// Example usages:
//  SLOG(Service, 1) << "Printed when the 'service' scope is enabled and "
//                      "the verbose level is greater than or equal to 1";
//
//  SLOG_IF(Service, 1, (size > 1024))
//      << "Printed when the 'service' scope is enabled, the verbose level "
//         "is greater than or equal to 1, and size is more than 1024";
//

#if defined(SLOG_MEANS_VLOG)

// For libshill-net, because library users do not implement SLOG.
#define SLOG(verbose_level) VLOG(verbose_level)

#else

#define GET_MACRO_OVERLOAD2(arg1, arg2, macro_name, ...) macro_name

#define SLOG_IS_ON(scope, verbose_level)                             \
  ::shill::ScopeLogger::IsLogEnabled(::shill::ScopeLogger::k##scope, \
                                     verbose_level)

#define SLOG_STREAM(verbose_level) \
  ::logging::LogMessage(__FILE__, __LINE__, -verbose_level).stream()

#define SLOG_1ARG(verbose_level)                  \
  LAZY_STREAM(SLOG_STREAM(verbose_level),         \
              ::shill::ScopeLogger::IsLogEnabled( \
                  ::shill::Logging::kModuleLogScope, verbose_level))

#define SLOG_2ARG(object, verbose_level)                             \
  LAZY_STREAM(SLOG_STREAM(verbose_level),                            \
              ::shill::ScopeLogger::IsLogEnabled(                    \
                  ::shill::Logging::kModuleLogScope, verbose_level)) \
      << (object ? ::shill::Logging::ObjectID(object) : "(anon)") << " "

#define SLOG(...) \
  GET_MACRO_OVERLOAD2(__VA_ARGS__, SLOG_2ARG, SLOG_1ARG)(__VA_ARGS__)

#define SLOG_IF(scope, verbose_level, condition) \
  LAZY_STREAM(SLOG_STREAM(verbose_level),        \
              SLOG_IS_ON(scope, verbose_level) && (condition))

#define SPLOG_STREAM(verbose_level)                               \
  ::logging::ErrnoLogMessage(__FILE__, __LINE__, -verbose_level,  \
                             ::logging::GetLastSystemErrorCode()) \
      .stream()

#define SPLOG(scope, verbose_level) \
  LAZY_STREAM(SPLOG_STREAM(verbose_level), SLOG_IS_ON(scope, verbose_level))

#define SPLOG_IF(scope, verbose_level, condition) \
  LAZY_STREAM(SPLOG_STREAM(verbose_level),        \
              SLOG_IS_ON(scope, verbose_level) && (condition))

#endif

namespace base {

class CommandLine;

}  // namespace base

namespace shill {

namespace switches {

// Command line switches used to setup logging.
// Clients may use this to display useful help messages.

// Logging level:
//   0 = LOG(INFO), 1 = LOG(WARNING), 2 = LOG(ERROR),
//   -1 = SLOG(..., 1), -2 = SLOG(..., 2), etc.
extern const char kLogLevel[];
// Scopes to enable for SLOG()-based logging.
extern const char kLogScopes[];

}  // namespace switches

// Looks for the command line switches |kLogLevelSwitch| and |kLogScopesSwitch|
// in |cl| and accordingly sets log scopes and levels.
void SetLogLevelFromCommandLine(base::CommandLine* cl);

}  // namespace shill

#endif  // SHILL_LOGGING_H_
