// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/scope_logger.h"

#include <iterator>
#include <vector>

#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_tokenizer.h>
#include <base/strings/string_util.h>

namespace shill {

namespace {

const int kDefaultVerboseLevel = 0;

// Scope names corresponding to the scope defined by ScopeLogger::Scope.
const char* const kScopeNames[] = {
    "bluetooth", "cellular", "connection", "crypto",   "daemon", "dbus",
    "device",    "dhcp",     "dns",        "ethernet", "http",   "inet",
    "link",      "manager",  "metrics",    "modem",    "portal", "power",
    "ppp",       "profile",  "property",   "resolver", "route",  "rtnl",
    "service",   "storage",  "task",       "tc",       "vpn",    "wifi",
};

static_assert(std::size(kScopeNames) == ScopeLogger::kNumScopes,
              "Scope tags do not have expected number of strings");

}  // namespace

// static
ScopeLogger* ScopeLogger::GetInstance() {
  // ScopeLogger needs to be a 'leaky' singleton as it needs to survive to
  // handle logging till the very end of the shill process. Making ScopeLogger
  // leaky is fine as it does not need to clean up or release any resource at
  // destruction.
  static base::NoDestructor<ScopeLogger> instance;
  return instance.get();
}

// static
bool ScopeLogger::IsLogEnabled(Scope scope, int verbose_level) {
  auto* logger = GetInstance();
  return logger->IsScopeEnabled(scope) &&
         verbose_level <= logger->verbose_level_;
}

ScopeLogger::ScopeLogger() : verbose_level_(kDefaultVerboseLevel) {}

ScopeLogger::~ScopeLogger() {}

bool ScopeLogger::IsScopeEnabled(Scope scope) const {
  CHECK_GE(scope, 0);
  CHECK_LT(scope, kNumScopes);

  return scope_enabled_[scope];
}

std::string ScopeLogger::GetAllScopeNames() const {
  std::vector<std::string> names(std::begin(kScopeNames),
                                 std::end(kScopeNames));
  return base::JoinString(names, "+");
}

std::string ScopeLogger::GetEnabledScopeNames() const {
  std::vector<std::string> names;
  for (size_t i = 0; i < std::size(kScopeNames); ++i) {
    if (scope_enabled_[i])
      names.push_back(kScopeNames[i]);
  }
  return base::JoinString(names, "+");
}

void ScopeLogger::EnableScopesByName(const std::string& expression) {
  if (expression.empty()) {
    DisableAllScopes();
    return;
  }

  // As described in the header file, if the first scope name in the
  // sequence specified by |expression| is not prefixed by a plus or
  // minus sign, it indicates that all scopes are first disabled before
  // enabled by |expression|.
  if (expression[0] != '+' && expression[0] != '-')
    DisableAllScopes();

  bool enable_scope = true;
  base::StringTokenizer tokenizer(expression, "+-");
  tokenizer.set_options(base::StringTokenizer::RETURN_DELIMS);
  while (tokenizer.GetNext()) {
    if (tokenizer.token_is_delim()) {
      enable_scope = (tokenizer.token() == "+");
      continue;
    }

    if (tokenizer.token().empty())
      continue;

    size_t i;
    for (i = 0; i < std::size(kScopeNames); ++i) {
      if (tokenizer.token() == kScopeNames[i]) {
        SetScopeEnabled(static_cast<Scope>(i), enable_scope);
        break;
      }
    }
    LOG_IF(WARNING, i == std::size(kScopeNames))
        << "Unknown scope '" << tokenizer.token() << "'";
  }
}

void ScopeLogger::RegisterScopeEnableChangedCallback(
    Scope scope, base::RepeatingCallback<void(bool)> callback) {
  CHECK_GE(scope, 0);
  CHECK_LT(scope, kNumScopes);
  log_scope_callbacks_[scope].push_back(callback);
}

void ScopeLogger::DisableAllScopes() {
  // Iterate over all scopes so the notification side-effect occurs.
  for (size_t i = 0; i < std::size(kScopeNames); ++i) {
    SetScopeEnabled(static_cast<Scope>(i), false);
  }
}

void ScopeLogger::SetScopeEnabled(Scope scope, bool enabled) {
  CHECK_GE(scope, 0);
  CHECK_LT(scope, kNumScopes);

  if (scope_enabled_[scope] != enabled) {
    for (const auto& callback : log_scope_callbacks_[scope]) {
      callback.Run(enabled);
    }
  }

  scope_enabled_[scope] = enabled;
}

}  // namespace shill
