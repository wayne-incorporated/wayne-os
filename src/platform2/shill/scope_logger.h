// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SCOPE_LOGGER_H_
#define SHILL_SCOPE_LOGGER_H_

#include <bitset>
#include <string>
#include <vector>

#include <base/logging.h>
#include <base/no_destructor.h>
#include <gtest/gtest_prod.h>

#include "shill/callbacks.h"

namespace shill {

// A class that enables logging based on scope and verbose level. It is not
// intended to be used directly but via the SLOG() macros in shill/logging.h
class ScopeLogger {
 public:
  // Logging scopes.
  //
  // Update kScopeNames in scope_logger.cc after changing this enumerated type.
  // These scope identifiers are sorted by their scope names alphabetically.
  enum Scope {
    kBluetooth,
    kCellular,
    kConnection,
    kCrypto,
    kDaemon,
    kDBus,
    kDevice,
    kDHCP,
    kDNS,
    kEthernet,
    kHTTP,
    kInet,
    kLink,
    kManager,
    kMetrics,
    kModem,
    kPortal,
    kPower,
    kPPP,
    kProfile,
    kProperty,
    kResolver,
    kRoute,
    kRTNL,
    kService,
    kStorage,
    kTask,
    kTC,
    kVPN,
    kWiFi,
    kNumScopes
  };

  // Returns a singleton of this class.
  static ScopeLogger* GetInstance();

  // Returns true if logging is enabled for |scope| and |verbose_level|, i.e.
  // scope_enable_[|scope|] is true and |verbose_level| <= |verbose_level_|
  static bool IsLogEnabled(Scope scope, int verbose_level);

  ~ScopeLogger();

  // Returns true if logging is enabled for |scope| at any verbosity level.
  bool IsScopeEnabled(Scope scope) const;

  // Returns a string comprising the names, separated by commas, of all scopes.
  std::string GetAllScopeNames() const;

  // Returns a string comprising the names, separated by plus signs, of all
  // scopes that are enabled for logging.
  std::string GetEnabledScopeNames() const;

  // Enables/disables scopes as specified by |expression|.
  //
  // |expression| is a string comprising a sequence of scope names, each
  // prefixed by a plus '+' or minus '-' sign. A scope prefixed by a plus
  // sign is enabled for logging, whereas a scope prefixed by a minus sign
  // is disabled for logging. Scopes that are not mentioned in |expression|
  // remain the same state.
  //
  // To allow resetting the state of all scopes, an exception is made for the
  // first scope name in the sequence, which may not be prefixed by any sign.
  // That is considered as an implicit plus sign for that scope and also
  // indicates that all scopes are first disabled before enabled by
  // |expression|.
  //
  // If |expression| is an empty string, all scopes are disabled. Any unknown
  // scope name found in |expression| is ignored.
  void EnableScopesByName(const std::string& expression);

  // Register for log scope enable/disable state changes for |scope|.
  void RegisterScopeEnableChangedCallback(
      Scope scope, base::RepeatingCallback<void(bool)> callback);

  // Sets the verbose level for all scopes to |verbose_level|.
  void set_verbose_level(int verbose_level) { verbose_level_ = verbose_level; }

  // Retrieves the current verbose level.
  int verbose_level() const { return verbose_level_; }

 private:
  friend class base::NoDestructor<ScopeLogger>;
  friend class ScopeLoggerTest;
  FRIEND_TEST(ScopeLoggerTest, GetEnabledScopeNames);
  FRIEND_TEST(ScopeLoggerTest, SetScopeEnabled);
  FRIEND_TEST(ScopeLoggerTest, SetVerboseLevel);

  ScopeLogger();
  ScopeLogger(const ScopeLogger&) = delete;
  ScopeLogger& operator=(const ScopeLogger&) = delete;

  // Disables logging for all scopes.
  void DisableAllScopes();

  // Enables or disables logging for |scope|.
  void SetScopeEnabled(Scope scope, bool enabled);

  // Boolean values to indicate whether logging is enabled for each scope.
  std::bitset<kNumScopes> scope_enabled_;

  // Verbose level that is applied to all scopes.
  int verbose_level_;

  // Hooks to notify interested parties of changes to log scopes.
  std::vector<base::RepeatingCallback<void(bool)>>
      log_scope_callbacks_[kNumScopes];
};

}  // namespace shill

#endif  // SHILL_SCOPE_LOGGER_H_
