// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_SETUP_CONFIG_H_
#define ARC_SETUP_CONFIG_H_

#include <functional>
#include <map>
#include <memory>
#include <string>

#include <base/environment.h>
#include <base/strings/string_piece.h>
#include <base/values.h>

namespace base {

class FilePath;

}  // namespace base

namespace arc {

// A class that holds configuration variables for arc-setup.
class Config {
 public:
  Config(const base::FilePath& config_json,
         std::unique_ptr<base::Environment> config_env);
  Config(const Config&) = delete;
  Config& operator=(const Config&) = delete;

  ~Config();

  // Finds a string config with |name| first in JSON and stores it in |out| if
  // found. If the |name| is not in JSON, does the same search against the
  // environment variables. Returns true if found.
  bool GetString(base::StringPiece name, std::string* out) const;

  // Finds an integer config with |name| in JSON and stores it in |out| if
  // found. If the |name| is not in JSON, does the same search against the
  // environment variables. Returns true if an integer entry in JSON or
  // an integer-compatible string in env (e.g. "123", "-123") is found.
  bool GetInt(base::StringPiece name, int* out) const;

  // Finds a boolean config with |name| in JSON and stores it in |out| if
  // found. If the |name| is not in JSON, does the same search against the
  // environment variables. Returns true if a boolean entry in JSON or
  // a boolean-compatible string in env (e.g. "1", "0", "false") is found.
  bool GetBool(base::StringPiece name, bool* out) const;

  // These functions do the same as above, but aborts when |name| is not found.
  std::string GetStringOrDie(base::StringPiece name) const;
  int GetIntOrDie(base::StringPiece name) const;
  bool GetBoolOrDie(base::StringPiece name) const;

 private:
  bool ParseJsonFile(const base::FilePath& config_json);
  base::Value* FindConfig(base::StringPiece name) const;

  std::map<std::string, std::unique_ptr<base::Value>, std::less<>> json_;
  std::unique_ptr<base::Environment> env_;
};

}  // namespace arc

#endif  // ARC_SETUP_CONFIG_H_
