// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGELOADER_GLOBAL_CONTEXT_H_
#define IMAGELOADER_GLOBAL_CONTEXT_H_

#include <memory>

namespace imageloader {

class GlobalContext {
 public:
  GlobalContext() = default;
  // Since an object of this class is a global static variable, this destructor
  // needs to stay non-trivial. This means no keeping objects with non-trivial
  // dtors around in this class.
  virtual ~GlobalContext() = default;

  GlobalContext(const GlobalContext&) = delete;
  GlobalContext& operator=(const GlobalContext&) = delete;

  // Sets the curernt instance as the global one.
  void SetAsCurrent();

  // Returns the ponter to the current global instance of this object.
  static GlobalContext* Current();

  // Returns whether we're running an official build (true) or an dev-signed
  // image (false).
  virtual bool IsOfficialBuild() const;

 private:
  static GlobalContext* g_ctx_;
};

}  // namespace imageloader

#endif  // IMAGELOADER_GLOBAL_CONTEXT_H_
