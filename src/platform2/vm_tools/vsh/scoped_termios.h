// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_VSH_SCOPED_TERMIOS_H_
#define VM_TOOLS_VSH_SCOPED_TERMIOS_H_

#include <termios.h>

#include <base/files/scoped_file.h>

namespace vm_tools {
namespace vsh {

// ScopedTermios is a helper class for managing termios settings,
// namely raw/canonical mode. When an instance of this class goes
// out of scope, it will restore the original termios settings.
class ScopedTermios {
 public:
  // Creates an instance of ScopedTermios that will control the termios
  // settings for a TTY. The TTY fd must be valid for at least the lifetime of
  // this ScopedTermios instance.
  explicit ScopedTermios(base::ScopedFD tty_fd);
  ScopedTermios(const ScopedTermios&) = delete;
  ScopedTermios& operator=(const ScopedTermios&) = delete;

  ~ScopedTermios();

  enum class TermiosMode { RAW, CANON };

  // Sets the termios mode for the TTY.
  bool SetTermiosMode(TermiosMode mode);

  // Restores the termios settings for the TTY to match those before
  // SetTermiosMode was first called.
  bool Restore();

  // Gets the raw FD for this terminal.
  int GetRawFD();

 private:
  base::ScopedFD tty_fd_;
  bool has_termios_;
  struct termios saved_termios_;
};

}  // namespace vsh
}  // namespace vm_tools

#endif  // VM_TOOLS_VSH_SCOPED_TERMIOS_H_
