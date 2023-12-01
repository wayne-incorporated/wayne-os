// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/vsh/scoped_termios.h"

#include <fcntl.h>

#include <sys/types.h>

#include <utility>

#include <base/files/scoped_file.h>
#include <base/logging.h>

namespace vm_tools {
namespace vsh {

ScopedTermios::ScopedTermios(base::ScopedFD tty_fd)
    : tty_fd_(std::move(tty_fd)), has_termios_(false) {}

ScopedTermios::~ScopedTermios() {
  if (!Restore())
    LOG(ERROR) << "Failed to reset termios settings. Terminal may be broken.";
}

bool ScopedTermios::SetTermiosMode(TermiosMode mode) {
  if (!has_termios_) {
    if (tcgetattr(tty_fd_.get(), &saved_termios_) < 0) {
      PLOG(ERROR) << "Error getting termios attributes";
      return false;
    }
    has_termios_ = true;
  }

  struct termios new_termios = saved_termios_;
  // The termios flags below are lifted from cfmakeraw(3).
  switch (mode) {
    case TermiosMode::RAW:
      new_termios.c_iflag &=
          ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
      new_termios.c_oflag &= ~(OPOST);
      new_termios.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
      new_termios.c_cflag &= ~(CSIZE | PARENB);
      new_termios.c_cflag |= (CS8);
      break;
    case TermiosMode::CANON:
      new_termios.c_iflag |=
          (IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
      new_termios.c_oflag |= (OPOST);
      new_termios.c_lflag |= (ECHO | ECHONL | ICANON | ISIG | IEXTEN);
      new_termios.c_cflag |= (CSIZE | PARENB);
      new_termios.c_cflag |= (CS8);
      break;
  }

  if (tcsetattr(tty_fd_.get(), TCSAFLUSH, &new_termios) < 0) {
    PLOG(ERROR) << "Error setting termios attributes";
    return false;
  }

  return true;
}

bool ScopedTermios::Restore() {
  // If SetTermiosMode() was never called, Restore() should do nothing.
  if (!has_termios_)
    return true;

  if (tcsetattr(tty_fd_.get(), TCSAFLUSH, &saved_termios_) < 0) {
    PLOG(ERROR) << "Error restoring termios attributes";
    return false;
  }

  // Once the Restore() is done, don't bother doing another Restore() unless
  // SetTermiosMode() is called again.
  has_termios_ = false;

  return true;
}

int ScopedTermios::GetRawFD() {
  return tty_fd_.get();
}

}  // namespace vsh
}  // namespace vm_tools
