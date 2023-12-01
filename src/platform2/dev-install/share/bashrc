# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Allow `sudo dev_install` and `sudo emerge` to work by preserving the
# active LD_LIBRARY_PATH settings.
# https://crbug.com/535771
alias sudo='sudo LD_LIBRARY_PATH="${LD_LIBRARY_PATH}"'

# Hook to notify users of dev_install if they type a command which is
# provided by running dev_install.
command_not_found_handle() {
  echo "${0##*/}: $1: command not found" >&2

  if [[ -d /usr/local/etc/portage ]]; then
    # dev_install was already run.  Don't confuse the user if
    # installable_commands wasn't accurate.
    return 127
  fi

  if grep -Fxq "$1" /usr/share/dev-install/installable_commands; then
    echo >&2
    echo 'This command is available in the ChromiumOS developer tools.  You' >&2
    echo 'can download the developer tools by running "sudo dev_install".' >&2
  fi

  return 127
}
