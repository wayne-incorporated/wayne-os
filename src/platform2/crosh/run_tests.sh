#!/bin/bash
# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Be lazy about locale sorting and such.
export LC_ALL=C

show_diff() {
  local tmp1 tmp2
  tmp1=$(mktemp)
  tmp2=$(mktemp)
  echo "$1" > "${tmp1}"
  echo "$2" > "${tmp2}"
  diff -U 1 "${tmp1}" "${tmp2}" | sed -e 1d -e 2d -e 's:^:\t:'
  rm -f "${tmp1}" "${tmp2}"
}

ret=0

for s in crosh {dev,extra,removable}.d/[0-9][0-9]-*.sh; do
  # One or more directories might not exist or be empty.
  [[ -e "${s}" ]] || continue

  echo "Checking ${s}"

  #
  # No trailing whitespace.
  #
  grep -Ehn '[[:space:]]+$' "${s}" && ret=1

  #
  # Make sure we can at least parse the file and catch glaringly
  # obvious errors.
  #
  bash -n "${s}" || ret=1

  #
  # Make sure every command is documented.
  #
  commands=$(grep -o '^cmd_[^(]*' "${s}" | sed 's:^cmd_::' | sort)
  for command in ${commands}; do
    if ! grep -q "^help_${command}()" "${s}"; then
      if ! grep -q "^USAGE_${command}=" "${s}"; then
        echo "ERROR: ${command} is not documented (missing USAGE_${command})"
        ret=1
      fi
      if ! grep -q "^HELP_${command}=" "${s}"; then
        echo "ERROR: ${command} is not documented (missing HELP_${command})"
        ret=1
      fi
    fi
  done
  # Every HELP_xxx needs a cmd_xxx (catch typos).
  commands=$(grep -o '^HELP_[^=]*' "${s}" | sed 's:^HELP_::' | sort)
  for command in ${commands}; do
    if ! grep -q "^cmd_${command}()" "${s}"; then
      echo "ERROR: stray HELP_${command} var (typo?)"
      ret=1
    fi
  done
  # Same for USAGE_xxx.
  commands=$(grep -o '^USAGE_[^=]*' "${s}" | sed 's:^USAGE_::' | sort)
  for command in ${commands}; do
    if ! grep -q "^cmd_${command}()" "${s}"; then
      echo "ERROR: stray USAGE_${command} var (typo?)"
      ret=1
    fi
  done
  # Same for help_xxx.
  commands=$(grep -o '^help_[^(]*' "${s}" | sed 's:^help_::' | sort)
  for command in ${commands}; do
    if ! grep -q "^cmd_${command}()" "${s}"; then
      echo "ERROR: stray help_${command} var (typo?)"
      ret=1
    fi
  done

  #
  # Make sure cmd_* and help_* use () for function bodies.
  # People often forget to use `local` in their functions and end up polluting
  # the environment.  Forcing all commands into a subshell prevents that.
  #
  if grep -Ehn '^(cmd|help)_.*\(\) *\{' "${s}"; then
    cat <<EOF
ERROR: The above commands need to use () for their bodies, not {}:
 cmd_foo() (
   ...
 )

EOF
    ret=1
  fi

  #
  # Check for common style mistakes.
  #
  if grep -hn '^[a-z0-9_]*()[{(]' "${s}"; then
    cat <<EOF
ERROR: The above commands need a space after the ()

EOF
    ret=1
  fi

  #
  # Check for common bashisms.  We don't use `checkbashisms` as that script
  # throws too many false positives, and we do actually use some bash.
  #
  if grep -hn '&>' "${s}"; then
    cat <<EOF
ERROR: The &> construct is a bashism.  Please fix it like so:
       before:   some_command &> /dev/null
       after :   some_command >/dev/null 2>&1
       Note: Some commands (like grep) have options to silence
             their output.  Use that rather than redirection.

EOF
    ret=1
  fi

  if grep -hn '[[:space:]]\[\[[[:space:]]' "${s}"; then
    cat <<EOF
ERROR: The [[...]] construct is a bashism.  Please stick to [...].

EOF
    ret=1
  fi

  if grep -hn 'echo -' "${s}"; then
    cat <<\EOF
ERROR: `echo -n` and `echo -e` options are not portable.  Please use printf.
       before:   echo -n "foo ${blah}"
       after :   printf '%s' "foo ${blah}"
       before:   echo -e "${var_with_escapes}"
       after :   printf '%b\n' "${var_with_escapes}"

EOF
    ret=1
  fi
done

exit "${ret}"
