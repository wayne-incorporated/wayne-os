# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Common utilities for shell programs that manipulate devices and the
# connection manager, including "modem" and "connectivity"

# Prints an error message to stderr.
error() {
  echo "ERROR: $@" 1>&2
}

# Prints an error message to stderr and exits with a status code 1.
error_exit() {
  error "$@"
  exit 1
}

# Generates a small snippet of code to take a single argument out of our
# parameter list, and complain (and exit) if it's not present. Used in other
# places like: $(needarg foo), which binds foo to $1.
needarg() {
  # We need to echo eval here because the part of bash that understands
  # variable assignments has already run by the time we substitute in the
  # text of $(needarg foo) - i.e., bash will try to execute 'foo="$1"' as
  # a *command*, which it isn't. The eval forces bash to reparse the code
  # before executing it.
  echo eval "$1=\"\$1\";
      [ -z \"\$$1\" ] && echo 'Missing argument: $1' && usage;
      shift"
}

# Generates a small snippet of code to take a matching flag argument
# and value out of our parameter list if present.  If not, assign the
# default value to $1.
# Used in other places like: $(arg_or_default foo bar)
# which binds foo to "bar", unless $1 is "-foo" in which case foo is
# bound to $2.
arg_or_default() {
  echo eval "[ x\"\$1\" = x\"-$1\" ] && $1=\"\$2\" && shift 2;
      [ -z \"\$$1\" ] && $1=\"$2\""
}

# Generates a small snippet of code to take a single argument out of our
# parameter list.  If it's not present, prompt the user and accept a
# blank input as if the users chose the default specified as $2.
arg_or_prompt() {
  echo eval "$1=\"\$1\";
      [ -n \"\$$1\" ] && shift ;
      [ -z \"\$$1\" ] && read -p \"$1 [$2]: \" $1 ;
      [ -z \"\$$1\" ] && $1=\"$2\";"
}

# Requires a key in a csv list of key value pairs
#  $1 - comma separated list of keys and values
#  $2 - required key
# If the key is not found in the argument list, then prompt the user
# for a value for key, and return $key,$value appended to $1
require() {
  local value
  local args=$1
  local key=$2
  if [ -z "$args" -o -n "${args##*$2*}" ] ; then
    read -p "$key: " value
    if [ -n "$args" ] ; then
      args="$args,"
    fi
    args="$args$key,$value"
  fi
  echo "$args"
}

# Removes the indexes output by the --fixed option of dbus-send
stripindexes() {
  sed -e 's/^\/[[:digit:]]\+\///' -e 's/[^[:space:]]*/\0:/' -e 's/^/  /'
}

# Prints values for dbus-send --fixed output lines whose keys match
# the first argument.  Call it with 'Key' and it will take input like
#  /4/Key/0 value value
#  /5/SomethingElse/0 something else
# and write
#  value value
extract_dbus_match() {
  local argument=$1
  sed -r -n -e "s_^/[[:digit:]]+/$argument/\S+\s+__p"
}

# Waits for a particular DBus service to be up.
poll_for_dbus_service() {
  local service="$1"
  local found
  for _ in {0..9}; do
    found=$(dbus_call "org.freedesktop.DBus" "/org/freedesktop/DBus" \
                      "org.freedesktop.DBus.NameHasOwner" \
                      string:"${service}")
    [ "${found}" = "true" ] && return 0
    sleep 0.1
  done
  error_exit "${service} could not be found."
}

# Invokes a DBus method on a DBus object.
dbus_call() {
  local dest="$1"
  local object="$2"
  local method="$3"
  shift 3

  dbus-send --system --print-reply --fixed --dest="${dest}" \
    "${object}" "${method}" "$@"
}

# Invokes a DBus method on a DBus object with the specified timeout.
dbus_call_with_timeout() {
  local dest="$1"
  local timeout_ms="$2"
  local object="$3"
  local method="$4"
  shift 4

  dbus-send --system --print-reply --fixed --dest="${dest}" \
    --reply-timeout="${timeout_ms}" "${object}" "${method}" "$@"
}

# Gets a DBus property of an interface of a DBus object.
dbus_property() {
  local dest="$1"
  local object="$2"
  local interface="$3"
  local property="$4"

  dbus_call "${dest}" "${object}" org.freedesktop.DBus.Properties.Get \
    "string:${interface}" "string:${property}"
}

# Invokes a DBus introspect on a DBus object using gdbus.
gdbus_introspect() {
  local dest="$1"
  local object="$2"
  shift 2

  gdbus introspect --system --dest="${dest}" -o "${object}"  --recurse \
    --only-properties "$@"
}

# Gets all DBus properties of an interface of a DBus object.
dbus_properties() {
  local dest="$1"
  local object="$2"
  local interface="$3"

  dbus_call "${dest}" "${object}" org.freedesktop.DBus.Properties.GetAll \
    "string:${interface}"
}

# Unpacks output by the --fixed option of dbus-send into key-value pairs.
#
# e.g. The following code
#
#     echo "
#     /0 value1
#     /1 value2
#     " | unpack_tuple key1 key2
#
#  will output
#
#     key1: value1
#     key2: value2
#
unpack_tuple() {
  local cmd='sed'
  local argidx=0
  while test $# != 0; do
    # Grab a variable name
    local varname=$1
    shift

    # Generate an expression that turns the current index into that
    # variable name, and append it.
    cmd="$cmd -e s/^\\/${argidx}/$varname:/"
    argidx=$((argidx+1))
  done
  $cmd
}

# Formats dictionary output by the --fixed option of dbus-send into
# key-value pairs.
#
# e.g. The following code
#
#     echo "
#     /0/key1 value1
#     /1/key2/0 value2a
#     /1/key2/1 value2b
#     " | format_dbus_dict
#
#  will output
#
#     key1: value1
#     key2: value2a, value2b
#
format_dbus_dict() {
  awk 'BEGIN {
    entry_pattern = "/([0-9]+)/([^ /]+)(/[0-9]+)?"
    num_entries = 0
  }
  $0 ~ entry_pattern {
    entry_value = substr($0, length($1) + 2)
    split($1, entry_tokens, "/")
    entry_index = entry_tokens[2]
    if (entry_keys[entry_index] == "") {
      entry_indices[num_entries++] = entry_index
      entry_keys[entry_index] = entry_tokens[3]
      entry_values[entry_index] = entry_value
    } else {
      entry_values[entry_index] = entry_values[entry_index] ", " entry_value
    }
  }
  END {
    for (i = 0; i < num_entries; ++i) {
      entry_index = entry_indices[i]
      print entry_keys[entry_index] ": " entry_values[entry_index]
    }
  }'
}

# Indents non-empty lines with two spaces per indent level.
indent() {
  local level="$1"
  local space

  [ -n "${level}" ] || level=1
  space=$(printf "%${level}s%${level}s" ' ' ' ')
  sed -E "s/^(.+)/${space}\1/"
}
