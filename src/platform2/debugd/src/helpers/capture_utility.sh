#!/bin/sh

# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Helper script to initiate over-the-air or regular net-device packet
# capture.


# get_array_size returns the number of positional arguments passed to
# this function.
#
# @param a, b, c... the input positional parameters.
# @return count of positional parameters.
get_array_size ()
{
  echo "$#"
}


# get_array_element returns the n'th positional argument passed to
# this function.
#
# @param count the number of the positional parameter to return.
# @param a, b, c... the input positional parameters.
# @return positional paramter #|count|.
get_array_element ()
{
  shift $1
  echo "$1"
}


# get_device_list returns the name of all network interfaces.
#
# @return "<device0>\n<device1>..."
get_device_list ()
{
  ip -o link show | awk '{ sub(/:$/, "", $2); print $2 }'
}


# get_center_freq returns the center frequency of a channel with a 160 MHz
# width.
#
# @param control_freq the control frequency for the channel being used
# @return the center freq corresponding to the channel, or an empty string
#     if the frequency is not within one of the 160 MHz channels
get_center_freq ()
{
  local control_freq="${1}"
  if [ "${control_freq}" -gt 5179 ] && [ "${control_freq}" -lt 5321 ]; then
    echo "5250"
  elif [ "${control_freq}" -gt 5499 ] && [ "${control_freq}" -lt 5641 ]; then
    echo "5570"
  fi
}


# get_phy_info gets the WiFi interface type and wiphy identifier for |device|.
#
# @param device, the device we want information about
# @return "<type> <wiphy_number>", or an empty string if |device| is not WiFi.
get_phy_info ()
{
  local device="${1}"
  local info

  # We run it directly at first so we can return an error when it's not a WiFi
  # interface.  Otherwise we mishandle wired devices.
  if ! info=$(iw dev "${device}" info 2>/dev/null); then
    return 1
  fi

  echo "${info}" | awk '/^\ttype/ { print $2 }; /^\twiphy/ { print $2 };'
}


# get_devices_for_phy returns all the device names associated with this phy.
#
# @param phy_number, e.g., "3" or "phy3" for which to perform the listing.
# @return "<device0> <device1>...", or an empty string if no devices match.
get_devices_for_phy ()
{
  local phy_number="${1}"
  iw dev 2>/dev/null |
      awk -v search_phy="${phy_number}" \
          'BEGIN { sub(/^phy/, "", search_phy) };
           /^phy#/ { sub(/phy#/, ""); phynum=$1 };
           /^\tInterface/ { if (phynum == search_phy) print $2 }'
}


# get_monitor_phy_list returns a list of WiFi phys that are capable of monitor
# mode on |frequency|.
#
# @param frequency, channel this phy must be able to connect to
# @return "<phy#0> <phy#1> ...", or an empty string if no monitor phys found.
get_monitor_phy_list ()
{
  local frequency="${1}"
  iw phy 2>/dev/null |
      awk -v search_frequency="${frequency}" \
          '/^Wiphy/ { phy=$2; has_frequency=0 };
           /\* [0-9]+ MHz/ { if ($2 == search_frequency) has_frequency=1 };
           /^\t\t \* monitor/ { if (has_frequency) print phy }'
}


# get_link_info gets the WiFi interface link information -- SSID and frequency.
#
# @param device, the device we want information about
# @return "<BSSID> <frequency>" if connected, otherwise an empty string.
get_link_info ()
{
  local device="${1}"
  iw dev "${device}" link 2>/dev/null |
      awk '/^Connected to/ { print $3 }; /^\tfreq:/ { print $2 };'
}


# get_ht_info gets HT information for a |bssid| on a given |frequency|.
# We depend on the scan cache to get this information since this function
# is only called for a connected AP.
#
# @param device, the device on which to perform the scan
# @param bssid, the identifier for the AP we want information about
# @param frequency, the frequency on which we expect to find this information
# @return "<above|below>" if this is an HT40 network, or an empty string.
get_ht_info ()
{
  local device="${1}"
  local bssid="${2}"
  local frequency="${3}"
  iw dev "${device}" scan dump 2>/dev/null |
      awk -v search_bssid="${bssid}" -v search_frequency="${frequency}" \
           '/^BSS/ { gsub(/\(.*/, ""); bssid=$2 };
           /^\tfreq:/ { frequency=$2 };
           /\* secondary channel offset: (above|below)/ {
               if (bssid == search_bssid && frequency == search_frequency)
                   print $5
           }'
}


# get_width returns the channel width for a |bssid| on a given |frequency|.
# We use the command iw dev info because this is only called for a
# connected AP, and the info command will give information about the channel to
# which the device is connected.
#
# @param device, the device on which to perform the scan
# @return "<20|40|80|160>", or empty string if the device is not connected
get_width ()
{
  local device="${1}"
  iw dev "${device}" info 2>/dev/null |
      awk '/type/ { type=$2 };
          /channel/ {
            if (type == "managed")
              print $6
          }'
}


# create_monitor creates a monitor device on |phy|.
#
# @param phy, the phy to create the monitor device on.
# @return "<device>", the name of the created device if successful, or an
#     empty string on failure
create_monitor ()
{
  local phy="${1}"

  # There are no likely collisions here since the caller has already searched
  # for monitor devices over all phys.
  local device="${phy}_mon"
  if ! iw phy "${phy}" interface add "${device}" type monitor ; then
    return
  fi
  if ! ip link set "${device}" up ; then
    iw dev "${device}" del
    return
  fi
  echo "${device}"
}


# configure_monitor configures a monitor |device| to listen to |frequency|
# and uses an HT location of |ht_location|, or a VHT width of |vht_width|.
#
# @param device, the monitor device to be configured
# @param frequency, the frequency to listen to
# @param ht_location, "above", "below" or an empty string, indicating that
#     HT40 should not be used.
# @param vht_width, "80" or "160" indicating the size of the VHT band, or an
#     empty string, if we are not using VHT.
# @status_code 0 if successful, 1 or the return code for iw.
configure_monitor ()
{
  local device="${1}"
  local frequency="${2}"
  local ht_location="${3}"
  local vht_width="${4}"

  if [ "${vht_width}" = "80" ] || [ "${vht_width}" = "80MHz" ]; then
    iw dev "${device}" set freq "${frequency}" 80MHz
  elif [ "${vht_width}" = "160" ]; then
    local center_freq="$(get_center_freq "${frequency}")"
    if [ -z "${center_freq}" ]; then
      error "frequency \"${frequency}\" not part of a valid 160 MHz channel"
      return 1
    fi
    iw dev "${device}" set freq "${frequency}" 160 "${center_freq}"
  elif [ -z "${ht_location}" ]; then
    iw dev "${device}" set freq "${frequency}"
  elif [ "${ht_location}" = "above" ]; then
    iw dev "${device}" set freq "${frequency}" HT40+
  elif [ "${ht_location}" = "below" ]; then
    iw dev "${device}" set freq "${frequency}" HT40-
  else
    error "ht_location should be \"above\" or \"below\", not \"${ht_location}\""
    return 1
  fi
}


# get_monitor_device returns a device that is set up to monitor |frequency|,
# preferably one that is not connected to |wiphy|.
#
# @param frequency, the frequency on which we should monitor
# @param ht_location, the location of the additional 20MHz of bandwidth for
#     HT40, relative to |frequency|.  Can be empty to signify "not HT40".
# @param vht_width, the width of the channel if we are using VHT, or nothing.
# @param wiphy, the phy we would rather NOT use for this capture.
# @return "<device>", the discovered or created device, or an empty string
#     indicating failure.
get_monitor_device ()
{
  local frequency="${1}"
  local ht_location="${2}"
  local vht_width="${3}"
  local wiphy="${4}"
  local connected_monitor_device
  local connected_monitor_phy

  # See if there is a monitor device already around.
  local device
  for device in $(get_device_list); do
    local phy_info="$(get_phy_info "$device")"
    local mode="$(get_array_element 1 $phy_info)"
    if [ "${mode}" != "monitor" ] ; then
      continue
    fi
    local phy="$(get_array_element 2 $phy_info)"
    if [ "${phy}" = "${wiphy}" ] ; then
      # Save this one for later, if we don't find anything better.
      connected_monitor_device="${device}"
      continue
    fi
    # If we fail to configure this device, move on to the next device.  The
    # configuration could fail, for example, if the phy is in use.
    if ! configure_monitor \
        "${device}" "${frequency}" "${ht_location}" "${vht_width}"; then
      continue
    fi
    echo $device
    return
  done

  # Find a monitor-capable phy and try to create a device on it.
  local phy
  for phy in $(get_monitor_phy_list "${frequency}"); do
    if [ "${phy}" = "phy${wiphy}" ] ; then
      # Try this phy as a last resort.
      connected_monitor_phy=$phy
      continue
    fi

    # Shutdown any un-connected interfaces on this phy.
    local check_device
    for check_device in $(get_devices_for_phy "${phy}") ; do
      local mode="$(get_array_element 1 $(get_phy_info "$check_device"))"
      if [ "${mode}" = "monitor" ] ; then
        # We have already tried to use this monitor device and failed in
        # the first loop.  Skip this phy.
        continue 2
      fi
    done

    local unused_device
    for unused_device in $(get_devices_for_phy "${phy}") ; do
      local link_count="$(get_array_size $(get_link_info "$unused_device"))"
      if [ ${link_count} -eq 0 ] ; then
        error "Shutting down interface ${unused_device} so we can perform"
        error "monitoring.  You may need to disable, then re-enable WiFi to"
        error "use this interface again normally again."
        ip link set "${unused_device}" down
      else
        error "Warning: Interface ${unused_device} is in-use for an active"
        error "connection.  This may affect the quality of the packet capture."
      fi
    done

    device=$(create_monitor "${phy}")
    if [ -z "${device}" ] ; then
      continue
    fi

    if ! configure_monitor \
        "${device}" "${frequency}" "${ht_location}" "${vht_width}"; then
      iw dev "${device}" del
      continue
    fi

    echo $device
    return
  done

  # We were unable to find or create a monitor device on a different phy than
  # the one we are connected through.  Let's try using a monitor on the
  # the connected phy.
  if [ -n "$connected_monitor_device" ] ; then
    device="${connected_monitor_device}"
    if ! configure_monitor \
        "${device}" "${frequency}" "${ht_location}" "${vht_width}"; then
      return 1
    fi
  elif [ -n "${connected_monitor_phy}" ] ; then
    device=$(create_monitor "${connected_monitor_phy}")
    if [ -z "${device}" ] ; then
      return 1
    fi

    if ! configure_monitor \
        "${device}" "${frequency}" "${ht_location}" "${vht_width}"; then
      iw dev "${device}" del
      return 1
    fi
  else
    # The connected phy cannot be used for a monitor either.  We have failed.
    error "Could not find a device to monitor ${frequency} MHz.  It is likely"
    error "that none of your wireless devices are capable of monitor-mode."
    return 1
  fi
  echo "${device}"
}

# get_monitor_on_phy attempts to find, or create, a monitor device on |phy|
# Does not change the channel or other parameters of |phy|.
#
# @param phy, the phy on which we want to monitor
# @return "<device>" a monitor device on |phy|, or an empty string indicating
#     failure
get_monitor_on_phy()
{
  local target_phy="${1}"

  # See if there is a monitor device already around.
  local device
  for device in $(get_device_list); do
    local phy_info="$(get_phy_info "$device")"
    local mode="$(get_array_element 1 $phy_info)"
    if [ "${mode}" != "monitor" ] ; then
      continue
    fi
    local phy="$(get_array_element 2 $phy_info)"
    if [ "${phy}" = "${target_phy}" ] ; then
      echo "$device"
      return
    fi
  done

  # No existing monitor interface for the device. Create one.
  create_monitor "phy${target_phy}"
}

# get_monitor_for_link does a "best effort" capture on the specified device.
#
# If |device| is specified, we configure it with the same parameters as
# |monitored_device|. Otherwise, we attempt to find a suitable capture
# device, as follows...
#
# If |monitored_device| is a connected managed-mode WiFi device, the best case
# scenario is to find an unconnected monitor-capable wireless device that
# can perform a capture on the same channel.  Failing this, if the monitored
# device can enter monitor mode, this would be the second best choice.  Failing
# this (or if this is an un-connected WiFi device or is not in managed mode
# or not WiFi at all) we return an empty string, signifying failure.
#
# @param monitored_device, the device we are asking to monitor
# @param device, the device we want to monitor with, or an empty string
#     to have this function choose one.
# @return "<device>" a monitor device that can be used to capture this link,
#     or an empty string indicating failure.
get_monitor_for_link ()
{
  local monitored_device="${1}"
  local device="${2}"
  local phy_info="$(get_phy_info "$monitored_device")"
  local mode="$(get_array_element 1 $phy_info)"
  if [ "${mode}" != "managed" ] ; then
    error "Cannot monitor ${monitored_device}: it is not an 802.11 device."
    return
  fi

  local link_info="$(get_link_info "$monitored_device")"
  if [ $(get_array_size $link_info) -eq 0 ] ; then
    error "Cannot monitor ${monitored_device}: it is not currently connected."
    return
  fi

  local bssid="$(get_array_element 1 $link_info)"
  local frequency="$(get_array_element 2 $link_info)"
  local width="$(get_width "${monitored_device}")"
  local ht_info
  if [ "${width}" = "40" ]; then
    ht_info="$(get_ht_info "${monitored_device}" "${bssid}" "${frequency}")"
  fi
  if [ -z "${device}" ] ; then
    local phy="$(get_array_element 2 $phy_info)"
    device=$(
      get_monitor_device "${frequency}" "${ht_info}" "${width}" "${phy}" ||
      get_monitor_on_phy "${phy}")
  elif ! configure_monitor "${device}" "${frequency}" "${ht_info}" "${width}"
  then
    error "Cannot monitor ${monitored_device}: ${device} did not configure."
    return
  fi

  if [ -z "${device}" ] ; then
    # Couldn't find or create a monitor-mode device.
    return
  fi

  echo "${device}"
  return
}


# start_capture starts a packet capture on |device|.
#
# @param device, the device to capture form
# @param output_file, file to write the output packet capture to
# @status_code the return value from the capture process.
start_capture ()
{
  local device="${1}"
  local output_file="${2}"
  local max_size="${3}"
  local status_pipe="${4}"
  echo "Capturing from ${device}.  Press Ctrl-C to stop."
  ip link set "${device}" up
  exec /usr/libexec/debugd/helpers/capture_packets \
    "${device}" "${output_file}" "${max_size}" "${status_pipe}"
}


# usage displays a help message explaining the available options.
usage ()
{
  echo "Usage: $0 [ --device <device> ] [ --frequency <frequency> ] "
  echo "        [ --max-size <max size in MiB> ] "
  echo "        [ --ht-location <above|below> ] "
  echo "        [ --vht-width <80|160> ] "
  echo "        [ --monitor-connection-on <monitored_device> ] "
  echo "        [ --help ]"
  echo "        --output-file <output_file - do not use except internal calls>"
  echo
  echo "Where <device> can be one of:"
  local device
  for device in $(get_device_list); do
    local phy_info="$(get_phy_info "$device")"
    echo -n "    $device: "
    if [ "$(get_array_size $phy_info)" -eq 0 ] ; then
      echo "Ethernet-like device"
      continue
    else
      local mode="$(get_array_element 1 $phy_info)"
      local phy="$(get_array_element 2 $phy_info)"
      echo "Wireless device in ${mode} mode using Wiphy${phy}"
    fi
  done
}


# Prints an error |message|.
#
# @param message to send before exiting
# @param usage, if non-empty, lists command-line usage.
error ()
{
  local message="${1}"
  echo "${message}" 1>&2
}


# fatal_error sends a |message| and exits.
#
# @param message to send before exiting
fatal_error ()
{
  local message="${1}"
  error "${message}"
  exit 1
}


# command_line_error sends a |message|, prints helpful hints about command
# line usage, then exits.
#
# @param message to send before exiting
command_line_error ()
{
  local message="${1}"
  echo "${message}"
  echo
  usage
  exit 1
}


main ()
{
  local device
  local frequency
  local max_size="0"
  local ht_location
  local vht_chan_width
  local center_freq
  local monitor_connection_on
  local output_file
  local status_pipe
  while [ $# -gt 0 ] ; do
    param="${1}"
    shift
    case "${param}" in
      --device)
        device="${1}"
        shift
        ;;
      --frequency)
        frequency="${1}"
        shift
        ;;
      --max-size)
        max_size="${1}"
        shift
        ;;
      --ht-location)
        ht_location="${1}"
        if [ "${ht_location}" != "above" -a "${ht_location}" != "below" ] ; then
          command_line_error "HT location must be either \"above\" or \"below\""
        fi
        shift
        ;;
      --vht-width)
        vht_width="${1}"
        if [ "${vht_width}" != "80" -a "${vht_width}" != "160" ]; then
          command_line_error "VHT width must be either 80 or 160"
        fi
        shift
        ;;
      --monitor-connection-on)
        monitor_connection_on="${1}"
        shift
        ;;
      --output-file)
        output_file="${1}"
        shift
        ;;
      --status-pipe)
        status_pipe="${1}"
        shift
        ;;
      --help)
        usage
        return 0
        ;;
      *)
        command_line_error "Unknown option ${param}"
        ;;
    esac
  done

  if [ -z "${output_file}" ] ; then
    command_line_error "The --output-file argument is mandatory"
  fi

  if [ -n "${ht_location}" ] && [ -n "${vht_width}" ]; then
    command_line_error "Cannot specify both ht-location and vht-width"
  fi

  # WP2 does not permit us to set parameters like power-save and
  # beacon filtering via the monitor device. So stash away the
  # user specified device here.
  local user_device="${device}"

  if [ -n "${monitor_connection_on}" ] ; then
    user_device="${monitor_connection_on}"
    device=$(get_monitor_for_link "${monitor_connection_on}" "${device}")
    if [ -z "${device}" ] ; then
      fatal_error "Cannot create a device to monitor ${monitor_connection_on}"
    fi
  elif [ -z "${device}" ] ; then
    if [ -n "${frequency}" ] ; then
      device=$(get_monitor_device \
          "${frequency}" "${ht_location}" "${vht_width}")
      if [ -z "${device}" ] ; then
        fatal_error "No devices found to capture channel ${frequency}"
      fi
    else
      command_line_error "I don't know what you want me to capture!"
    fi
  elif [ -n "${frequency}" ] ; then
    if ! configure_monitor \
        "${device}" "${frequency}" "${ht_location}" "${vht_width}"; then
      fatal_error "Unable to set frequency on device ${device}."
    fi
  elif [ -n "${ht_location}" ] ; then
    command_line_error "Channel was not specified but ht_location was."
  fi

  if get_phy_info "${user_device}" > /dev/null 2>&1; then
    iw dev "${user_device}" set power_save off || true
    for bf_params in \
        /sys/kernel/debug/ieee80211/*/netdev:"${user_device}"/iwlmvm/bf_params;
    do
      [ -e $bf_params ] || break  # unmatched glob expands to itself
      echo "bf_enable_beacon_filter=0" > "${bf_params}"
    done
  fi

  start_capture "${device}" "${output_file}" "${max_size}" "${status_pipe}"
}

set -e  # exit on failures

main "$@"
