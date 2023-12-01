#!/bin/bash -e

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
VERSION="MODEM-TIME-SAMPLES-RESET-GENERIC_V1.0.5"
readonly PROG="$(basename "$0")"
readonly PID="$$"
echo $PID
readonly LOG_TAG='modem-time-samples'
readonly LOCK_FILE=/run/lock/modem-time-samples.lock
readonly RESULT_FILE=/tmp/modem-time-samples.log

# Starting from Coral Proto2, EN_PP3300_DX_LTE is controlled via this GPIO
EN_GPIO=311
readonly EN_GPIO_ON=1
readonly EN_GPIO_OFF=0
chromeos_cfg_file="/etc/lsb-release"

readonly WWAN_IF='wwan0'
readonly DELAY_AFTER_POWER_OFF_SECONDS=5
readonly TIMEOUT_SECONDS=60

# Adjust these parameters accordingly
MODEM_USB_VID_PID='2CB7:0007'
readonly APN='internet'
readonly DEFAULT_NUM_ITERATIONS=1

readonly COLOR_HIGHLIGHT='\033[1;32m'
readonly COLOR_RESET='\033[0m'

log_info() {
  logger -t "${LOG_TAG}" --id="$$" -p info "$*"
  echo "   INFO: $*" > /dev/stderr
}

log_warning() {
  logger -t "${LOG_TAG}" --id="$$" -p warn "$*"
  echo "WARNING: $*" > /dev/stderr
}

log_error() {
  logger -t "${LOG_TAG}" --id="$$" -p err "$*"
  echo "  ERROR: $*" > /dev/stderr
}

die() {
  log_error "$@"
  exit 1
}

get_timestamp() {
  date '+%s.%N'
}

set_en_gpio() {
  local customer=""

  if [ ! -f "$chromeos_cfg_file" ]; then
    echo "$modemfwd_cfg_file is not exist"
    customer="other"
  else
    board_line=`cat /etc/lsb-release | grep CHROMEOS_RELEASE_BUILDER_PATH`
    echo "$board_line" > board_newline
    customer=$(cut -d = -f 2 board_newline|cut -d - -f 1)
    rm -rf  board_newline
  fi

  echo "$customer"

  if [ "$customer" == "nautilus" ];then
    echo "it's samsung platform, use EN_GPIO=432"
    EN_GPIO=432
  elif [ "$customer" == "coral" ];then
    echo "it's acer platform, use EN_GPIO=395"
    EN_GPIO=395
  elif [ "$customer" == "quanta" ];then
    echo "it's quanta platform, use EN_GPIO=395"
    EN_GPIO=395
  elif [ "$customer" == "sarien" ];then
    echo "it's dell platform, use EN_GPIO=311"
    EN_GPIO=311
  elif [ "$customer" == "drallion" ];then
    echo "it's drallion platform, use EN_GPIO=466"
    EN_GPIO=466
  elif [ "$customer" == "hatch" ];then
    echo "it's hatch platform, use EN_GPIO=218"
    EN_GPIO=218
  elif [ "$customer" == "dedede" ];then
    echo "it's dedede platform, use EN_GPIO=349"
    EN_GPIO=349
  elif [ "$customer" == "zork" ];then
    echo "it's zork platform, use EN_GPIO=345"
    EN_GPIO=345
  elif [ "$customer" == "brya" ];then
    echo "it's brya platform, use EN_GPIO=488"
    EN_GPIO=488
  elif [ "$customer" == "octopus" ];then
    echo "it's octopus platform, use EN_GPIO=337"
    # EN_GPIO=393
    # set_modem_power "${EN_GPIO_ON}"
    # EN_GPIO=499
    # set_modem_power "${EN_GPIO_ON}"
    EN_GPIO=337
  else
    echo "$customer customer not support"
    # customer="other"
    usage
    exit 0
  fi
}

last_timestamp="$(get_timestamp)"
last_modemstate=""
test_step=1
test_result="\033[1;5;31m                               [TEST RESULT]\033[0m\n"

print_elapsed_time() {
  local description="$1"
  local current_modem_state="$2"
  local current_state_time="$3"
  local current_timestamp="${current_state_time:-$(get_timestamp)}"
  if [ -z "${current_modem_state}" ]; then
    local elapsed_time=`echo "$current_timestamp - $last_timestamp"|bc`
    rt=$(printf "${COLOR_HIGHLIGHT}"'%-30s      ===> %30.30s (s): %0.3f\n'"${COLOR_RESET}" "${test_step}.${last_modemstate}" "${description}" "${elapsed_time}")
    printf "${rt}"
    test_result+=${rt}
    ((test_step++))
  fi
  last_timestamp="${current_state_time:-$current_timestamp}"
  last_modemstate="${description:-$current_modem_state}"
}

is_service_running() {
  local service="$1"
  status "${service}" | grep -q 'running'
}

restart_service() {
  local service="$1"
  shift
  if is_service_running "${service}"; then
    stop "${service}"
  fi
  start "${service}" "$@"
}

set_modem_power() {
  local new_value="$1"

  local gpio_node=/sys/class/gpio/gpio"${EN_GPIO}"
  if [ ! -e "${gpio_node}" ]; then
    echo "${EN_GPIO}" > /sys/class/gpio/export
    [ -e "${gpio_node}" ] || die "Failed to export GPIO ${EN_GPIO}"
  fi

  local value_file="${gpio_node}"/value
  local old_value="$(cat "${value_file}")"
  if [ "${old_value}" != "${new_value}" ]; then
    echo 'out' > "${gpio_node}"/direction
    echo "${new_value}" > "${value_file}"
  fi
  old_value="$(cat "${value_file}")"
  [ "${old_value}" = "${new_value}" ] || die "Failed to update GPIO ${EN_GPIO}"
}

wait_for_modem_usb_device() {
  local start_time="$(get_timestamp)"
  local elapsed_time=0

  while [ `echo "${elapsed_time} < ${TIMEOUT_SECONDS}"|bc` ]; do
    if lsusb -d "${MODEM_USB_VID_PID}" >/dev/null; then
      return 0
    fi
    sleep .1
    elapsed_time=`echo "$(get_timestamp) - $start_time"|bc`
  done
  return 1
}

wait_for_modem_object() {
  local start_time="$(get_timestamp)"
  local elapsed_time=0

  while [ `echo "${elapsed_time} < ${TIMEOUT_SECONDS}"|bc` ]; do
    local modem_object="$(mmcli -L | grep "ModemManager1")"
    if [ -n "${modem_object}" ]; then
      return 0
    fi
    sleep .1
    elapsed_time=`echo "$(get_timestamp) - $start_time"|bc`
  done
  return 1
}

get_modem_object() {
  mmcli -L | sed -nE "s|.*/org/freedesktop/ModemManager1/Modem/([0-9]+).*|\1|p"
}

filter_log() {
  local pid="$1"

  sed -n ':skip {n; /modem-time-samples\['"${pid}"'\]/!b skip}; :start {n; /\(ModemManager\[\|modem-time-samples\[\|kernel\)/p; b start}'
}

get_modem_usb_device() {
  if lsusb -d "2CB7:0007" >/dev/null; then
    MODEM_USB_VID_PID='2CB7:0007'
  elif  lsusb -d "2CB7:01a0" >/dev/null; then
    MODEM_USB_VID_PID='2CB7:01a0'
  else
    echo "can't find any modem"
  fi
}

setup() {
  get_modem_usb_device
  log_info 'Power off modem'
  set_modem_power "${EN_GPIO_OFF}"
  sleep "${DELAY_AFTER_POWER_OFF_SECONDS}"

#  log_info 'Restart shill with the WWAN interface ignored'
  log_info 'Stop Shill'
  stop shill
#  restart_service shill DENYLISTED_DEVICES="${WWAN_IF}"

  log_info 'Restart ModemManager with log level set to debug'
  restart_service modemmanager MM_LOGLEVEL=DEBUG
}

wait_for_3gpp_update() {
  while true;do
    local modem_id=$(mmcli -L | grep -oE '/org/freedesktop/ModemManager1/Modem/[0-9]+')
    echo "modem is $modem_id"
    read_3gpp_operator=$(mmcli -m "$modem_id" | sed -n '/operator\ id/p')
    read_3gpp_packet=$(mmcli -m "$modem_id" | sed -n '/packet\ service\ state/p')
    echo "3gpp operator id is ${read_3gpp_operator}"
    echo "3gpp packet service state is ${read_3gpp_packet}"
    if [ -n "${read_3gpp_operator}" ] || [ -n "${read_3gpp_packet}" ];then
      break;
    fi
    sleep .1
  done
}

wait_for_modem_state() {
  local modemstate=$1
  while true;do
    local modem_id=$(mmcli -L | grep -oE '/org/freedesktop/ModemManager1/Modem/[0-9]+')
    echo "modem is $modem_id"
    read_connect_state=$(mmcli -m "$modem_id"  | grep 'state:' | grep -v 'power')
    echo "modem state is ${read_connect_state}"
    if [[ "${read_connect_state}" =~ "${modemstate}" ]];then
           break;
    fi
    sleep .1
  done
}

run_iteration() {
  local iteration="$1"

  log_info "[Iteration ${iteration}] Power on modem"
  set_modem_power "${EN_GPIO_ON}"
  last_timestamp="$(get_timestamp)"
  last_modemstate="OFF"

  log_info "[Iteration ${iteration}] Wait for modem USB device to appear"
  wait_for_modem_usb_device || die 'Modem USB device not found'

  print_elapsed_time 'Modem USB enumeration'

  log_info "[Iteration ${iteration}] Wait for modem object to initialize"
  wait_for_modem_object || die 'Modem object not found'

  print_elapsed_time '' 'Modem disabled #1'

  local modem_object="$(get_modem_object)"
  [ -n "${modem_object}" ] || die 'Modem not found'

  log_info "[Iteration ${iteration}] Enable modem"
  mmcli --timeout="${TIMEOUT_SECONDS}" -m "${modem_object}" -e

  print_elapsed_time 'Modem enabled #1'

  wait_for_modem_state "registered"
  #print_elapsed_time 'Modem registered #1'

  log_info "[Iteration ${iteration}] Connect modem to network"
  mmcli --timeout="${TIMEOUT_SECONDS}" -m "${modem_object}" "--simple-connect=apn=${APN}"

  #print_elapsed_time 'Modem connected #1'

  #log_info "[Iteration ${iteration}] Disconnect modem to network"
  #mmcli --timeout="${TIMEOUT_SECONDS}" -m "${modem_object}" "--simple-disconnect=apn=${APN}"

  #wait_for_modem_state "registered"
  #print_elapsed_time 'Modem registered #1'

  log_info "[Iteration ${iteration}] Disable modem"
  mmcli --timeout="${TIMEOUT_SECONDS}" -m "${modem_object}" -d

  #print_elapsed_time 'Modem disabled #1'

  log_info "[Iteration ${iteration}] Set low power state"
  mmcli --timeout="${TIMEOUT_SECONDS}" -m "${modem_object}" --set-power-state-low

  #print_elapsed_time '' 'Modem suspend #1'

  log_info "[Iteration ${iteration}] Set normal power state"
  mmcli --timeout="${TIMEOUT_SECONDS}" -m "${modem_object}" --set-power-state-on

  #print_elapsed_time 'Modem RF enable'

  log_info "[Iteration ${iteration}] Enable modem"
  mmcli --timeout="${TIMEOUT_SECONDS}" -m "${modem_object}" -e

  #print_elapsed_time 'Modem enable #2'

  wait_for_modem_state "registered"
  wait_for_3gpp_update
  log_info "[Iteration ${iteration}] Connect modem to network"
  mmcli --timeout="${TIMEOUT_SECONDS}" -m "${modem_object}" "--simple-connect=apn=${APN}"

  #print_elapsed_time '' 'Modem connected #2'

  log_info "[Iteration ${iteration}] Disable modem"
  mmcli --timeout="${TIMEOUT_SECONDS}" -m "${modem_object}" -d

  #print_elapsed_time 'Modem disabled #2'

  log_info "[Iteration ${iteration}] Power off modem"
  set_modem_power "${EN_GPIO_OFF}"
  sleep "${DELAY_AFTER_POWER_OFF_SECONDS}"
}

collect_result() {
  cat /var/log/messages /var/log/net.log | sort | uniq | filter_log "${PID}" > "${RESULT_FILE}"
}

show_last_result() {
  cat /var/log/messages /var/log/net.log | sort | uniq | filter_log '.*'
}

cleanup() {
  log_info 'Power off modem'
  set_modem_power "${EN_GPIO_ON}"

  log_info 'Restart shill with default settings'
  restart_service shill

  log_info 'Restart ModemManager with default settings'
  restart_service modemmanager
}

analysis_modem_state_from_log() {
  echo "net.log analysising"
  local modem_enabled=''
  local modem_registered=''
  local modem_connected_1st=''
  local modem_disabling=''
  local modem_3gpp_unknown=''
  local modem_disabled=''
  local modem_low_power=''
  local modem_connected_2nd=''

  if [ -f ${RESULT_FILE} ]; then
    while read line; do
      if [ -z "${modem_enabled}" ]; then
        if [[ "${line}" =~ "state changed (enabling -> enabled)" ]]; then
          modem_enabled=`date -d "${line%% *}" +%s.%6N`
          #echo ${modem_enabled}
          echo ${line}
          print_elapsed_time '' 'Modem enabled' "${modem_enabled}"
          continue
        fi
      fi
      if [ -z "${modem_registered}" ]; then
        if [[ "${line}" =~ "state changed (enabled -> registered)" ]]; then
          modem_registered=`date -d "${line%% *}" +%s.%6N`
          #echo ${modem_registered}
          echo ${line}
          print_elapsed_time 'Modem registered' '' "${modem_registered}"
          continue
        fi
      fi
      if [ -z "${modem_connected_1st}" ]; then
        if [[ "${line}" =~ "state changed (connecting -> connected)" ]]; then
          modem_connected_1st=`date -d "${line%% *}" +%s.%6N`
          #echo $modem_connected_1st
          echo ${line}
          print_elapsed_time 'Modem connected' '' "${modem_connected_1st}"
          continue
        fi
      fi
      if [ -z "${modem_disabling}" ]; then
        if [[ "${line}" =~ "state changed (connected -> disabling)" ]]; then
          modem_disabling=`date -d "${line%% *}" +%s.%6N`
          #echo $modem_disabling
          echo ${line}
          print_elapsed_time '' 'Modem connected' "${modem_disabling}"
          continue
        fi
      fi
      if [ -z "${modem_3gpp_unknown}" ]; then
        if [[ "${line}" =~ "state changed (home -> unknown)" ]]; then
          modem_3gpp_unknown=`date -d "${line%% *}" +%s.%6N`
          #echo $modem_3gpp_unknown
          echo ${line}
          print_elapsed_time 'Modem registered' '' "${modem_3gpp_unknown}"
          continue
        fi
      fi
      if [ -z "${modem_disabled}" ]; then
        if [[ "${line}" =~ "state changed (disabling -> disabled)" ]]; then
          modem_disabled=`date -d "${line%% *}" +%s.%6N`
          #echo $modem_disabled
          echo ${line}
          print_elapsed_time 'Modem disabled' '' "${modem_disabled}"
          continue
        fi
      fi
      if [ -z "${modem_low_power}" ]; then
        if [[ "${line}" =~ "low-power" ]] || [[ "${line}" =~ "power state updated: low" ]]; then
          modem_low_power=`date -d "${line%% *}" +%s.%6N`
          #echo $modem_low_power
          echo ${line}
          print_elapsed_time '' 'Modem suspend' "${modem_low_power}"
          continue
        fi
      fi
      if [ -z "${modem_connected_2nd}" ]; then
        if [[ "${line}" =~ "state changed (connecting -> connected)" ]]; then
          modem_connected_2nd=`date -d "${line%% *}" +%s.%6N`
          #echo $modem_connected_2nd
          echo ${line}
          print_elapsed_time 'Modem connected' '' "${modem_connected_2nd}"
          break
        fi
      fi
    done < ${RESULT_FILE}
  fi
}

print_result() {
  echo -e "${test_result}"
}

usage() {
  cat <<EOT

Usage: ${PROG} [options]

Options:
    -l    show last result and exit
    -n    number of iterations
    -h    help

EOT
}

main() {
  echo -e "########## $VERSION ###########"
  local show_last_result=0
  local show_help=0
  local num_iterations="${DEFAULT_NUM_ITERATIONS}"
  local opt

  while getopts 'hln:' opt; do
    case "${opt}" in
      h)
        show_help=1
        ;;
      l)
        show_last_result=1
        ;;
      n)
        num_iterations="${OPTARG}"
        [[ "${num_iterations}" =~ ^[0-9]+$ ]] || die "Invalid argument: ${OPTARG}"
        ;;
      *)
        die "Unknown option: ${opt}"
        ;;
    esac
  done

  if [ ${show_help} -eq 1 ]; then
    usage
    exit 0
  fi

  if [ ${show_last_result} -eq 1 ]; then
    show_last_result
    exit 0
  fi
  set_en_gpio
  setup
  local iteration
  for iteration in $(seq 1 "${num_iterations}"); do
    run_iteration "${iteration}"
  done
  collect_result
  cleanup
  analysis_modem_state_from_log
  print_result
}

main "$@"
