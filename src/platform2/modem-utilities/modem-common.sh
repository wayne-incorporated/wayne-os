# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Common utilities for interacting with modems.

#
# For modems managed by org.freedesktop.ModemManager1
#
MM1=org.freedesktop.ModemManager1
MM1_OBJECT=/org/freedesktop/ModemManager1
MM1_IMANAGER=org.freedesktop.ModemManager1

mm1_modem_properties() {
  gdbus_introspect "${MM1}" "${MM1_OBJECT}"
}

mm1_modems() {
  mmcli -L 2>/dev/null \
    | awk '/\/org\/freedesktop\/ModemManager1\/Modem\// { print $1 }'
}

#
# Common stuff
#
MASKED_PROPERTIES="DeviceIdentifier|EquipmentIdentifier|OwnNumbers|\
ESN|MEID|IMEI|IMSI|SimIdentifier|MDN|MIN|payment_url_postdata|Eid|\
Iccid|Number|SMSC|Text|Data"
MASKED_SUBPROPERTIES="user|password|${MASKED_PROPERTIES}"
MASKED_MMCLI_FIELDS="device id|equipment id|own|${MASKED_PROPERTIES}"

mask_esim_properties() {
  sed -E "s/\<(${MASKED_PROPERTIES}): (.+)/\1: *** MASKED ***/i"
}

mask_mmcli_fields() {
  sed -E "s/(${MASKED_MMCLI_FIELDS}): (.+)/\1: *** MASKED ***/i"
}

mask_modem_properties() {
  sed -E "s/\<(${MASKED_PROPERTIES}) = (.+)/\1 = *** MASKED ***/i" |
  sed -E "s/('(${MASKED_SUBPROPERTIES})'): (<[^>]+>)/\1: *** MASKED ***/gi" |
  sed -E "s/readonly //g"
}

mask_profiles() {
  sed -E "s/(\/profile\/)[0-9]+\/[0-9]+/\1[ ***MASKED*** ]/"
}

all_modem_status() {
  mm1_modem_properties
}

default_modem() {
  mm1_modems | head -1
}

# Sets the log level of the specified modem manager.
set_modem_manager_logging() {
  local level="$1"

  if [ "${level}" = "error" ]; then
    level=err
  fi
  dbus_call "${MM1}" "${MM1_OBJECT}" "${MM1_IMANAGER}.SetLogging" \
    "string:${level}"
}

#
# For interactions with modemfwd.
#
MODEMFWD=org.chromium.Modemfwd
MODEMFWD_OBJECT=/org/chromium/Modemfwd
MODEMFWD_IFACE=org.chromium.Modemfwd

force_flash() {
  local device="$1"
  local carrier_uuid="$2"
  [ -z "${device}" ] && error_exit "No device_id provided."
  [ -z "${carrier_uuid}" ] && carrier_uuid="generic"

  dbus_call_with_timeout "${MODEMFWD}" 120000 "${MODEMFWD_OBJECT}" \
    "${MODEMFWD_IFACE}.ForceFlash" "string:${device}" \
    dict:string:string:"carrier_uuid","${carrier_uuid}"
}

#
# For eSIM interactions.
#
HERMES=org.chromium.Hermes
HERMES_MANAGER_OBJECT=/org/chromium/Hermes/Manager
HERMES_MANAGER_IFACE=org.chromium.Hermes.Manager

HERMES_EUICC_IFACE=org.chromium.Hermes.Euicc
HERMES_PROFILE_IFACE=org.chromium.Hermes.Profile

# Timeout for Hermes esim operations (in milliseconds)
HERMES_DBUS_TIMEOUT=120000

esim() {
  local command="$1"
  shift

  local euicc
  if [ "$1" = "-euicc" ]; then
    euicc="/org/chromium/Hermes/euicc/$2"
    shift 2
  else
    euicc=$(default_euicc)
  fi
  [ -z "${euicc}" ] && error_exit "No euicc found."

  if crossystem 'cros_debug?0'; then
    if [ "${command}" != "status" ] && [ "${command}" != "refresh_profiles" ] ; then
      error_exit "${command} not allowed outside of developer mode"
    fi
  fi

  case "${command}" in
    use_test_certs)
      poll_for_dbus_service "${HERMES}"
      esim_use_test_certs "${euicc}" "$@"
      ;;
    set_test_mode)
      poll_for_dbus_service "${HERMES}"
      esim_set_test_mode "${euicc}" "$@"
      ;;
    refresh_profiles)
      poll_for_dbus_service "${HERMES}"
      esim_refresh_profiles "${euicc}" "$@"
      ;;
    request_pending_profiles)
      poll_for_dbus_service "${HERMES}"
      esim_request_pending_profiles "${euicc}" "$@"
      ;;
    status)
      poll_for_dbus_service "${HERMES}"
      esim_status "$@"
      ;;
    status_feedback)
      poll_for_dbus_service "${HERMES}"
      esim_status_feedback "$@"
      ;;
    install)
      poll_for_dbus_service "${HERMES}"
      esim_install "${euicc}" "$@"
      ;;
    install_pending_profile)
      poll_for_dbus_service "${HERMES}"
      esim_install_pending_profile "${euicc}" "$@"
      ;;
    uninstall)
        poll_for_dbus_service "${HERMES}"
        esim_uninstall "${euicc}" "$@"
      ;;
    enable)
      poll_for_dbus_service "${HERMES}"
      esim_enable "${euicc}" "$@"
      ;;
    disable)
      poll_for_dbus_service "${HERMES}"
      esim_disable "${euicc}" "$@"
      ;;
    *)
      error_exit "Expected one of "\
        "{use_test_certs|set_test_mode|"\
        "refresh_profiles|request_pending_profiles|"\
        "status|status_feedback|install|install_pending_profile|uninstall|"\
        "enable|disable}"
      ;;
  esac
}

all_euiccs() {
  dbus_property "${HERMES}" "${HERMES_MANAGER_OBJECT}" \
    "${HERMES_MANAGER_IFACE}" AvailableEuiccs |
    sed 's|^/[[:digit:]]* ||'
}

default_euicc() {
  all_euiccs | head -1
}

esim_profile_from_iccid() {
  local euicc="$1"

  local iccid="$2"
  [ -z "${iccid}" ] && error_exit "No iccid provided."

  local profile_type
  for profile_type in "InstalledProfiles" "PendingProfiles"; do
    local profiles
    profiles="$(dbus_property "${HERMES}" "${euicc}" \
                              "${HERMES_EUICC_IFACE}" "${profile_type}" |
                              sed 's|^/[[:digit:]]* ||' | tr '\n' ' ')"

    if ! echo "${profiles}" | grep -q -E \
      '^(/org/chromium/Hermes/profile/[0-9]+/[0-9]+ )*$'; then

      error_exit "Invalid profile objects received from hermes"

    fi

    local profile
    for profile in ${profiles}; do
      local current
      current="$(dbus_property "${HERMES}" "${profile}" \
                               "${HERMES_PROFILE_IFACE}" Iccid)"
      if [ "${current}" = "${iccid}" ]; then
        echo "${profile}"
        return
      fi
    done
  done
  error_exit "No matching Profile found for iccid ${iccid}."
}

esim_use_test_certs() {
  local euicc="$1"
  dbus_call "${HERMES}" "${euicc}" \
            "${HERMES_EUICC_IFACE}.UseTestCerts" \
            boolean:"$2"
}

esim_set_test_mode() {
  local euicc="$1"
  dbus_call "${HERMES}" "${euicc}" \
            "${HERMES_EUICC_IFACE}.SetTestMode" \
            boolean:"$2"
}

esim_status() {
  local euicc
  for euicc in $(all_euiccs); do
    echo "${euicc}"
    dbus_properties "${HERMES}" "${euicc}" "${HERMES_EUICC_IFACE}" |
      stripindexes

    local profile_type
    for profile_type in "InstalledProfiles" "PendingProfiles"; do
      echo "${profile_type}:" | indent 1
      local profile
      for profile in $(dbus_property "${HERMES}" "${euicc}" \
        "${HERMES_EUICC_IFACE}" "${profile_type}" |
                         sed 's|^/[[:digit:]]* ||'); do
        echo "${profile}" | indent 2
        dbus_properties "${HERMES}" "${profile}" "${HERMES_PROFILE_IFACE}" |
          stripindexes | indent 3
        echo
      done
    done
    echo ""
  done
}

esim_status_feedback() {
  esim_status | mask_esim_properties | mask_profiles
}

esim_refresh_profiles() {
  local euicc="$1"
  local should_not_switch_slot="$2"
  [ -z "${should_not_switch_slot}" ] && should_not_switch_slot="false"

  dbus_call "${HERMES}" "${euicc}" \
           "${HERMES_EUICC_IFACE}.RefreshInstalledProfiles" \
           boolean:"${should_not_switch_slot}"
}

esim_install() {
  local euicc="$1"
  local activation_code="$2"
  local confirmation_code="$3"
  [ -z "${activation_code}" ] && error_exit "No activation_code provided."

  dbus_call_with_timeout "${HERMES}" "${HERMES_DBUS_TIMEOUT}" "${euicc}" \
            "${HERMES_EUICC_IFACE}.InstallProfileFromActivationCode" \
            string:"${activation_code}" string:"${confirmation_code}"
}

esim_install_pending_profile() {
  local euicc="$1"
  local profile
  profile=$(esim_profile_from_iccid "$@")
  dbus_call_with_timeout "${HERMES}" "${HERMES_DBUS_TIMEOUT}" "${euicc}" \
            "${HERMES_EUICC_IFACE}.InstallPendingProfile" \
            objpath:"${profile}" string:"${confirmation_code}"
}

esim_uninstall() {
  local euicc="$1"
  local profile
  profile=$(esim_profile_from_iccid "$@")
  [ -z "${profile}" ] && exit 1
  dbus_call_with_timeout "${HERMES}" "${HERMES_DBUS_TIMEOUT}" "${euicc}" \
            "${HERMES_EUICC_IFACE}.UninstallProfile" objpath:"${profile}"
}

esim_request_pending_profiles() {
  local euicc="$1"
  local smds="$2"

  dbus_call_with_timeout "${HERMES}" "${HERMES_DBUS_TIMEOUT}" "${euicc}" \
            "${HERMES_EUICC_IFACE}.RequestPendingProfiles" string:"${smds}"
}

esim_enable() {
  local profile
  profile=$(esim_profile_from_iccid "$@")
  [ -z "${profile}" ] && exit 1
  dbus_call_with_timeout "${HERMES}" "${HERMES_DBUS_TIMEOUT}" \
                         "${profile}" "${HERMES_PROFILE_IFACE}.Enable"
}

esim_disable() {
  local profile
  profile=$(esim_profile_from_iccid "$@")
  [ -z "${profile}" ] && exit 1
  dbus_call_with_timeout "${HERMES}" "${HERMES_DBUS_TIMEOUT}" "${profile}" \
            "${HERMES_PROFILE_IFACE}.Disable"
}
