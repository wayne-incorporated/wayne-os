#!/bin/bash
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e

setup_nvidia_device_files() {
    local module_name="$1"

    case "${module_name}" in
        nvidia)
            echo "Setting up device node for module name = ${module_name}.ko"
            if ! nvidia-modprobe -c 0; then
                echo "ERROR: Failed to create device file minor number 0" >&2
                exit 1
            fi
            if ! nvidia-modprobe -c 255; then
                echo "ERROR: Failed to create device file minor number 255" >&2
                exit 1
            fi
            ;;
        nvidia-uvm)
            echo "Setting up device node for module name = ${module_name}.ko"
            if ! nvidia-modprobe -u; then
                echo "ERROR: Failed to create device file for nvidia-uvm" >&2
                exit 1
            fi
            # Find out the major device number used by the nvidia-uvm driver
            D="$(grep nvidia-uvm /proc/devices | awk '{print $1}')"
            mknod -m 666 /dev/nvidia-uvm c "${D}" 0
            ;;
        nvidia-modeset)
            echo "Setting up device node for module name = ${module_name}.ko"
            if ! nvidia-modprobe -m; then
                echo "ERROR: Failed to create device file for nvidia-modeset" \
                    >&2
                exit 1
            fi
            ;;
        nvidia-drm)
            echo "No device node required for module name = ${module_name}.ko"
            ;;
        *)
            echo "ERROR: Unknown module name ${module_name}" >&2
            exit 1
            ;;
    esac
}

nvidia_drivers_post_process() {
    setup_nvidia_device_files "nvidia"
    setup_nvidia_device_files "nvidia-uvm"
    setup_nvidia_device_files "nvidia-modeset"
    setup_nvidia_device_files "nvidia-drm"
}

bind_drivers()
{
    device_path="$1"
    bind_driver="$2"
    unbind_driver="$3"

    if [[ -f "${device_path}/device" ]]; then
        read -r device < "${device_path}/device"
        read -r vendor < "${device_path}/vendor"
        dev_bdf="$(echo "${device_path}" | cut -f 6 -d '/')"
        drvr_path="/sys/bus/pci/drivers"

        if modprobe --ignore-install "${bind_driver}"; then
            if [[ -f "${device_path}/driver/unbind" ]]; then
                echo "${dev_bdf}" > "${device_path}/driver/unbind"
            fi

            if ! echo "${vendor} ${device}" > "${drvr_path}/${bind_driver}/new_id"; then
                echo "ERROR: Failed to set ${vendor} ${device} to ${bind_driver}" >&2
            fi

            if ! echo "${dev_bdf}" > "${drvr_path}/${bind_driver}/bind"; then
                echo "ERROR: Failed bind ${dev_bdf} to ${bind_driver}" >&2
            fi

            if ! echo "${vendor} ${device}" > "${drvr_path}/${bind_driver}/remove_id"; then
                echo "ERROR: Failed to remove id from ${bind_driver}" >&2
            fi
        fi

        # Post process.
        if [[ "${bind_driver}" == "nvidia" ]]; then
            nvidia_drivers_post_process
        fi
    fi
}

help_manual() {
    echo "Valid Arguments:"
    echo "-a: Auto mode (default). Mode determined by .dgpu-host file."
    echo "    Host mode if '/var/lib/.dgpu-host' file is present,"
    echo "    else passthrough mode."
    echo "-h: Host mode. NVIDIA dGPU bound to NVIDIA drivers on host OS."
    echo "-p: Passthrough mode. NVIDIA dGPU bound to VFIO drivers."
    echo "-m: Show help manual"
}

main()
{
    local arg_found=0
    local arg_auto=0
    # Drivers for each function (0:GPU. 1:Audio. 2:USB) of NVIDIA dGPU.
    drivers_nvidia=("nvidia" "snd_hda_intel" "xhci_hcd")
    drivers_vfio=("vfio-pci" "vfio-pci" "vfio-pci")
    drivers_bind=("${drivers_vfio[@]}")
    drivers_unbind=("${drivers_nvidia[@]}")

    while getopts ":mhpa" option; do
        if [[ "${arg_found}" -eq 1 ]]; then
            echo "More than 1 arguments detected. Invalid parameters."
            exit 0
        fi

        case "${option}" in
            m)
                help_manual
                exit 0
                ;;
            h)
                # Host mode.
                drivers_bind=("${drivers_nvidia[@]}")
                drivers_unbind=("${drivers_vfio[@]}")
                ;;
            p)
                # Passthrough mode.
                drivers_bind=("${drivers_vfio[@]}")
                drivers_unbind=("${drivers_nvidia[@]}")
                ;;
            a | *)
                arg_auto=1
                ;;
        esac
        arg_found=1
    done

    if [ ${arg_found} = 0 ] || [ ${arg_auto} = 1 ]; then
        # Auto mode (default).
        # Check for presence of persistent file indicating whether
        # NVIDIA dGPU needs to be bound to NVIDIA modules or to VFIO
        # module on system init.
        if [[ -f "/var/lib/.dgpu-host" ]]; then
            drivers_bind=("${drivers_nvidia[@]}")
            drivers_unbind=("${drivers_vfio[@]}")
        else
            drivers_bind=("${drivers_vfio[@]}")
            drivers_unbind=("${drivers_nvidia[@]}")
        fi
    fi

    # Bind vfio-pci driver to all functions of non boot_vga NVIDIA GPUs and
    # to all NVIDIA 3D Controller GPUs
    for f in /sys/bus/pci/devices/*; do
        if [[ -f "${f}/device" ]]; then
            read -r device < "${f}/device"
            read -r vendor < "${f}/vendor"
            read -r class < "${f}/class"

            # Check if NVIDIA dGPU device is detected.
            # class "0x030200" = 3D Controller;
            # class "0x030000" = VGA device;
            if [[ "${vendor}" == "0x10de" ]] && \
              ([[ "${class}" == "0x030200" ]] || \
              ([[ "${class}" == "0x030000" ]] && \
               [[ "$(cat "${f}/boot_vga")" == "0" ]])); then
                gpu_path="${f}"
                gpu_audio_path="$(echo "${gpu_path}" | sed -e "s/0$/1/")"
                gpu_usb_path="$(echo "${gpu_path}" | sed -e "s/0$/2/")"

                bind_drivers "${gpu_path}" \
                             "${drivers_bind[0]}" \
                             "${drivers_unbind[0]}"
                bind_drivers "${gpu_audio_path}" \
                             "${drivers_bind[1]}" \
                             "${drivers_unbind[1]}"
                bind_drivers "${gpu_usb_path}" \
                             "${drivers_bind[2]}" \
                             "${drivers_unbind[2]}"
            fi
        fi
    done
}

main "$@"