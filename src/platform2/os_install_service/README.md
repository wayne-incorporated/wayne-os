# os_install_service

This directory contains the OS install D-Bus service. The service is
used to install the OS to disk.

The service exposes a single method, `StartOsInstall`. This method
takes no parameters; the service chooses an appropriate disk to
install to without any user input. Updates are provided with the
`OsInstallStatusChanged` signal. Currently there is no
percentage-complete report, the signal just indicates if the install
succeeded or failed. The signal also includes the install log so that
error details can be presented.

This service (when included in the OS image) only runs when the OS is
live booted from an installer image. This is checked in the [upstart
script](conf/os_install_service.conf) by running
`is_running_from_installer`, which compares the sizes of the root-A
and root-B partitions. If they are the same size, then the OS is
considered installed, whereas if the sizes are different then the OS
is running from an installer image with a stub root-B partition. Note
that this check would break if the USB layout is ever changed to
include a full-size root-B partition.

## Automatic install

To support the creation of mass deployable images install can be
started without human intervention. If a specific UEFI variable,
ChromiumOSAutoInstall-2a6f93c9-29ea-46bf-b618-271b63baacf3, is
present, the service will begin installing when it starts, and request
that the OS shut down when install succeeds.

## Testing

To test the service manually:

    dbus-monitor --system sender=org.chromium.OsInstallService

    sudo -u chronos dbus-send --print-reply --system \
        --dest=org.chromium.OsInstallService \
        /org/chromium/OsInstallService \
        org.chromium.OsInstallService.StartOsInstall

To test autoinstall in a VM:

Use [virt-firmware] to create an OVMF_VARS.fd with the right UEFI variable:

    cp /usr/share/OVMF/OVMF_VARS.fd .
    echo '{
        "variables": [
            {
                "name": "ChromiumOSAutoInstall",
                "guid": "8be4df61-93ca-11d2-aa0d-00e098032b8c",
                "attr": 7,
                "data": "00"
            }
        ]
    }' > var.json
    virt-fw-vars -i OVMF_VARS.fd -o OVMF_VARS.fd --set-json var.json

Then run qemu with that OVMF_FARS.fd:

    runvm --uefi --ovmf-vars OVMF_VARS.fd <...>
    > qemu-system-x86_64 \
    >   ...
    >   -drive if=pflash,format=raw,readonly=on,file=/.../OVMF_CODE.fd \
    >   -drive if=pflash,format=raw,readonly=on,file=OVMF_VARS.fd

Installation should start immediately.

## Security

This service is run as root due to all the privileged operations needed
for OS installation. The [Upstart service] runs `os_install_service` in
minijail to restrict some syscalls, and there's an [SELinux policy] to
further restrict what the service can do.

[Upstart service]: conf/os_install_service.conf
[SELinux policy]: ../sepolicy/policy/chromeos/cros_os_install_service.te
