# Garcon

Garcon is a daemon that runs inside the container for Linux VMs. Its purpose
is for bi-directional communication with the host for various application and
container level features. It uses vsock for the communication with the host over
gRPC.

Garcon's binary code lives inside of the VM and is bind-mounted into the
container. There is also the cros-garcon Debian package which contains various
configuration files for garcon.

Garcon receives a token from the host which is used to identify itself in all
communication back to the host. This is bind-mounted into the container from the
VM.

## Container to Host RPCs

These are the things that garcon initiates communication on and sends a message
back to the host.

### Startup and Shutdown

A message is sent to the host whenever garcon starts up or is terminated via
SIGTERM.

### Installed Applications

Garcon will look for .desktop files in all of the directories specified in the
XDG_DATA_DIRS environment variable. It then sends a message to the host with
a list of all the installed applications so they can be presented in the Chrome
OS launcher.

If you want to create your own shortcut, putting .desktop file under
/usr/local/share/applications/ or ~/.local/share/applications/ should normally
be sufficient.

### MIME Types

Garcon parses the system and user
[mime.types](https://wiki.debian.org/MIME/etc/mime.types) files and informs the
host about the registered mappings to allow the host to correlate file types to
applications available in the container.

### Opening URLs

Garcon can send a message to the host which tells Chrome to open a specific URL
in a new tab in the browser. This is setup through a few different
/etc/alternatives and also through BROWSER environment variable.

### Opening Terminals

Garcon can send a message to the host which causes a new terminal window to be
opened with a connection back into the container. This is setup through the
/etc/alternative/x-terminal-emulator.

## Host to Container RPCs

### Launching Applications

Garcon can be instructed to execute an application that corresponds to a
.desktop entry that was sent to the host.

### Fetching Icons

Garcon can retrieve icons that correspond to .desktop files from the container
and will return that icon data to the host. Currently only PNG files are
supported.

### Linux Package Information

Garcon can be queried from the host for information about a specific Linux
package file that is accessible to the container. PackageKit is used to get the
information from the file.

### Linux Package Installation

Garcon can be instructed by the host to perform an installation on a Linux
package file that is accessible to the container. PackageKit is used as the
backend for performing the install.

### Linux Package Uninstallation

Garcon can be instructed by the host to uninstall an installed Linux package.
The package to be uninstalled is indicated by the name of the .desktop file,
not the package_id, to avoid issues with stale package_ids. PackageKit is used
as the backend for performing the uninstall.

## Garcon Background Processing

Garcon does additional work in the background aside from the RPC services
outlined above. It watches various directories for changes that would affect
information relating to installed applications or MIME type information. It will
also perform regular updates on all of the Google installed packages relating to
various services (such as garcon) that are in the container.

### Configuration Settings

There is a file located at $HOME/.config/cros-garcon.conf which contains
configuration settings that can affect how garcon operates.

DisableAutomaticCrosPackageUpdates is a boolean setting of false or true. If set
to true it will prevent garcon from regularly checking for and installing
updates to the Google provided 'cros' packages.

DisableAutomaticSecurityUpdates is a boolean setting of false or true. If set to
true it will prevent garcon from regularly checking for and installing security
updates for packages that are currently installed.
