# Private Computing Device Active Daemon
The check membership request of Private Set Membership is computing expensive,
and in order to decrease the traffic of checking membership, we store the
device last ping dates of each use case into the preserved file. This daemon
is used to save the device active ping status into preserved file, and retrieve
the device active ping status from preserved file after powerwash.
DD: go/cros-psm-preservedfile-dbus
