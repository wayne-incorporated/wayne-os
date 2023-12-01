# Some applications may use /etc/machine-id, if available, so ensure that
# it's available and unique per OS instance. https://crbug.com/221678
cros_post_pkg_postinst_dbus_mung_machineid() {
  ln -sfT /var/lib/dbus/machine-id "${ROOT}"/etc/machine-id
}
