sudo_mask="
  /etc/pam.d/sudo
  /etc/pam.d/sudo-i
  /usr/lib/tmpfiles.d/sudo.conf
"

PKG_INSTALL_MASK+=" ${sudo_mask}"
INSTALL_MASK+=" ${sudo_mask}"
