#!/bin/bash
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script is used to generate the GPG keys required to run this the
# fingerprint study tool with GPG encryption.


: "${GPG_NAME_REAL:=ChromeOSFPStudy}"
: "${GPG_NAME_COMMENT:=Chrome OS Fingerprint Study Key}"
: "${GPG_EMAIL:=}"
: "${OUTPUT_DIR:=.}" # The directory where the output keys will be moved to.

die() {
  echo "$@" >&2
  exit 1
}

if [[ -z "${GPG_EMAIL}" ]]; then
  read -r -p "Please enter the GPG recipient email address: " GPG_EMAIL
fi

# Setup a new empty GNUPG directory.
GNUPGHOME="$(mktemp -d /tmp/fpstudygpg-XXXX)" || die \
  "Error - Failed to generate temp GNUPGHOME."
export GNUPGHOME

mkdir -p "${GNUPGHOME}/private-keys-v1.d" || die \
  "Error - Failed to create the GNUPGHOME private keys dir."

chmod -R 700 "${GNUPGHOME}" || die \
  "Error - Failed to set permission of the GNUPGHOME dir."

# Setup key generation parameters.
# https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
KEY_PARAMS_FILE="${GNUPGHOME}/keyparams"
cat >"${KEY_PARAMS_FILE}" <<EOF
  %echo Generating key.
  Key-Type: RSA
  Key-Length: 4096
  # Disable subkey generation, since this is a one time use key pair anyways.
  # Subkey-Type: RSA
  # Subkey-Length: 4096
  Name-Real: ${GPG_NAME_REAL}
  Name-Comment: ${GPG_NAME_COMMENT}
  Name-Email: ${GPG_EMAIL}
  Expire-Date: 0
  # Passphrase: <IF_UNCOMMENTED_THIS_IS_THE_PASSWORD>
  %ask-passphrase
  # %no-ask-passphrase
  # %no-protection
  %commit
  %echo Done.
EOF

# Generate a new key pair. Make note of the password used. This password is used
# to protect the private key and will be required when decrypting the captures.
echo "# Generating Keys."
gpg --verbose --batch --gen-key "${KEY_PARAMS_FILE}" || die \
  "Error - Failed to generate key pair."
echo

# Record the fingerprint/keyid from by the following command.
# The fingerprint is the 40 hex character string grouped into 10 groups of
# 4 characters. Remove the spaces from this fingerprint to form the keyid.
echo "# Showing generated key fingerprint."
gpg --fingerprint "${GPG_NAME_REAL}" || die \
  "Error - Failed to lookup new generated keyid."
cat <<EOF
# Please take note of the 40 hex character string above, which is shown as 10
# groups of 4 characters.
# This string (without spaces) will be used as the --gpg-recipient argument
# to study_serve[.py].
#
# Example output from gpg:
# pub   rsa4096 2020-12-15 [SCEA]
#      XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX
# uid           [ultimate] ${GPG_NAME_REAL} (${GPG_NAME_COMMENT}) <${GPG_EMAIL}>
#
# This becomes:
# --gpg-recipient 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
EOF
echo

echo "# Exporting keys."
# Export only the public key for the test device. This key must be copied to the
# test device and will be used as the keyring.
gpg --verbose --export "${GPG_NAME_REAL}" \
  >"${GNUPGHOME}/chromeos-fpstudy-public-device.gpg" || die \
  "Error - Failed to generate key pair."

# Export the private key for backup. This key is for the recipient to be able
# to decrypt the fingerprint capture.
# This key must NOT be copied to the test device.
gpg --verbose --export-secret-keys "${GPG_NAME_REAL}" \
  >"${GNUPGHOME}/chromeos-fpstudy-private.gpg" || die \
  "Error - Failed to generate key pair."

mv -iv "${GNUPGHOME}/chromeos-fpstudy-public-device.gpg" \
       "${GNUPGHOME}/chromeos-fpstudy-private.gpg" \
       "${OUTPUT_DIR}" || die "Error - Failed to move key files to output dir."

echo "# Removing temporary directory '${GNUPGHOME}'"
rm -rf "${GNUPGHOME}" || die "Error - Failed to remove temp directory."
