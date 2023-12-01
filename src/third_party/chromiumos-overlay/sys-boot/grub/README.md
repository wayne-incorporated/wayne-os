# sbat.csv

sbat.csv is used by `/scripts/build_library/create_legacy_bootloader_templates.sh` to implement UEFI Secure Boot Advanced Targeting (SBAT), a mechanism to require a specific level of resistance to UEFI Secure Boot bypasses. It is stored in the grub ebuild directory so that it is easier to update it with grub.

sbat.csv is required for the reven board.

## Updating sbat.csv
sbat.csv needs to be updated whenever grub or sbat is updated to a new version.

**It has three lines in it containing info about the following:**

1) sbat

2) upstream grub

3) our forked grub


**Whenever grub is updated, the following needs to be updated:**

1) grub version number (X.XX)

**AND the following may need to be updated, depending on upstream grub requirements\*:**

1) grub generation number (X)

2) sbat generation number (X)

3) sbat version number (X)

Generation numbers are incremented whenever the most recent secure boot vulnerability becomes required by SBAT.

\*As of right now, both SBAT and grub upstream documentation don't currently have generation numbers listed, as they are all set to 1.

## Understanding SBAT
Part of sbat.csv is meant to be human-readable, and part of it (specifically, the generation numbers) is processed by SBAT.

As far as I understand, SBAT only needs to process the grub line with a generation number that matches its requirements, so having two grub lines (upstream and our version) as opposed to one is more for human-readability.

SBAT official documentation is located here: https://github.com/rhboot/shim/blob/main/SBAT.md
