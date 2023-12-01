# Chromium OS Region Database.

This folder contains the Chromium OS region database.

The database is created in JSON format and available in
 `/usr/share/misc/cros-regions.json`.

Every Chromium OS device should have a `region` VPD entry that can be directly
used as a key into this JSON database.

## New Regions

For projects that need to use unpublished regions, please:

1.  Visit http://go/cros-keyboard-request and find the table
    *Consolidated VPD & region data*, and check if your region is confirmed.
    (If not, contact OOBE / L10N team to confirm and sign-off).
2.  `cd ~/trunk/src/private-overlays/chromeos-partner-overlay/chromeos-base`
3.  `cd regions-private/files`
4.  Edit `regions_overlay.py` to add correct region data into `REGIONS_LIST`.
5.  Build system and try. You can use tool `cros_region_data` to verify:
    `cros_region_data <FIELD> <REGION_TO_TEST>`
    For example, `cros_region_data description us` shows `United States`.
6.  Create the CL and cherry-pick into both factory branches and
    release image (including FSI) branches.
