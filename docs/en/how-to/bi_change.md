## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).
<br>Wayne OS allows users/customers to change BI (brand idendity: logo, name) of Wayne OS, under [Terms of service](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/business/terms_of_service.md).

## Preparation
- Arrange your _png_ image files by referring to [chromiumos-assets](https://github.com/wayne-incorporated/wayne-os/tree/main/src/platform/chromiumos-assets) package.
- Check whether your image files' pixel size and name are same with the reference.

## Putting your BI in Wayne OS
- [login to console mode](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/using_shell.md).
- Remove the existing image files in 
<br>/usr/share/chromeos-assets/images
<br>/usr/share/chromeos-assets/images_100_percent
<br>/usr/share/chromeos-assets/images_200_percent
- Put your image files in above path (via USB flash drive or ssh).
- Reboot and check the new BI.
