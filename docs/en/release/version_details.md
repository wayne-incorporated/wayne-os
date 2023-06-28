## Notation
wayne-os-${IMAGE_TYPE}-${USE}-${RELEASED_QUARTER_YEAR}

## Description
#### Image type
- _base_: Pristine Chromium OS image that is similar to Chrome OS 
- _dev_: Developer image that is similar to base with additional dev packages
- _test_: Similar to dev with additional test specific packages and can be easily used for automatic testing using scripts such as test_that, etc
#### Use
- _portable_: Include USB-STORAGE partition that can be used as a removable storage in _Windows_, _macOS_, _Linux_, _Wayne OS_
- _installation_: Can install Wayne OS from a USB flash drive to another local/removable disk on PC
#### Released quarter and year
- For example, _3q21_ means released in 3rd quarter in 2021

## Feature comparison
|                           |_base-portable_ |_dev-installation_  |_test-installation_ |
|---                        |---    |---    |---    |
|USB-STORAGE                |O      |X      |X      |
|[using shell](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/using_shell.md)                |X      |O      |O      |
|[installing on PC](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/installing_wayne_os_on_a_pc.md)           |X      |O      |O      |
|[ssh connection from remote](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/ssh_connection_from_remote.md) |X      |O      |O      |
|[cros flash](https://chromium.googlesource.com/chromiumos/docs/+/master/cros_flash.md) |X      |X      |O      |

