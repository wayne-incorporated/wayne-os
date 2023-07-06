## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).
<br>TODO: It seems like this document works for other CROS derivates, so the test result should be added.
<br>This document intends to help developers who want to manage Wayne OS.

## Requirement
_wayne-os-dev_ or _wayne-os-test_ versions

## In local shell
[Open shell](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/using_shell.md) in Wayne OS device then try the following steps.
#### Powerwash
```
$ { sudo bash -c 'echo "fast safe" > /mnt/stateful_partition/factory_install_reset' ;} && sudo reboot
```
or
```
$ { echo "fast safe" | sudo tee -a /mnt/stateful_partition/factory_install_reset ;} && sudo reboot
```
#### Job control
Wayne OS and Chromium OS derivates use [Upstart](https://upstart.ubuntu.com/).
<br>To check job list.
```
$ sudo initctl list
```
To control the job.
```
sudo initctl start/stop/restart/status ${JOB}
```

#### Available commands for checking information, performance
- cat [/proc/*](https://man7.org/linux/man-pages/man5/proc.5.html)
- cat /etc/*release
- [lscpu](https://man7.org/linux/man-pages/man1/lscpu.1.html)
- [lsusb](https://man7.org/linux/man-pages/man8/lsusb.8.html)
- sudo [lspci](https://man7.org/linux/man-pages/man8/lspci.8.html)
- [mount](https://man7.org/linux/man-pages/man8/mount.8.html)
- [uname](https://man7.org/linux/man-pages/man1/uname.1.html)
- [ifconfig](https://man7.org/linux/man-pages/man8/ifconfig.8.html)
- [top](https://man7.org/linux/man-pages/man1/top.1.html)
- [free](https://man7.org/linux/man-pages/man1/free.1.html)
- [vmstat](https://man7.org/linux/man-pages/man8/vmstat.8.html)
- [netstat](https://man7.org/linux/man-pages/man8/netstat.8.html)
- [df](https://man7.org/linux/man-pages/man1/df.1.html)
- [du](https://man7.org/linux/man-pages/man1/du.1.html)
- [lsof](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [uptime](https://man7.org/linux/man-pages/man1/uptime.1.html)
- [ps](https://man7.org/linux/man-pages/man1/ps.1.html)
- [pmap](https://man7.org/linux/man-pages/man1/pmap.1.html)
- sudo [ss](https://man7.org/linux/man-pages/man8/ss.8.html)
- [ipcs](https://man7.org/linux/man-pages/man1/ipcs.1.html)
- sudo [dmidecode](https://linux.die.net/man/8/dmidecode)
- sudo [hdparm](https://man7.org/linux/man-pages/man8/hdparm.8.html)
- [lsblk](https://man7.org/linux/man-pages/man8/lsblk.8.html)
- sudo [dmesg](https://man7.org/linux/man-pages/man1/dmesg.1.html)

## From remote
You can send the shell commands from remote device to Wayne OS device [via ssh](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/ssh_connection_from_remote.md).
```
ssh chronos@${IP} -t "COMMAND"  # This will ask pw again if the COMMAND includes sudo.
ssh root@${IP} "COMMAND"  # This is available only in Wayne OS test version.
```

#### Examples
- Force powerwash to Wayne OS device.
```
$ ssh chronos@192.168.100.200 -t "{ echo "fast safe" | sudo tee -a /mnt/stateful_partition/factory_install_reset ;} && sudo reboot"
```
- Force to restart UI (logout user graphic session) on Wayne OS device.
```
$ ssh root@192.168.100.200 "initctl restart ui"
```
- Getting process information from Wayne OS device.
```
$ ssh chronos@192.168.100.200 -t "top -n 1 -b" > proc_list.txt
```
