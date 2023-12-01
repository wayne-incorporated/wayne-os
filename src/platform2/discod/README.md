# discod (DISk COntrol Daemon)

This daemon is intended to perform runtime control of behavioral features of
storage devices in response to changes in io patterns, system utilization etc.
Presentlys the daemon only controls UFS Write Booster. The control is performed
by observing io to the storage device via iostat, as well as by listening to an
explicit signal an application can send.

## TODOs
* Add/Tune state transition rules
