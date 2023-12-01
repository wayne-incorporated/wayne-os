# typecd: The Chrome OS USB Type C Daemon

## ABOUT

typecd is a system daemon for tracking the state of various USB Type C ports and connected
peripherals on a Chromebook. It interfaces with the Linux Type C connector class framework
to obtain notifications about Type C events, and to pull updated information about ports and
port-partners state. It also listens to USB events for handling USB device
add/remove.

## CLASS ORGANIZATION

The general structure of the classes is best illustrated by a few diagrams:

```
                         Daemon
                           |
                           |
                           |
        ------------------------------------------------------------------------------------------------
        |                                     |              |                  |                      |
        |                                     |              |                  |                      |
        |                                     |              |                  |                      |
        |                                     |              |                  |                      |
   UdevMonitor ---typec- udev- events---> PortManager ---> ECUtil  ------> DBusManager    SessionManagerProxy
                                                   /|\      |                |                               |
                                                    |       ------------------                               |
                                                    |                                                        |
                                                    ----------------------------------------------------------
                                                                     session_manager events
```

### UdevMonitor

All communication and event notification between the Linux Kernel Type C connector class framework
and typecd occurs through the udev mechanism. This class watches for any events of the `typec` subsystem.
Other classes (in this case, `PortManager`) can register `TypecObserver`s with `UdevMonitor`. When any notification
occurs, `UdevMonitor` calls the relevant function callback from the registered `TypecObserver`s.

This class also watches for events of the `usb` subsystem. Similar to
`TypecObserver`, there is `UsbObserver` with callbacks for `usb` add/remove events.

This class has basic parsing to determine which `Observer` should be called (is this a port/partner/cable notification?
is it add/remove/change?)

### PortManager

This class maintains a representation of all the state of a typec port exposed by the Type C connector class via sysfs.
The primary entity for `PortManager` is a Port.

```
         PortManager(UdevMonitor::TypecObserver)
                           |
                           |
                           |
        ---------------------------------------
        |        |                            |
        |        |                            |
        |        |                            |
      Port0    Port1     ....               PortN
```

`PortManager` sub-classes `UdevMonitor::TypecObserver`, and registers itself to receive typec event notifications. In turn, it
routes the notifications to the relevant object (Port, Partner, Cable) that the notification affects.

#### Port

This class represents a physical Type C connector on the host, along with components that are connected to it. Each `Port`
has a sysfs path associated with it of the form `/sys/class/typec/portX` where all the data (including relevant PD information)
is exposed by the kernel. On udev events this sysfs directory is read to update the `Port`'s in-memory state.
A `Port` can be detailed as follows:

```
                      Port
                       |
                       |
        -----------------------------------------------------------
        |                                 |                        |
        |                                 |                        |
  (sysfs path info)                    Partner                   Cable
```

NOTE: In order to retrieve DisplayPort status (Hotplug Detect, Mux state) from the EC to synthesize a metric, `Port` also holds
a pointer to the `ECUtil` class (it is set by `PortManager` immediately after `Port` creation).

##### Partner

This class represents a device/peripheral connected to a `Port`. There can only be 1 partner for each `Port`. Each `Partner` has
a sysfs path associated with it of the form `/sys/class/typec/portX-partner` where all the data (including relevant PD
information) is exposed by the kernel. On udev events this sysfs directory is read to update the `Partner`'s in-memory state.

This class also stores a list of Alternate Modes which are supported by the partner. Each Alternate mode is given an index according
to the index ascribed to it by the kernel.

```
                    Partner
                       |
                       |
        ------------------------------------------------------------------------
        |                        |                   |          |               |
        |                        |                   |          |               |
  (sysfs path info)      PD Identity info        AltMode0    AltMode1  ...   AltModeN
```

There are getters and setters to access the PD identity information (for example, `{Get,Set}ProductVDO()`).
There are also functions to retrieve information associated with partner altmodes, like getting a pointer to an altmode (`GetAltMode()`).

##### Cable

This class represents a cable that connects a `Port` to a `Partner`. There can only be 1 cable for each `Port`. Each `Cable` has
a sysfs path associated with it of the form `/sys/class/typec/portX-cable` where the PD identity data is exposed by the kernel.

This class also stores a list of Alternate Modes which are supported by the cable. Each Alternate mode is given an index according
to the index ascribed to it by the kernel. At present only SOP' cable plug alt modes are supported.
Even though each cable plug (i.e SOP' and SOP'') has its own device and sysfs path (of the form `/sys/class/typec/portX-plug.{0|1}`),
since the Chrome OS Embedded Controller (EC) only enumerates SOP' alt modes, we don't create a separate class and instead just list
the Alternate Modes of SOP' as belonging to the associated `Cable`.

When `UdevMonitor` receives an `add` event for a SOP' plug device, the `Cable` code searches through the corresponding sysfs file and adds all
the alternate Modes associated with that file. It also reacts to individual SOP' plug altmode device add udev events and registers those,
in case they weren't already registered during SOP' plug registration.


```
                     Cable
                       |
                       |
        ------------------------------------------------------------------------------------
        |                        |                    |                |                    |
        |                        |                    |                |                    |
  (sysfs path info)      PD Identity info        SOP' AltMode0    SOP' AltMode1  ...   SOP' AltModeN
```

There are getters and setters to access the PD identity information (for example, `{Get,Set}ProductVDO()`).
There are also functions to retrieve information associated with partner altmodes, like getting a pointer to an altmode (`GetAltMode()`).

### ECUtil

Since there is no consistent sysfs interface to trigger alternate (or USB4) mode entry/exit, typecd uses the EC to accomplish this.
`PortManager` possesses a pointer to an object implementing this interface. In production code, this interface is implemented by
`CrosECUtil`, which communicates with the EC via `debugd` by means of D-Bus IPC. debugd in turn uses `ectool` to send the relevant
command to the EC.

The `debugd` API used by `CrosECUtil` is protected by D-Bus policy files that only allow users of type `typecd` to call it.

```

        PortManager
            |
            |                           CrosECUtil
            |---------------------> (implements ECUtil)
                                             |
                                             |
                                             |
                                          (D-Bus)
                                             |
                                             |
                                             |------------> debugd
                                                              |
                                                              |
                                                              |
                                                           (ectool)
                                                              |
                                                              |
                                                             \|/
                                                         Chrome OS EC

```

For unit tests, a mock implementation of the interface is used (`MockECUtil`) and its behaviour can be controlled based
on what is being tested.

### SessionManagerProxy

On devices where AP-driven mode entry is supported, the alternate mode which a Type C peripheral will enter is dictated
by the current session state (logged in, locked, etc.). To receive the state updates, `typecd` registers a listener for
`session_manager` session event D-Bus signals using `SessionManagerProxy`. When these signals are received, `PortManager`
is notified. `PortManager` then updates its internal state variable (which tracks session state), and depending on the
session event, performs an alternate mode switch (by exiting the current mode and then running the mode entry sequence again).

```

                PortManager
   (implements SessionManagerObserverInterface)
                   /|\
                    |
                    |
                    |-------------> SessionManagerProxy
                                            /|\
                                             |
                                             |
                                          (D-Bus)
                                             |
                                             |
                                             |---------- session_manager

```

For unit tests, where it's difficult to emulate the asynchronous `session_manager` events, we emulate the same behaviour by calling
the `PortManager`'s `SessionManagerObserverInterface` functions.


### DBusManager

The `PortManager` contains a pointer to a `DBusManager` instance which signals notification requests to Chromium over D-bus. In
Chromium, Aura Shell (Ash) includes instances of the `PciePeripheralNotificationController` and `UsbPeripheralNotificationController`
classes which inherit from the `TypecdClient` class. The `DBusManager` supports two types of D-bus message. (1) `DeviceConnectedType`
which signals the capabilities of the connected device and (2) `CableWarningType` which signals a scenario where the connected partner may
be limited in some way by the cable. On receiving D-bus signals sent by the typec `DBusManager`, the USB and PCIe notification
controller classes in Ash will process the type of signal received to determine which notification, if any, to show the user.

```

                 PortManager -----------> DBusManager
                                               |
                                               |
                                            (D-Bus)
                                               |
                                              \|/
                                              Ash
                                               |
                                               |
                  -----------------------------------------------------------
                  |                                                         |
                  |                                                         |
  PciePeripheralNotificationController                      UsbPeripheralNotificationController
       (implements TypecdClient)                                 (implements TypecdClient)

```

## Alternate Mode Entry examples

On `Partner`s which support both Thunderbolt 3 (TBT3) alternate mode as well as DisplayPort (DP) alternate mode, the choice of which
mode to enter can depend on a few factors like the current user session state and the value of the `PeripheralDataAccessEnabled`
device setting. We can describe the expected behaviour with the help of a table. NOTE: The following applies *only* to TBT3 docks and
peripherals that also support DP alternate mode.

| Device Event                           | PciPeripheralAccess == true | PciPeripheralAccess ==  false |
|    :--------------------------------:  |     :------------------:    |  :-------------------------:  |
| Hotplug when unlocked                  | TBT3                        | DP                            |
| Hotplug when locked                    | DP                          | DP                            |
| Hotplug when logged out                | DP                          | DP                            |
| Hotplug - Guest Mode                   | DP                          | DP                            |
| Already connected, then screen unlocks | DP -> TBT3                  | DP                            |
| Already connected, then screen locks   | TBT3                        | DP                            |
| Already connected, then login occurs   | DP -> TBT3                  | DP                            |
| Already connected, then logout occurs  | TBT3 -> DP                  | DP                            |
