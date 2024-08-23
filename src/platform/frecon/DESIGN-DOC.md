[TOC]

# Frecon, a console for freon

## What is Frecon
Frecon is a replacement for the kernel console on Chrome OS. It uses KMS and dumb buffers, and no graphics acceleration at all. Unlike the kernel FB, it should not keep persistent framebuffers in memory.

## Motivation
This change is motivated by the fact that we are removing X from the system, and making the gpu process the drm master.  As this happens, if the gpu process crashes, the normal debug procedure is to switch to the console and get debug info.  However, if we do that with the current VT console, it will blank the screen and we would lose valuable debug information.  To resolve this, we propose to remove the VT console and replace it with a user mode console based on libtsm.   This console can draw itself and preserve state of the gpu process when crashed.   As a consequence, we would need to make sure that the ctrl-alt-f1 and ctrl-alt-f2 can be used to switch between chrome and the console in dev mode, as well as make sure that the console can be activated when a chrome crash is detected.

## Kernel changes
Disable FB at the kernel level. No VT/FB switches any more.

## DRM master
Problem: switch away (DROP_MASTER), switch back, you can't use SET_MASTER because you aren't root.

Solution: Fix SET_MASTER to allow you to get master if you're the only DRM process

## Transition
There will need to be two types of transitions between frecon and chrome.   The first is a graceful transition in which chrome is asked to either drop_master to allow frecon to take control or chrome is asked to retake master, and set the mode.   The second transition type is a forced taking of drm master.  This will be necessary in the event the chrome has crashed or is in some way not responding.   The general flow will be for chrome to be asked for a graceful transition and if it doesn't respond then go the forced transition route.   The reason to not use the forced transition every time is because if control is forcibly taken away from chrome, there really isn't a good way to give control back to chrome without some chrome involvement.   The chrome support for the transition will be just enough to allow dbus messages to be received and to tell the native_display_delegate to relinquish control of the display.   In the dri specific backend, relinquishing control means calling drmDropMaster.   In order to achieve that, there will be a dbus message service provider (called ConsoleServiceProvider) registered with cros_dbus_service that will listen for the ActivateConsole dbus message on the LibCrosServiceInterface.  This message has a single 32-bit integer parameter that indicates which conole number should be activated.   Console identifier's 0 and 1 are chrome.  Actually console id 1 is chrome.  Console id 0 can be reserved for some special circumstance that is unidentified at this point.   Console id's 2 and up can be other processes that want to control the display, such as multiple consoles, or crouton, or other things that may come up in the future.

The ConsoleServiceProvider will then relay the ActivateConsole message to a DBusClient that is handled by the DBusThreadManager.   Within the ui system, there will be an observer of this client that will receive notifications that the ActivateConsole was called with the console id.   It will then ask the ozone layer's native_display_delegate to either relinquish control (if the console id is 2 or more) or configure the display.   In the dri platform, in order to configure the display, it will need to call drmSetMaster in order to regain master control.   The native_display_delegate is allowed to assume that if it's being asked to take control of the display server, that any relinquishing of the display by other entities (frecon, crouton, etc) will have already been done.   It is possible that system events can lead to the native_display_delegate being asked to configure it's display while another entity has control (such as hotplug or user activity from a blanked screen).   In that event, the request to set_master will fail and the native_display_delegate is responsible for handling that gracefully.

## Interaction with Session Manager
Since the user mode console uses system resources, we would like it to be running only when requested (when the user switches to it and when a chrome crash is detected).    The problem with not having it running all the time is that there needs to be some entity that can listen for the ctrl-alt-f1/ctrl-alt-f2 sequence.   Additionally, the session manager should know how to launch this console when it detects that Chrome has crashed.   So, the proposal is that a class similar to the InputWatcher of powerd is added to SessionManager that can watch for keyboard input (as opposed to lid/power button input) and look for the hot-key sequences.   If it detects that the console should run gracefully (ie not a Chrome crash), then it can send a dbus message to Chrome to ask it to drop master and activate the console.   If it detects that Chrome should be in the foreground (ctrl-alt-f1), it can send send a dbus message to Chrome to tell it to acquire master and redo modeset.

## Ply-image replacement
frecon should be able to replace ply-image completely. This will let us share the modeset code. How do we achieve modeset-less boot? It should just work since the kernel turns modeset calls into a simple page flip call when the mode is the same.

## Job management
Add an upstart job to start frecon. If session_manager sees that chrome couldn't start, it sends a dbus message to frecon to start displaying the console.

## Input handling
We need to drop/get evdev at the same time we get DRM_MASTER. 

## FRECON API
Frecon will support the notion of running multiple consoles simultaneously.   At any one time, one or zero consoles will be visible.   Frecon will support an API that will allow for the following operations:
Create a terminal with either the default program or a specified program.  To initiate this, a client will send the MakeVT method.   It will take an integer parameter which is the terminal number.   Only the values 1 through MAX_TERMINALS (currently 5) are supported.   This method can take an optional parameter which is the name of a program to run.   This is only supported in recovery mode for security reasons.   This request will receive a response that is the name of a file that when written to, will be displayed on the terminal.   This will be used in place of existing uses of the openvt command.
Switch the display to an existing terminal.   To initiate this, a client will send the SwitchVT method.   It will take an integer parameter which is the terminal number.   If no terminal with the given ID has been created, this request will fail.   This will be used in place of existing uses of chvt.

Frecon will accept commands over dbus and over a tcp socket.   The D-Bus usage will be used in dev and test mode for testing and development purposes.   When using D-Bus, frecon will operate a server on the interface org.chromium.frecon.   The socket usage will be used in recovery mode in which there is no D-Bus server.   When using sockets, frecon will listen on port 6350.

## Command Line Options

## TODO
- See if we can use libtsm for console emulation which seems like a good fit.
- See if we should start from kmscon or just start from scratch and pick bits from kmscon.
- Figure out input with a raw keyboard on top of evdev
