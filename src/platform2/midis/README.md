# Midis: MIDI Service

## ABOUT

Midis (MIDI service) is a system service for processing
MIDI(https://en.wikipedia.org/wiki/MIDI) events. It can communicate information
about device connection/disconnection to several client applications, and pass
file descriptors to these clients to send and receive MIDI messages to and from
hardware, respectively.

## KEYWORDS

Client - A userspace process that establishes an IPC connection with midis. Once
the connection is established, it can listen for device
connection / disconnection messages sent from midis, and can also request for
file descriptors to listen to different MIDI H/W devices and write to them.

Device - Representation of a MIDI h/w device in midis. It is considered
analogous to the ALSA sequencer concept of a "client". A device consists of
multiple subdevices (referred to in ALSA sequencer parlance as "ports").

## CLASS ORGANIZATION

The general structure of the classes is best illustrated by a few diagrams:

### DEVICE HIERARCHY


                         DeviceTracker
                               |
                               |
                               |
             -----------------------------------------
             |                 |                     |
             |                 |                     |
             |                 |                     |
         SeqHandler          Device1    ...        DeviceN

#### DeviceTracker

This class handles the management of MIDI h/w devices connected to a system. Its
functionality includes:
- Managing Device objects associated with each MIDI H/W device.
- Sending data received from MIDI H/W via SeqHandler to the correct clients.
- Informing Client objects when a MIDI device is added/removed (using
  DeviceTracker::Observer).

#### SeqHandler

This class handles all the interactions with the ALSA Seq interface.
It performs many functions:
- Notifies the DeviceTracker class of devices being added/removed via callbacks.
- Used by Device to start/stop subscribing to input events *from* a MIDI H/W
  device. The callback here is sent to InPort (see below).
- Used by Device to send data from a client *to* a MIDI H/W device. The callback
  here is sent to OutPort (see below).

### DEVICE REPRESENTATION

                             Device
                               |
                               |
                               |
         ----------------------------------------------
         |                     |                      |
         |                     |                      |
      InPorts               OutPorts         SubDeviceClientFdHolders


#### InPort

This object is used to represent an input port of a subdevice, on which we
receive data *from* a MIDI H/W device.

When we want to start listening for data from a MIDI H/W subdevice, we call the
InPort::Create() function which creates an InPort object, and calls
InPort::Subscribe(). InPort::Subscribe() calls a SeqHandler function to register
with ALSA Seq to receive MIDI events from that subdevice.

#### OutPort

This object is used to represent the output port of a sudevice, on which we sent
data from a client *to* the MIDI H/W device.

When we want to enable the writing of data to a MIDI H/W subdevice, we call the
OutPort::Subscribe() function, which is a callback to a SeqHandler function to
register with ALSA seq to open a handle to the subdevice which we can
write to. When we receive data from a client, the OutPort invokes a SeqHandler
callback to send the data to the relevant ALSA device handle.

#### SubDeviceClientFdHolder

This class represents a connection between a client and a particular subdevice
of a H/W device. When a Client object receives a request to obtain/listen to a
subdevice, the Device object creates a socket pair. It sends one end to the
client to send/receive data on, and it creates a SubDeviceClientFdHolder object
using the other end. This object performs the following:
- Polls the FD for data from a client.
- Writes the client data to the subdevice, via a callback which is provided
  by Device (Device::WriteClientDataToDevice()).
- Via Device::HandleReceiveData(), it sends data from a MIDI H/W subdevice
  to the listening client.

### IPC

TODO(pmalani)

### Data flow

The data flow to and from H/W devices and clients is best illustrated with the
help of flow diagrams.

#### H/W device to client

    H/W device
       |
       |
      \|/
    SeqHandler -------------------> DeviceTracker
                                      |
                                      |
                                     \|/
                                    Device
                                      |
                                      |
                                     \|/
                          write to all client FDs registered
                              for that subdevice.           --------> Client
                             (SubDeviceClientFDHolder)

#### Client to H/W device

             Client
        (writes data to FD)
               |
               |
              \|/
             Device
     (WriteClientDataToDevice)
               |
               |
              \|/
             OutPort --------------> SeqHandler
                                   (SendMidiData)
                                         |
                                         |
                                        \|/
                                    H/W device
