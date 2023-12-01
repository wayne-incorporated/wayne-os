# glib-bridge: message loop interoperation

New code in platform2 should not be written on top of glib. However, it
is sometimes unavoidable that we use libraries that were written on top
of it. Instead of forcing us to write all of our code on top of glib as
well, this library provides a bridge to run the glib message loop on top
of libchrome's message loop.
