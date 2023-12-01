# Media Capabilities

`media_capabilities` is a command line tool to detect video and
camera capabilities on Chrome OS. Note that the tool reports combined
capabilities of V4L2 and VA-API. For example, if a device can decode VP8 4k
using the VA-API but only 1080p using V4L2, this tool would return both
regardless of which API Chrome uses.
