# ImageLoader Manifest Parser

Library for parsing ImageLoader manifest files. ImageLoader uses these files
to verify and mount images (e.g. DLC images).

## Required Fields

- `manifest-version`: Required for compatibility.
- `image-sha256-hash`: Image hash.
- `table-sha256-hash`: Hash of the `dm-verity` table file.
- `version`: e.g. DLC version.

## Optional Fields

- `fs-type`: File-system type.
- `id`: DLC ID name.
- `package`: DLC package name.
- `name`: Human readable DLC name.
- `image-type`: Type of image, e.g. "component", "dlc", etc. Needed for
verification and mount flow. Currently only required for DLC.
- `pre-allocated-size`: Preallocated size (bytes) for DLC image files. Needed by
the dlcservice daemon.
- `size`: DLC image size (bytes).
- `is-removable`: True if imageloader may unload the image.
- `preload-allowed`: True if preloading of DLC image is allowed on test images.
- `factory-install`: True if factory installation of DLC image is allowed.
- `mount-file-required`: File created for indirect access of mount path.
- `reserved`: True if DLC image slots should always be reserved on disk.
- `critical-update`:  True if DLC updates should always auto update with the OS.
- `used-by`: Either "user" or "system" for DLC ref counting.
- `days-to-purge`: Delay for cleaning up zero referenced DLC.
- `description`: Human readable DLC description.
- `metadata`: Expandable metadata.
- `use-logical-volume`: True if DLC should use logical volumes.
