Don't add binary image files. Create a diagram using GraphViz, and follow these
instructions to generate an SVG from it and upload it to GS bucket:

Example:
```
# Generate SVG file
dot -Tsvg provider_inheritance.gv -o out.svg
# Upload to GS bucket
~/chromiumos/website/scripts/upload_lobs.py out.svg
# Get the hash from the generated file `out.svg.sha1`
# Use the hash in your document as follow:
#![Alt text](https://storage.googleapis.com/chromium-website-lob-storage/<hash>)
```

Store the GraphViz code for each diagram on a separate file.
