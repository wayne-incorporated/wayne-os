#!/bin/bash
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# ---- Begin settings section ----

# Set to 0 for any resolutions not supported by scanner.
HAS_75DPI=1
HAS_100DPI=1
HAS_150DPI=1
HAS_200DPI=1
HAS_300DPI=1
HAS_400DPI=1
HAS_600DPI=1
HAS_1200DPI=1

# Set to 0 for any modes not supported by scanner.
SUPPORTS_COLOR=1
SUPPORTS_GRAYSCALE=1
SUPPORTS_BW=1

# Set to 0 for any modes not supported by scanner.
HAS_PLATEN=1
HAS_ADF_SIMPLEX=1
HAS_ADF_DUPLEX=1

# ---- End settings section.  No changes needed below here. ----

scanner="$1"
if [[ -z "${scanner}" ]]; then
  if [[ -n "${MFP_DEV}" ]]; then
    scanner="${MFP_DEV}"
  else
    echo "Usage: $0 scanner"
    exit 1
  fi
fi
echo "Testing scan combinations for ${scanner}"

# Copy stdout so we can redirect lorgnette away later
exec 3>&1

resolutions=()
[[ ${HAS_75DPI} -ne 0 ]] && resolutions+=(75)
[[ ${HAS_100DPI} -ne 0 ]] && resolutions+=(100)
[[ ${HAS_150DPI} -ne 0 ]] && resolutions+=(150)
[[ ${HAS_200DPI} -ne 0 ]] && resolutions+=(200)
[[ ${HAS_300DPI} -ne 0 ]] && resolutions+=(300)
[[ ${HAS_400DPI} -ne 0 ]] && resolutions+=(400)
[[ ${HAS_600DPI} -ne 0 ]] && resolutions+=(600)
[[ ${HAS_1200DPI} -ne 0 ]] && resolutions+=(1200)

color_modes=()
[[ ${SUPPORTS_COLOR} -ne 0 ]] && color_modes+=(Color)
[[ ${SUPPORTS_GRAYSCALE} -ne 0 ]] && color_modes+=(Grayscale)
[[ ${SUPPORTS_BW} -ne 0 ]] && echo "B&W is supported but will not be tested"

sources=()
[[ ${HAS_PLATEN} -ne 0 ]] && sources+=(Platen)
[[ ${HAS_ADF_SIMPLEX} -ne 0 ]] && sources+=("ADF Simplex")
[[ ${HAS_ADF_DUPLEX} -ne 0 ]] && sources+=("ADF Duplex")

echo -e "Testing resolutions: ${resolutions[*]/#/\\n  }"
echo -e "Testing color modes: ${color_modes[*]/#/\\n  }"
echo -e "Testing sources: ${sources[*]/#/\\n  }"

safe_name="${scanner//[^0-9a-zA-Z_-]/_}"
start_time=$(date +"%Y-%m-%dT%H:%M")
out_dir="/tmp/wwcb/${safe_name}/${start_time}"
mkdir -p "${out_dir}"

results=""
for src in "${sources[@]}"; do
  for mode in "${color_modes[@]}"; do
    for res in "${resolutions[@]}"; do
      output="${out_dir}/scan-${src}-${mode}-${res}_page%n.png"

      pages=1
      if [[ "${src}" == *ADF* ]]; then
        read -p "Put paper in ADF and enter number of pages: " -r pages
      fi

      # Capture stderr by redirecting it to stdout.
      # The original stdout is redirected to fd 3, which we created as a copy
      # earlier.
      # This lets us capture stderr while letting stdout go to the terminal.
      if ! error=$(
          lorgnette_cli scan \
              --scanner="${scanner}" \
              --bottom_right_y=279.4 \
              --scan_resolution="${res}" \
              --color_mode="${mode}" \
              --scan_source="${src}" \
              --output="${output}" \
              2>&1 1>&3); then
              results+="$(printf "\n%s\t%s\t%s\t%s" \
                          "${src}" "${mode}" "${res}" \
                          "FAIL: lorngette_cli failed: ${error}")"
        echo "${error}"
        continue
      fi

      expected_width=$((85*res/10))
      expected_height=$((110*res/10))
      if [[ ${mode} == "Color" ]]; then
        expected_color="sRGB"
      elif [[ ${mode} == "Grayscale" ]]; then
        expected_color="Gray"
      else
        expected_color="Unmatched"
      fi

      problems=""
      for pn in $(seq 1 "${pages}"); do
        page="${output/\%n/${pn}}";
        if [[ ! -f "${page}" ]]; then
          problems="${problems}${problems:+ }Page ${pn}: ${page} not found;"
          continue
        fi

        read -r width height color < <(identify "${page}" | \
            sed -e \
            's/.* PNG \([0-9]*\)x\([0-9]*\).*8-bit \([^ ]*\).*/\1 \2 \3/')

        if [[ "${width}" != "${expected_width}" ]]; then
          problems+="${problems:+ }Page ${pn}: "
          problems+="Width ${width} != expected ${expected_width};"
        fi
        if [[ "${height}" != "${expected_height}" ]]; then
          problems+="${problems:+ }Page ${pn}: "
          problems+="Height ${height} != expected ${expected_height};"
        fi
        if [[ "${color}" != "${expected_color}" ]] ; then
          problems+="${problems:+ }Page ${pn}: "
          problems+="Colorspace ${color} != expected ${expected_color};"
        fi
      done

      if [[ -z "${problems}" ]]; then
        results+="$(printf "\n%s\t%s\t%s\t%s" "${src}" "${mode}" "${res}" "OK")"
      else
        results+="$(printf "\n%s\t%s\t%s\t%s" \
                    "${src}" "${mode}" "${res}" "FAIL: ${page}: ${problems}")"
      fi
    done
  done
done

echo "${results}"
echo "Output in ${out_dir}"
