#!/bin/bash
# render.sh: renders images/src/NAME.html to images/NAME.png with headless Chrome.
#
#   images/src/render.sh            render every image
#   images/src/render.sh flow use   render only these
#
# Each page is laid out at half the PNG's size in CSS pixels and shot at device
# scale 2. Chrome shoots whole CSS pixels, so an odd height (1125) is shot one
# row taller and cropped from the bottom with sips. The pages load SF Mono from
# Terminal.app's bundled fonts (macOS); without it they fall back to Menlo.
# Set CHROME to use another Chrome or Chromium binary.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out=$(cd "$here/.." && pwd)
chrome=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
[ -x "$chrome" ] || { echo "render.sh: no Chrome at $chrome (set CHROME)" >&2; exit 2; }

# name, PNG width, PNG height
sizes='flow 2000 1440
guard 2000 1125
use 2000 1125
where-the-key-lives 2000 1125
why-keychain 2000 1125'

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

render() {
  local name=$1 w=$2 h=$3
  local css_w=$((w / 2)) css_h=$(((h + 1) / 2))
  [ -f "$here/$name.html" ] || { echo "render.sh: no $here/$name.html" >&2; return 1; }
  # (A --user-data-dir of its own made this Chrome hang without shooting.)
  "$chrome" --headless=new --disable-gpu --hide-scrollbars \
    --allow-file-access-from-files --virtual-time-budget=3000 \
    --force-device-scale-factor=2 --window-size="$css_w,$css_h" \
    --screenshot="$work/$name.png" "file://$here/$name.html" >/dev/null 2>&1
  [ -s "$work/$name.png" ] || { echo "render.sh: Chrome made no screenshot of $name" >&2; return 1; }
  sips --cropToHeightWidth "$h" "$w" --cropOffset 0 0 "$work/$name.png" --out "$out/$name.png" >/dev/null
  local got
  got=$(sips -g pixelWidth -g pixelHeight "$out/$name.png" | awk '/pixelWidth/ {w=$2} /pixelHeight/ {h=$2} END {print w "x" h}')
  [ "$got" = "${w}x${h}" ] || { echo "render.sh: $name.png is $got, expected ${w}x${h}" >&2; return 1; }
  echo "$out/$name.png  $got"
}

wanted=("$@")
while read -r name w h; do
  if [ ${#wanted[@]} -gt 0 ]; then
    match=
    for x in "${wanted[@]}"; do [ "$x" = "$name" ] && match=1; done
    [ -n "$match" ] || continue
  fi
  render "$name" "$w" "$h"
done <<< "$sizes"
