#!/bin/bash

set -eo pipefail

declare -a urls=(
https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/features/fields-Persoon.csv
https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/features/fields-PersoonBeperkt.csv
https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/features/fields-GezagPersoonBeperkt.csv
https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/features/fields-filtered-Persoon.csv
https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/features/fields-filtered-PersoonBeperkt.csv
https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/features/fields-filtered-GezagPersoonBeperkt.csv
)

for url in "${urls[@]}"
do
  echo "Updating $url"
  output="$(basename "$url")"
  curl -f "$url" | grep -v '^pad$' > "$output.tmp"
  mv "$output.tmp" "$output"
done
