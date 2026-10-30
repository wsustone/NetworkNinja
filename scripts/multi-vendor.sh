#!/usr/bin/env bash
# A multi-vendor exercise (ADR 0010): one nn-generator process per vendor
# profile, each with its own sockets, sites and application number, all
# sending to one nn-server. A clean run must raise no alerts.
#
#   scripts/multi-vendor.sh [TARGET] [DURATION] [-- extra generator flags]
#
# Vendor p (0-3) runs sites 2p+1..2p+2 as application p+1:
#   standard  sites 1-2  app 1      legacy   sites 3-4  app 2
#   body-axis sites 5-6  app 3      gateway  sites 7-8  app 4
# Extra flags go to every generator, e.g. `-- --all-types 5`. To inject a
# fault, run one more generator by hand on its own range, e.g.
#   nn-generator --site-base 9 --application 5 --sites 1 --all-defects
set -euo pipefail

target=${1:-127.0.0.1:3000}
duration=${2:-300}
shift $(( $# >= 2 ? 2 : $# ))
[[ ${1:-} == -- ]] && shift
bin=${NN_GENERATOR:-$(dirname "$0")/../target/release/nn-generator}

pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' INT TERM
p=0
for profile in standard legacy body-axis gateway; do
    "$bin" --profile "$profile" --target "$target" --duration "$duration" \
        --site-base $((2 * p + 1)) --sites 2 --application $((p + 1)) \
        --seed $((11 + p)) --fire-every 10 --truth /dev/null "$@" \
        2> >(sed "s/^/[$profile] /" >&2) &
    pids+=($!)
    p=$((p + 1))
done
echo "4 vendors sending to $target for ${duration}s (pids ${pids[*]})" >&2
wait
