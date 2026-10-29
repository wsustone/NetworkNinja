#!/usr/bin/env bash
# Run the workspace tests. On failure, surface the failing tests and their
# panic messages as a GitHub annotation, so they are readable from the
# checks API without downloading the full log.
set -o pipefail
if cargo test --workspace "$@" 2>&1 | tee test.log; then
  exit 0
fi
summary=$(grep -E "^---- |panicked at|^thread '|assertion|left:|right:|^test .* FAILED|error\[|^error:" test.log | head -60)
summary=${summary//'%'/'%25'}
summary=${summary//$'\r'/}
summary=${summary//$'\n'/'%0A'}
echo "::error title=Test failures ($RUNNER_OS $*)::${summary}"
exit 1
