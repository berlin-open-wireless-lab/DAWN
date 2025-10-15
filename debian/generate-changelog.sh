#!/bin/sh

cd "$(dirname "$0")/.."

COMMIT_DATE=$(git log -1 --format='%cd' --date=format:'%Y%m%d' 2>/dev/null || echo '00000000')
COMMIT_HASH=$(git log -1 --format='%h' 2>/dev/null || echo 'unknown')
COMMIT_TIMESTAMP=$(git log -1 --format='%cd' --date=rfc2822 2>/dev/null || date -R)

cat > debian/changelog <<EOF
dawn (0.0.${COMMIT_DATE}) unstable; urgency=medium

  * Latest version (${COMMIT_HASH})

 -- Russ Dill <russ.dill@gmail.com>  ${COMMIT_TIMESTAMP}
EOF
