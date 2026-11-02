#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# The image carries the listener CA trust chain named by tlsCa from build time.
# Unless TLS_CA_REFRESH=0, refresh it from iya-sts first; a failed refresh keeps
# the built-in file. Then start the demo.
if [ "${TLS_CA_REFRESH:-1}" != 0 ]; then
  python3 /app/scripts/trust_chain.py --config "${OIDC_CONFIG:-/app/demo/oidc.json}" || true
fi
exec "$@"
