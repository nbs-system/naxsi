#!/bin/sh
# SPDX-FileCopyrightText: 2022 wargio <deroad@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only
set -e

N_DEBUGS=$(cat naxsi_src/naxsi.h | grep "#define _debug" | grep 1 | wc -l)
if [ $N_DEBUGS -gt 0 ]; then
    cat naxsi_src/naxsi.h | grep "#define _debug" | grep 1
    exit 1
fi
