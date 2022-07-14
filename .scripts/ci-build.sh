#!/bin/sh
# SPDX-FileCopyrightText: 2022 wargio <deroad@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

NGINX_VERSION="$1"
N_CPUS=$(nproc)

if [ -z "$NGINX_VERSION" ]; then
	echo "usage: $0 <nginx version>"
	echo "example: $0 1.12.2"
	exit 1
fi

echo "############################"
echo "   NGINX VERSION: $NGINX_VERSION"
echo "############################"

rm -rf nginx-source nginx-tmp nginx.tar.gz 2>&1 > /dev/null

set -e

wget --no-clobber -O nginx.tar.gz "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
mkdir -p nginx-source nginx-tmp/naxsi_ut/root
tar -C nginx-source -xzf nginx.tar.gz --strip-components=1
rm nginx.tar.gz
export NAXSI_CFG_PATH=$(realpath naxsi_config/)
export NAXSI_SRC_PATH=$(realpath naxsi_src/)
export NAXSI_TMP_PATH=$(realpath nginx-tmp/)
export NAXSI_TST_PATH=$(realpath unit-tests/)
export NGINX_TMP_PATH=$(realpath nginx-source/)
export CFLAGS="-Wextra -Wall" # -Werror"
cd nginx-source
./configure --with-select_module \
            --conf-path="$NAXSI_TMP_PATH/naxsi_ut/nginx.conf" \
            --http-client-body-temp-path="$NAXSI_TMP_PATH/naxsi_ut/body/" \
            --http-fastcgi-temp-path="$NAXSI_TMP_PATH/naxsi_ut/fastcgi/" \
            --http-proxy-temp-path="$NAXSI_TMP_PATH/naxsi_ut/proxy/" \
            --lock-path="$NAXSI_TMP_PATH/nginx.lock" \
            --pid-path="$NAXSI_TMP_PATH/naxsi_ut/nginx.pid" \
            --modules-path="$NAXSI_TMP_PATH/naxsi_ut/modules/" \
            --without-mail_pop3_module \
            --without-mail_smtp_module \
            --without-mail_imap_module \
            --with-http_v2_module \
            --without-http_uwsgi_module \
            --without-http_scgi_module \
            --prefix="$NAXSI_TMP_PATH/" \
            --add-dynamic-module="$NAXSI_SRC_PATH" \
            --error-log-path="$NAXSI_TMP_PATH/naxsi_ut/error.log" \
            --conf-path="$NAXSI_TMP_PATH/naxsi_ut/nginx.conf"
cd ..
make -C "$NGINX_TMP_PATH" -j$N_CPUS install
