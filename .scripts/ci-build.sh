#!/bin/sh
# SPDX-FileCopyrightText: 2022 wargio <deroad@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only
set -e

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

NEW_BUILD=true
if [ -d "nginx-tmp" ] && [ "$NGINX_VERSION" == $(cat nginx-tmp/nginx.version) ]; then
    NEW_BUILD=false
fi

if $NEW_BUILD ; then
    rm -rf nginx-source nginx-tmp nginx.tar.gz 2>&1 > /dev/null
    wget --no-clobber -O nginx.tar.gz "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
    mkdir -p nginx-source nginx-tmp/naxsi_ut/root
    echo "$NGINX_VERSION" > nginx-tmp/nginx.version
    tar -C nginx-source -xzf nginx.tar.gz --strip-components=1
    rm nginx.tar.gz
fi

export NAXSI_SRC_PATH=$(realpath naxsi_src/)
export NAXSI_TMP_PATH=$(realpath nginx-tmp/)
export NGINX_TMP_PATH=$(realpath nginx-source/)

if $NEW_BUILD ; then
    cd "$NGINX_TMP_PATH"
    ./configure --with-cc-opt='-g -O2 -Wextra -Wall -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2' \
                --with-ld-opt='-Wl,-z,relro -Wl,-z,now -fPIC' \
                --with-select_module \
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
fi

make -C "$NGINX_TMP_PATH" -j$N_CPUS install
