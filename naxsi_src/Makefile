CORE_VERS	:=	$(shell grep NAXSI_VERSION naxsi.h | cut -d '"' -f 2)
MOD_PATH 	:=	$(shell pwd)
TMP_DIR		:=	/tmp/nginx/

# Keys for coverity
CAN		:=
CAK		:=

#Mode: coverage, fuzz, or base
COV 		?= 0
FUZZ		?= 0
STOCK		?= 1

#Allows to force for specific UT only
#TEST		:= ""
NGINX_VERS	:= "1.19.2"


NGINX_OPTIONS="--with-select_module"
NGINX_OPTIONS+="--conf-path=/tmp/naxsi_ut/nginx.conf"
NGINX_OPTIONS+="--http-client-body-temp-path=/tmp/naxsi_ut/body/"
NGINX_OPTIONS+="--http-fastcgi-temp-path=/tmp/naxsi_ut/fastcgi/"
NGINX_OPTIONS+="--http-proxy-temp-path=/tmp/naxsi_ut/proxy/"
NGINX_OPTIONS+="--lock-path=/tmpnginx.lock"
NGINX_OPTIONS+="--pid-path=/tmp/naxsi_ut/nginx.pid"
NGINX_OPTIONS+="--modules-path=/tmp/naxsi_ut/modules/"
NGINX_OPTIONS+="--without-mail_pop3_module"
NGINX_OPTIONS+="--without-mail_smtp_module"
NGINX_OPTIONS+="--without-mail_imap_module"
NGINX_OPTIONS+="--with-http_v2_module"
NGINX_OPTIONS+="--without-http_uwsgi_module"
NGINX_OPTIONS+="--without-http_scgi_module"
NGINX_OPTIONS+="--prefix=/tmp"
#for coverity NGINX_OPTIONS+="--with-cc=/usr/bin/gcc-6"	
#for coverity NGINX_OPTIONS+="--add-dynamic-module=$(MOD_PATH)"

CFLAGS:="-Wextra -Wall -Werror"

all: nginx_download configure build install deploy

re: clean all test

format_code:
	clang-format --verbose -i $(MOD_PATH)/*.c

FUZZ_PATH := "../fuzz"
AFL_PATH  := $(PWD)"/"$(FUZZ_PATH)"/afl/"

install_afl:
	mkdir -p $(FUZZ_PATH)
	cd $(FUZZ_PATH) && (wget -nc --no-clobber  "http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz" || exit 1)
	cd $(FUZZ_PATH) && (test -d $(AFL_PATH) || (mkdir $(FUZZ_PATH)"/afl" && tar -C $(AFL_PATH)/ -xzf afl-latest.tgz  --strip-components=1))
	cd $(FUZZ_PATH) && (make -C $(AFL_PATH) && make -C $(AFL_PATH)"/llvm_mode" clean  all afl-clang-fast)

install_preeny:
	cd $(FUZZ_PATH) && (test -d preeny || git clone https://github.com/zardus/preeny.git)
	cd $(FUZZ_PATH) && make -C preeny/src/

fuzz_build: install_afl install_preeny
	mkdir -p $(FUZZ_PATH)
	STOCK=0	FUZZ=1 make nginx_download
	cd $(TMP_DIR) && patch -p1 "./src/core/ngx_cycle.c"  < $(MOD_PATH)"/../t/confs/ngx_cycle.patch"
	cd $(TMP_DIR) && patch -p1 "./src/os/unix/ngx_process_cycle.c"  < $(MOD_PATH)"/../t/confs/ngx_process_cycle.patch"
	STOCK=0 FUZZ=1 make configure build install deploy

fuzz:
	LD_PRELOAD=$(FUZZ_PATH)"/preeny/src/desock.so" $(AFL_PATH)"afl-fuzz" -t 10  -i  "../t/fuzz/" -o $(FUZZ_PATH)/findings $(TMP_DIR)/objs/nginx

clean:
	rm -f "nginx-"$(NGINX_VERS)".tar.gz"
	rm -f "nginx-"$(NGINX_VERS)".tar.gz.asc"
	rm -rf /tmp/naxsi_ut/
	rm -rf $(TMP_DIR)/
	rm -rf $(FUZZ_PATH)/

nginx_download:
	wget --no-clobber "http://nginx.org/download/nginx-"$(NGINX_VERS)".tar.gz" || exit 1
	wget --no-clobber "http://nginx.org/download/nginx-"$(NGINX_VERS)".tar.gz.asc" || exit 1
#	gpg --keyserver pgp.key-server.io --recv-keys 0x251a28de2685aed4 0x520A9993A1C052F8
#	gpg --verify "nginx-"$(NGINX_VERS)".tar.gz.asc" "nginx-"$(NGINX_VERS)".tar.gz" || exit 1
	mkdir -p $(TMP_DIR)/
	tar -C $(TMP_DIR)/ -xzf nginx-$(NGINX_VERS).tar.gz  --strip-components=1

configure:
#build non dynamic module (faster) for fuzz/afl
ifeq ($(FUZZ),1)
	cd $(TMP_DIR)/ && AFL_PATH=$(AFL_PATH) ./configure --with-cc=$(AFL_PATH)"/llvm_mode/afl-clang-fast" --with-cc-opt="-O3" $(NGINX_OPTIONS) --add-module=$(MOD_PATH)  --error-log-path=/dev/null --http-log-path=/dev/null
endif

ifeq ($(COV),1)
	cd $(TMP_DIR)/ && ./configure --with-cc-opt="--coverage -g3 -gstabs" --with-ld-opt="-lgcov" $(NGINX_OPTIONS) --add-dynamic-module=$(MOD_PATH) --error-log-path=/tmp/naxsi_ut/error.log --conf-path=/tmp/naxsi_ut/nginx.conf
endif

ifeq ($(STOCK),1)
	cd $(TMP_DIR)/ && ./configure --with-cc-opt="-g3 -ggdb" $(NGINX_OPTIONS) --add-dynamic-module=$(MOD_PATH) --error-log-path=/tmp/naxsi_ut/error.log --conf-path=/tmp/naxsi_ut/nginx.conf
endif


build:
	AFL_PATH=$(AFL_PATH) make -C $(TMP_DIR)
	if [ -d "/tmp/naxsi_ut" ] && [ -f $(TMP_DIR)/objs/ngx_http_naxsi_module.so ] ; then  cp $(TMP_DIR)/objs/ngx_http_naxsi_module.so /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so ; fi

install:
	make -C $(TMP_DIR) install

deploy:
ifeq ($(FUZZ),1)
	@cp ../t/confs/nginx_fuzz.conf.example /tmp/naxsi_ut/nginx.conf
else
	@cp ../t/confs/nginx.conf.example /tmp/naxsi_ut/nginx.conf
endif
	@cp ../naxsi_config/naxsi_core.rules /tmp/naxsi_ut/naxsi_core.rules
	@openssl req -batch -x509 -nodes -days 365 -newkey rsa:2048 -keyout /tmp/nginx.key -out /tmp/nginx.crt


# RUN UNIT TESTS
test:
ifeq ($(COV),1)
	lcov --directory $(TMP_DIR) --zerocounters
endif
	if [ ! $(TEST) ] ; then TEST="*.t" ; fi
	export PATH="$(TMP_DIR)/objs/:"$(PATH) ; \
	export PERL5LIB="~/perl5/lib/perl5/" ;\
	cd .. ; prove -r "t/$(TEST)"
ifeq ($(COV),1)
	lcov --directory $(TMP_DIR)/objs/addon/naxsi_src/ --capture --output-file naxsi.info --base-directory $(TMP_DIR)
	genhtml -s -o /tmp/naxsicov.html naxsi.info
endif

#Build for coverity and submit build !
#Remember to enforce gcc-6 when doing so, coverity doesn't support gcc-7 or gcc-8
coverity: nginx_download
	@CAK=$(shell cat ../../coverity.key | cut -d ':' -f2) ; \
	CAN=$(shell cat ../../coverity.key | cut -d ':' -f1) ; \
	echo "Coverity token/login : $$CAK and $$CAN"; \
	wget -nc  https://scan.coverity.com/download/cxx/linux64 --post-data "token=$$CAK&project=nbs-system%2Fnaxsi" -O /tmp/coverity.tgz ; \
	if ! [ -d /tmp/cov ] ; then \
		mkdir -p /tmp/cov && \
		cd /tmp/cov && \
		cat ../coverity.tgz  | tar --strip-components=2 -xvzf - && \
		/tmp/cov/bin/cov-configure  --comptype gcc --compiler gcc-6 --template ; \
	fi ; \
	cd $(TMP_DIR) ; \
	./configure $(NGINX_OPTIONS) && \
	/tmp/cov/bin/cov-build --dir cov-int make -j4 && \
	tar cvzf coverity-res-naxsi.tgz cov-int/ ; \
	curl --form token="$$CAK" \
	  --form email="$$CAN" \
	  --form file=@$(TMP_DIR)/coverity-res-naxsi.tgz \
	  --form version="$(CORE_VERS)" \
	  --form description="Automatically submitted" \
	  https://scan.coverity.com/builds?project=nbs-system%2Fnaxsi
