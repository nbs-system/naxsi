CORE_VERS	:=	$(shell grep NAXSI_VERSION naxsi.h | cut -d '"' -f 2)
MOD_PATH 	:=	$(shell pwd)
TMP_DIR     := /tmp/nginx/

# Keys for coverity
CAN		:=
CAK		:=

#Set to 1 if you want coverage report
COV 		:= 0

#Allows to force for specific UT only
#TEST 		:= "00*.t"
NGINX_VERS := "1.9.11"

NGINX_OPTIONS="--error-log-path=/tmp/naxsi_ut/error.log"
NGINX_OPTIONS+="--conf-path=/tmp/naxsi_ut/nginx.conf"
NGINX_OPTIONS+="--http-client-body-temp-path=/tmp/naxsi_ut/body/"
NGINX_OPTIONS+="--http-fastcgi-temp-path=/tmp/naxsi_ut/fastcgi/"
NGINX_OPTIONS+="--http-log-path=/tmp/naxsi_ut/access.log"
NGINX_OPTIONS+="--http-proxy-temp-path=/tmp/naxsi_ut/proxy/"
NGINX_OPTIONS+="--lock-path=/tmpnginx.lock"
NGINX_OPTIONS+="--pid-path=/tmp/naxsi_ut/nginx.pid"
NGINX_OPTIONS+="--modules-path=/tmp/naxsi_ut/modules/"
NGINX_OPTIONS+="--with-http_ssl_module"
NGINX_OPTIONS+="--without-mail_pop3_module"
NGINX_OPTIONS+="--without-mail_smtp_module"
NGINX_OPTIONS+="--without-mail_imap_module"
NGINX_OPTIONS+="--without-http_uwsgi_module"
NGINX_OPTIONS+="--without-http_scgi_module"
NGINX_OPTIONS+="--add-dynamic-module=$(MOD_PATH)"
NGINX_OPTIONS+="--with-ipv6"
NGINX_OPTIONS+="--prefix=/tmp"
NGINX_OPTIONS+="--with-debug"


all: nginx_download configure build install deploy

re: clean all test

clean:
	rm -f "nginx-"$(NGINX_VERS)".tar.gz"
	rm -f "nginx-"$(NGINX_VERS)".tar.gz.asc"
	rm -rf /tmp/naxsi_ut/
	rm -rf $(TMP_DIR)/

nginx_download:
	wget --no-clobber "http://nginx.org/download/nginx-"$(NGINX_VERS)".tar.gz" || exit 1
	wget --no-clobber "http://nginx.org/download/nginx-"$(NGINX_VERS)".tar.gz.asc" || exit 1
	gpg --keyserver pgp.mit.edu --recv-keys 0x251a28de2685aed4 0x520A9993A1C052F8
	gpg --verify "nginx-"$(NGINX_VERS)".tar.gz.asc" "nginx-"$(NGINX_VERS)".tar.gz" || exit 1
	mkdir -p $(TMP_DIR)/
	tar -C $(TMP_DIR)/ -xvzf nginx-$(NGINX_VERS).tar.gz  --strip-components=1

configure:
ifeq ($(COV),1)
	cd $(TMP_DIR)/ && ./configure --with-cc-opt="--coverage -g3" --with-ld-opt="-lgcov" $(NGINX_OPTIONS)
else
	cd $(TMP_DIR)/ && ./configure $(NGINX_OPTIONS)
endif

build:
	cd $(TMP_DIR)/ && make

install:
	cd $(TMP_DIR)/ && make install

deploy: 
	@cp ./nginx.conf.example /tmp/naxsi_ut/nginx.conf
	@cp ../naxsi_config/naxsi_core.rules /tmp/naxsi_ut/naxsi_core.rules


# RUN UNIT TESTS
test:
ifeq ($(COV),1)
	lcov --directory $(TMP_DIR) --zerocounters
endif

	if [ ! $(TEST) ] ; then TEST="*.t" ; fi

	export PATH="$(TMP_DIR)/objs/:"$(PATH) ; \
	export PERL5LIB=/usr/local/share/perl/5.14.2/ ; \
	cd .. ; prove -r "t/$(TEST)"

ifeq ($(COV),1)
	lcov --directory $(TMP_DIR)/objs/addon/naxsi_src/ --capture --output-file naxsi.info --base-directory $(TMP_DIR)
	genhtml -s -o /tmp/naxsicov.html naxsi.info
endif

#Build for coverity and submit build !
coverity: 
	@CAK=$(shell cat ../../coverity.key | cut -d ':' -f2) ; \
	CAN=$(shell cat ../../coverity.key | cut -d ':' -f1) ; \
	echo "Coverity token/login : $$CAK and $$CAN"; \
	wget -nc  https://scan.coverity.com/download/linux-64 --post-data "token=$$CAK&project=nbs-system%2Fnaxsi" -O /tmp/coverity.tgz ; \
	mkdir /tmp/cov && cd /tmp/cov && cat ../coverity.tgz  | tar --strip-components=1 -xvzf - ; \
	cd $(TMP_DIR) ; \
	./configure $(NGINX_OPTIONS) && \
	/tmp/cov/bin/cov-build --dir cov-int make && \
	tar cvzf coverity-res-naxsi.tgz cov-int/ ; \
	curl --form token="$$CAK" \
	  --form email="$$CAN" \
	  --form file=@$(TMP_DIR)/coverity-res-naxsi.tgz \
	  --form version="$(CORE_VERS)" \
	  --form description="Automatically submitted" \
	  https://scan.coverity.com/builds?project=nbs-system%2Fnaxsi
