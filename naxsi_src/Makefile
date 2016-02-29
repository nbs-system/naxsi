CORE_VERS	:=	$(shell grep NAXSI_VERSION naxsi.h | cut -d '"' -f 2)
MOD_PATH 	:=	$(shell pwd)
CAN		:=
CAK		:=
#1 : LCOV is enabled, and coverage report is generated.
COV 		:= 0
#Allows to force for specific UT only
#TEST 		:= "00*.t"

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
NGINX_OPTIONS+="prefix=/tmp"
NGINX_OPTIONS+="--with-debug"

define NAXSI_CFG=
master_process off;
worker_processes  1;
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
events {
 worker_connections  1024;
}
http {
 include /tmp/naxsi_ut/naxsi_core.rules;
 include       mime.types;
 default_type  application/octet-stream;
 sendfile        on;
 keepalive_timeout  65;
 server {
  listen 4242;
  server_name  localhost;
  location / {
   LearningMode;
   SecRulesEnabled;
   DeniedUrl "/50x.html";
   CheckRule "$$SQL >= 8" BLOCK;
   CheckRule "$$RFI >= 8" BLOCK;
   CheckRule "$$TRAVERSAL >= 4" BLOCK;
   CheckRule "$$EVADE >= 4" BLOCK;
   CheckRule "$$XSS >= 8" BLOCK;
   error_log /tmp/ngx_error.log debug;
   access_log /tmp/ngx_access.log;
   root   html;
   index  index.html index.htm;
  }
  error_page   500 502 503 504  /50x.html;
  location = /50x.html {
   root   html;
  }
 }
}
endef
export NAXSI_CFG

all: re

re: clean nginx_config nginx_build

clean:
	rm -rf /tmp/naxsi_ut/

deploy: deploy_config

deploy_config:
	@echo "$$NAXSI_CFG" > /tmp/naxsi_ut/nginx.conf
	@cp ../naxsi_config/naxsi_core.rules /tmp/naxsi_ut/naxsi_core.rules

nginx_build:
	cd /tmp/nginx && make && make install

# RUN UNIT TESTS
# - generate coverage report if option is on
test:
	if [ $(COV) -eq 1 ] ; then lcov --directory /tmp/nginx --zerocounters ; fi

	if [ ! $(TEST) ] ; then TEST="*.t" ; fi

	export PATH="/tmp/nginx/objs/:"$(PATH) ; \
	export PERL5LIB=/usr/local/share/perl/5.14.2/ ; \
	cd .. ; prove -r "t/$(TEST)"

	if [ $(COV) -eq 1 ] ; then \
	lcov --directory /tmp/nginx/objs/addon/naxsi_src/ --capture \
	--output-file naxsi.info --base-directory /tmp/nginx ; \
	genhtml -s -o /tmp/naxsicov.html naxsi.info ; fi

nginx_config:
	@if [ $(COV) -eq 1 ] ; then \
	echo "[Enabling CODE COVERAGE]" ; \
	CC_OPT="--coverage -g3" ; \
	LD_OPT="-lgcov" ; \
	else CC_OPT="" ; \
	LD_OPT="" ; fi ; \
	cd /tmp/nginx ; \
	echo "CC_OPT: $$CC_OPT / LD_OPT: $$LD_OPT" ; \
	./configure --with-cc-opt="$$CC_OPT" --with-ld-opt="$$LD_OPT" $(NGINX_OPTIONS)

#Build for coverity and submit build !
coverity: 
	@CAK=$(shell cat ../../coverity.key | cut -d ':' -f2) ; \
	CAN=$(shell cat ../../coverity.key | cut -d ':' -f1) ; \
	echo "Coverity token/login : $$CAK and $$CAN"; \
	wget -nc  https://scan.coverity.com/download/linux-64 --post-data "token=$$CAK&project=nbs-system%2Fnaxsi" -O /tmp/coverity.tgz ; \
	mkdir /tmp/cov && cd /tmp/cov && cat ../coverity.tgz  | tar --strip-components=1 -xvzf - ; \
	cd /tmp/nginx ; \
	./configure $(NGINX_OPTIONS) && \
	/tmp/cov/bin/cov-build --dir cov-int make && \
	tar cvzf coverity-res-naxsi.tgz cov-int/ ; \
	curl --form token="$$CAK" \
	  --form email="$$CAN" \
	  --form file=@/tmp/nginx/coverity-res-naxsi.tgz \
	  --form version="$(CORE_VERS)" \
	  --form description="Automatically submitted" \
	  https://scan.coverity.com/builds?project=nbs-system%2Fnaxsi
