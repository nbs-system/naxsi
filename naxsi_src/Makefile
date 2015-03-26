CORE_VERS	 :=	$(shell grep NAXSI_VERSION naxsi.h | cut -d '"' -f 2)
UTIL_VERS :=	$(shell grep version ../nx_util/setup.py | cut -d "'" -f2)
MOD_PATH :=	$(shell pwd)
#Enables lcov for unit test code coverage
COV := 1
#TEST := "23*.t"
build:
	@if test -d /tmp/nginx ; then \
		cd /tmp/nginx && make; \
	else \
		echo "nginx source tree must be in /tmp/nginx"; \
	fi


test:
	@if [ $(COV) -eq 1 ] ; then  \
	echo "[!] BUILDING WITH -LGCOV" ; \
	lcov --directory /tmp/nginx --zerocounters ; fi
	@export PATH="/tmp/nginx/objs/:"$(PATH) ; \
	export PERL5LIB=/usr/local/share/perl/5.14.2/ ; \
	cd .. ; echo "-->" $(TEST) ; \
	if [ $(TEST) ] ; then prove -r "t/$(TEST)" ; else \
	prove -r t/*.t ; fi
	@if [ $(COV) -eq 1 ] ; then \
	lcov --directory /tmp/nginx/objs/addon/naxsi_src/ --capture --output-file naxsi.info --base-directory /tmp/nginx ; \
	genhtml -s -o /tmp/naxsicov.html naxsi.info ; \
	echo "Coverage report is in /tmp/naxsicov.html" ; fi

re:
	@echo "Nginx source tree : /tmp/nginx" 
	@if [ $(COV) -eq 1 ] ; then echo "[!] BUILDING WITH -LGCOV" ; \
	cd /tmp/nginx && ./configure --with-cc-opt="--coverage" --with-ld-opt=-lgcov  --conf-path=/tmp/naxsi_ut/nginx.conf  --add-module=$(MOD_PATH) --error-log-path=/tmp/naxsi_ut/error.log     --http-client-body-temp-path=/tmp/naxsi_ut/body/     --http-fastcgi-temp-path=/tmp/naxsi_ut/fastcgi/     --http-log-path=/tmp/naxsi_ut/access.log     --http-proxy-temp-path=/tmp/naxsi_ut/proxy/     --lock-path=/tmpnginx.lock     --pid-path=/tmp/naxsi_ut/nginx.pid     --with-http_ssl_module     --without-mail_pop3_module     --without-mail_smtp_module     --without-mail_imap_module     --without-http_uwsgi_module     --without-http_scgi_module     --with-ipv6  --prefix=/tmp --with-debug && make \
	; else cd /tmp/nginx && ./configure --with-cc-opt="--O0" --with-ld-opt=-lgcov  --conf-path=/tmp/naxsi_ut/nginx.conf  --add-module=$(MOD_PATH) --error-log-path=/tmp/naxsi_ut/error.log     --http-client-body-temp-path=/tmp/naxsi_ut/body/     --http-fastcgi-temp-path=/tmp/naxsi_ut/fastcgi/     --http-log-path=/tmp/naxsi_ut/access.log     --http-proxy-temp-path=/tmp/naxsi_ut/proxy/     --lock-path=/tmpnginx.lock     --pid-path=/tmp/naxsi_ut/nginx.pid     --with-http_ssl_module     --without-mail_pop3_module     --without-mail_smtp_module     --without-mail_imap_module     --without-http_uwsgi_module     --without-http_scgi_module     --with-ipv6  --prefix=/tmp --with-debug && make ; fi



deploy:
	@cd /tmp/nginx && make install
	@cat /tmp/naxsi_ut/nginx.conf | grep -v '#' | sed -e 's@http {@http {\ninclude /etc/nginx/naxsi_core.rules;\n@' | sed -e 's@listen.*80;@listen 4242;@' | sed '1i\master_process off;' > /tmp/naxsi_ut/nginx.conf.tmp
	@cat /tmp/naxsi_ut/nginx.conf.tmp | sed  's@location / {@location / {\nLearningMode;\nSecRulesEnabled;\nDeniedUrl "/50x.html";\nCheckRule "$$SQL >= 8" BLOCK;\nCheckRule "$$RFI >= 8" BLOCK;\nCheckRule "$$TRAVERSAL >= 4" BLOCK;\nCheckRule "$$EVADE >= 4" BLOCK;\nCheckRule "$$XSS >= 8" BLOCK;\nerror_log /tmp/ngx_error.log debug;\naccess_log /tmp/ngx_access.log;\n@'  > /tmp/naxsi_ut/nginx.conf
	@mkdir -p /tmp/naxsi_ut/body/ /tmp/naxsi_ut/fastcgi/ /tmp/naxsi_ut/proxy/ 

