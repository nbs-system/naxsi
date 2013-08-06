CORE_VERS	 :=	$(shell grep NAXSI_VERSION naxsi.h | cut -d '"' -f 2)
UTIL_VERS :=	$(shell grep version ../nx_util/setup.py | cut -d "'" -f2)
MOD_PATH :=	$(shell pwd)

build:
	@if test -d /tmp/nginx ; then \
		cd /tmp/nginx && make; \
	else \
		echo "nginx source tree must be in /tmp/nginx"; \
	fi
# run unit tests
test:
	export PATH="/tmp/nginx/objs/:"$(PATH) ; \
	export PERL5LIB=/usr/local/share/perl/5.12.4/ ; \
	cd .. ; \
	prove -r t/*.t

package: 
	mkdir ../../naxsi-core-$(CORE_VERS)
	mkdir ../../nx_util-$(UTIL_VERS)	
	cp -R ../naxsi_src ../../naxsi-core-$(CORE_VERS)
	cp -R ../naxsi_config ../../naxsi-core-$(CORE_VERS)
	cp -R ../nx_util ../../nx_util-$(UTIL_VERS)
	cp -R ../t ../../naxsi-core-$(CORE_VERS)
	cp ../COPYING ../../naxsi-core-$(CORE_VERS)
	cd ../../ ; \
	tar --exclude-vcs -cvzf naxsi-core-$(CORE_VERS).tgz naxsi-core-$(CORE_VERS)/ ; \
	tar --exclude-vcs -cvzf nx_util-$(UTIL_VERS).tgz nx_util-$(UTIL_VERS)/ ; \
	rm -rf ../../naxsi-core-$(CORE_VERS)/ ; \
	rm -rf ../../nx_util-$(UTIL_VERS)/ ; \
	md5sum naxsi-core-$(CORE_VERS).tgz > naxsi-core-$(CORE_VERS).md5 ; \
	md5sum nx_util-$(UTIL_VERS).tgz > nx_util-$(UTIL_VERS).md5 ;



re:
	@echo "Nginx source tree : /tmp/nginx" 
	cd /tmp/nginx && ./configure --with-cc-opt="-O0" --conf-path=/tmp/nginx.conf  --add-module=$(MOD_PATH) --error-log-path=/tmp/error.log     --http-client-body-temp-path=/tmp/     --http-fastcgi-temp-path=/var/lib/nginx/fastcgi     --http-log-path=/tmp/access.log     --http-proxy-temp-path=/var/lib/nginx/proxy     --lock-path=/tmpnginx.lock     --pid-path=/tmp/nginx.pid     --with-http_ssl_module     --without-mail_pop3_module     --without-mail_smtp_module     --without-mail_imap_module     --without-http_uwsgi_module     --without-http_scgi_module     --with-ipv6  --prefix=/tmp && make


debug :
	@gdb /tmp/nginx/objs/nginx  `ps -o "%p" -u www-data  | tail -n1`

deploy:
	cd /tmp/nginx && make install
	@cat /tmp/nginx.conf | grep -v '#' | sed -e 's@http {@http {\ninclude /etc/nginx/naxsi_core.rules;\n@' | sed -e 's@listen.*80;@listen 4242;@' > /tmp/nginx.conf.tmp
	@cat /tmp/nginx.conf.tmp | sed  's@location / {@location / {\nLearningMode;\nSecRulesEnabled;\nDeniedUrl "/50x.html";\nCheckRule "$$SQL >= 8" BLOCK;\nCheckRule "$$RFI >= 8" BLOCK;\nCheckRule "$$TRAVERSAL >= 4" BLOCK;\nCheckRule "$$EVADE >= 4" BLOCK;\nCheckRule "$$XSS >= 8" BLOCK;\nerror_log /tmp/ngx_error.log debug;\naccess_log /tmp/ngx_access.log;\n@'  > /tmp/nginx.conf
#	@cat /tmp/nginx.conf | 

