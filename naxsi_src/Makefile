VERS	 :=	$(shell grep NAXSI_VERSION naxsi.h | cut -d '"' -f 2)
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
	mkdir ../../naxsi-core-$(VERS)
	mkdir ../../naxsi-ui-$(VERS)	
	cp -R ../naxsi_src ../../naxsi-core-$(VERS)
	cp -R ../naxsi_config ../../naxsi-core-$(VERS)
	cp -R ../contrib/naxsi-ui ../../naxsi-ui-$(VERS)
	cp -R ../t ../../naxsi-core-$(VERS)
	cp ../COPYING ../../naxsi-core-$(VERS)
	cd ../../ ; \
	tar --exclude-vcs -cvzf naxsi-core-$(VERS).tgz naxsi-core-$(VERS)/ ; \
	tar --exclude-vcs -cvzf naxsi-ui-$(VERS).tgz naxsi-ui-$(VERS)/ ; \
	md5sum naxsi-core-$(VERS).tgz > naxsi-core-$(VERS).md5 ; \
	md5sum naxsi-ui-$(VERS).tgz > naxsi-ui-$(VERS).md5 ;

re:
	@echo "Nginx source tree : /tmp/nginx" 
	cd /tmp/nginx && ./configure --with-cc-opt="-O0" --conf-path=/etc/nginx/nginx.conf  --add-module=$(MOD_PATH) --error-log-path=/tmp/error.log     --http-client-body-temp-path=/var/lib/nginx/body     --http-fastcgi-temp-path=/var/lib/nginx/fastcgi     --http-log-path=/var/log/nginx/access.log     --http-proxy-temp-path=/var/lib/nginx/proxy     --lock-path=/var/lock/nginx.lock     --pid-path=/var/run/nginx.pid     --with-http_ssl_module     --without-mail_pop3_module     --without-mail_smtp_module     --without-mail_imap_module     --without-http_uwsgi_module     --without-http_scgi_module     --with-ipv6  --prefix=/usr && make

