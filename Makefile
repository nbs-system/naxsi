VERS	:=	$(shell grep NAXSI_VERSION naxsi.h | cut -d '"' -f 2)

unit_test:
	export PERL5LIB=/usr/local/share/perl/5.12.4/ ; \
	export PATH=$(PATH):/usr/sbin/ ; \
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
