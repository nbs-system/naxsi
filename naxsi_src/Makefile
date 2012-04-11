VERS	:=	$(shell grep NAXSI_VERSION naxsi.h | cut -d '"' -f 2)

unit_test:
	export PERL5LIB=/usr/local/share/perl/5.12.4/ ; \
	export PATH=$(PATH):/usr/sbin/ ; \
	cd .. ; \
	prove -r t/*.t

package: 
	mkdir ../../naxsi-$(VERS)
	cp -R ../naxsi_src ../../naxsi-$(VERS)
	cp -R ../naxsi_config ../../naxsi-$(VERS)
	cp -R ../contrib ../../naxsi-$(VERS)
	cp -R ../t ../../naxsi-$(VERS)
	cp ../COPYING ../../naxsi-$(VERS)
	cp ../README.txt ../../naxsi-$(VERS)
	cd ../../ ; \
	tar --exclude-vcs -cvzf naxsi-$(VERS).tgz naxsi-$(VERS)/ ; \
	md5sum naxsi-$(VERS).tgz > naxsi-$(VERS).md5 ;
