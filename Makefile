.SUFFIXES : .x .o .c .s


LIGHTTPD_SUBDIRS=lighttpd-1.4.39
ETH2UART_SUBDIRS=demos/eth2uart
CGI_SUBDIRS=demos/eth2uart/lighttpd/www/cgi-bin

define make_eth2uart
	@for subdir in $(ETH2UART_SUBDIRS) ; do \
		( cd $$subdir && make $1) || exit 1; \
	done;

	@for subdir in $(CGI_SUBDIRS) ; do \
		( cd $$subdir && arm-linux-gcc uart.c -o uart.cgi; \
		  arm-linux-gcc uart2.c -o uart2.cgi; \
		)\
	done;

	@for subdir in $(LIGHTTPD_SUBDIRS) ; do \
		( cd $$subdir && ./configure --host arm-linux --build pentium-pc-linux --without-zlib --without-bzip2 --without-pcre --target arm-linux && autoreconf --install --verbose --force && make) || exit 1; \
	done;

	cp $(ETH2UART_SUBDIRS)/eth2uart ../rootfs
	mkdir ../rootfs/usr/local/sbin -p
	mkdir ../rootfs/usr/local/lib -p
	cp $(LIGHTTPD_SUBDIRS)/src/lighttpd ../rootfs/usr/local/sbin/arm-linux-lighttpd
	cp $(LIGHTTPD_SUBDIRS)/src/lighttpd-angel ../rootfs/usr/local/sbin/arm-linux-lighttpd-angel
	cp $(LIGHTTPD_SUBDIRS)/src/.libs/mod_*.la ../rootfs/usr/local/lib/
	cp $(LIGHTTPD_SUBDIRS)/src/.libs/mod_*.so ../rootfs/usr/local/lib/
	cp $(LIGHTTPD_SUBDIRS)/config_html_sample/lighttpd.conf ../rootfs/usr/local/sbin/
	cp $(ETH2UART_SUBDIRS)/lighttpd/www ../rootfs/usr/local/sbin/ -R
	cp $(ETH2UART_SUBDIRS)/lighttpd/log ../rootfs/var/ -R
	cp $(ETH2UART_SUBDIRS)/lighttpd/rcS ../rootfs/etc/init.d/ -r

endef

eth2uart:
	$(call make_eth2uart , all)


