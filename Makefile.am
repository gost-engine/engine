enginedir=@ENGINEDIR@
PERL=@PERL@
AM_CPPFLAGS=@AM_CPPFLAGS@
srcdir=.
lib_LTLIBRARIES=libgost.la
libgost_enginedir=$(enginedir)
libgost_la_includedir=$(includedir)/openssl
libgost_la_include_HEADERS=e_gost_err.h gost89.h gosthash2012_const.h gosthash2012.h gosthash2012_precalc.h gosthash2012_ref.h gosthash2012_sse2.h gosthash.h gost_keywrap.h gost_lcl.h newnids.h
libgost_la_SOURCES=e_gost_err.c gost89.c gost_ameth.c gost_asn1.c gost_crypt.c gost_ctl.c gost_ec_keyx.c gost_ec_sign.c gost_eng.c gosthash2012.c gosthash.c gost_keywrap.c gost_md2012.c gost_md.c gost_params.c gost_pmeth.c  newnids.c obj_create.c

.PHONY: test

install-data-hook:
	rm -f $(DESTDIR)$(enginedir)/*.a $(DESTDIR)$(enginedir)/*.la

newnids.c newnids.h: mkobj.pl gost_obj.txt
	$(PERL) mkobj.pl

test:
	$(MAKE) -C test test
