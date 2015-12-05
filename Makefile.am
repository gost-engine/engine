AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = libgost.la

SRC = gost_md2012.c gosthash2012.c gost_ec_sign.c gost_ec_keyx.c gost89.c gost_ameth.c gost_asn1.c gost_crypt.c gost_ctl.c gost_eng.c gosthash.c gost_keywrap.c gost_md.c gost_params.c gost_pmeth.c
libgost_la_SOURCES = $(SRC) e_gost_err.c

update:
	@ [ -n "$(OPENSSL_SRCDIR)" ] || (echo "Please set OPENSSL_SRCDIR when configuring to be able to 'make update'"; exit 1)
	cd $(srcdir); perl "$(OPENSSL_SRCDIR)/util/mkerr.pl" -conf gost.ec -nostatic -write $(SRC)
