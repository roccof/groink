SUBDIRS = src

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = 
	AUTHORS		\
	COPYING		\
	INSTALL		\
	TODO		\
	README		\
	NEWS		\
	ChangeLog

selibdir = $(pkgdatadir)/selib
selib_DATA = 			\
	selib/oui_db.txt 	\
	selib/core.luadoc	\
	selib/bit.luadoc	\
	selib/script_engine.lua	\
	selib/dump.lua		\
	selib/netutil.luadoc	\
	selib/ouidb.lua

scriptsdir = $(pkgdatadir)/scripts
scripts_DATA = 			\
	scripts/default.lua 	\
	scripts/dump.lua	\
# 	scripts/isolate.lua 	\
#	scripts/show.lua	\
#	scripts/scripts.db

CLEANFILES = *.out *~
