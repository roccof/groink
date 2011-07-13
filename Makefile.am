SUBDIRS = src tests

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
	scripts/show.lua	\
	scripts/isolate.lua	\
	scripts/scripts.db

datadir = $(pkgdatadir)/data
data_DATA =			\
	data/oui_db.txt

CLEANFILES = *.out *~
