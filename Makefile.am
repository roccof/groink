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
	selib/script_engine.lua	\
	selib/dump.lua		\
	selib/oui_db.txt        \
	selib/ouidb.lua         \
	selib/util.lua          \
	selib/base64.lua	\
	selib/dissector.lua	\
	selib/http.lua		\
	selib/urllib.lua

scriptsdir = $(pkgdatadir)/scripts
scripts_DATA = 			\
	scripts/default.lua 	\
	scripts/dump.lua	\
	scripts/show.lua	\
	scripts/isolate.lua	\
	scripts/scripts.db

CLEANFILES = *.out *~
