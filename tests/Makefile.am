
AM_COLOR_TESTS=always

GEN_CFLAGS = -I$(top_builddir)/src $(LUA_CFLAGS)
GEN_LDADD = $(LUA_LIBS)
GEN_SRC = `find ../src -name "*.c"`

check_PROGRAMS = netutil_test
TESTS = $(check_PROGRAMS)

# Test1: netutil
netutil_test_SOURCES = netutil_test.c $(GEN_SRC)
netutil_test_CFLAGS = $(GEN_CFLAGS)
netutil_test_LDADD = $(GEN_LDADD)
#netutil_test_DEPENDENCIES = ../src/*.c

CLEANFILES = $(TESTS) *.o *~
