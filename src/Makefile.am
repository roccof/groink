bin_PROGRAMS = groink

groink_SOURCES =				\
		base.c				\
		debug.c				\
		main.c

noinst_HEADERS =				\
		base.h				\
		debug.h

groink_CFLAGS = $(LUA_CFLAGS)
groink_LDADD = $(LUA_LIBS)

CLEANFILES = *~ protocols/*~