bin_PROGRAMS = groink

groink_SOURCES =				\
		base.c				\
		debug.c				\
		globals.c			\
		list.c				\
		main.c				\
		packet.c			\
		rp_queue.c			\
		threads.c

noinst_HEADERS =				\
		base.h				\
		debug.h				\
		globals.h			\
		list.h				\
		packet.h			\
		rp_queue.h			\
		threads.h

groink_CFLAGS = $(LUA_CFLAGS)
groink_LDADD = $(LUA_LIBS)

CLEANFILES = *~ protocols/*~