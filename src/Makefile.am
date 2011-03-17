bin_PROGRAMS = groink

groink_SOURCES =				\
		base.c				\
		capture.c			\
		debug.c				\
		globals.c			\
		list.c				\
		main.c				\
		packet.c			\
		parse_options.c			\
		rp_queue.c			\
		threads.c

noinst_HEADERS =				\
		base.h				\
		capture.h			\
		debug.h				\
		globals.h			\
		list.h				\
		packet.h			\
		parse_options.h			\
		rp_queue.h			\
		threads.h

groink_CFLAGS = $(LUA_CFLAGS)
groink_LDADD = $(LUA_LIBS)

CLEANFILES = *~ protocols/*~