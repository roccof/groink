bin_PROGRAMS = groink

groink_SOURCES =				\
		base.c				\
		capture.c			\
		debug.c				\
		globals.c			\
		hook.c				\
		iface.c				\
		list.c				\
		main.c				\
		netutil.c			\
		packet.c			\
		parse_options.c			\
		rp_processor.c			\
		rp_queue.c			\
		threads.c

noinst_HEADERS =				\
		base.h				\
		capture.h			\
		debug.h				\
		globals.h			\
		hook.h				\
		list.h				\
		netutil.h			\
		packet.h			\
		parse_options.h			\
		rp_processor.h			\
		rp_queue.h			\
		threads.h

groink_CFLAGS = $(LUA_CFLAGS)
groink_LDADD = $(LUA_LIBS)

CLEANFILES = *~ protocols/*~