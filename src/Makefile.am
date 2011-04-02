bin_PROGRAMS = groink

groink_SOURCES =				\
		base.c				\
		capture.c			\
		debug.c				\
		decoder.c			\
		globals.c			\
		hook.c				\
		iface.c				\
		list.c				\
		main.c				\
		netutil.c			\
		packet.c			\
		parse_options.c			\
		protos.c			\
		protocols/ethernet.c		\
		rp_processor.c			\
		rp_queue.c			\
		threads.c

noinst_HEADERS =				\
		base.h				\
		capture.h			\
		debug.h				\
		decoder.h			\
		globals.h			\
		hashtable.h			\
		hook.h				\
		list.h				\
		netutil.h			\
		packet.h			\
		parse_options.h			\
		protos.h			\
		protos_name.h			\
		protocols/ethernet.h		\
		rp_processor.h			\
		rp_queue.h			\
		threads.h			\
		utlist.h			\
		uthash.h

groink_CFLAGS = $(LUA_CFLAGS)
groink_LDADD = $(LUA_LIBS)

CLEANFILES = *~ protocols/*~