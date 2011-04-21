bin_PROGRAMS = groink

groink_SOURCES =				\
		base.c				\
		capture.c			\
		debug.c				\
		decoder.c			\
		globals.c			\
		hook.c				\
		host.c				\
		iface.c				\
		inject.c			\
		main.c				\
		netutil.c			\
		packet.c			\
		parse_options.c			\
		protos.c			\
		protocols/arp.c			\
		protocols/icmp.c		\
		protocols/ipv4.c		\
		protocols/ethernet.c		\
		protocols/pppoe.c		\
		protocols/raw.c			\
		protocols/tcp.c			\
		protocols/udp.c			\
		rp_processor.c			\
		rp_queue.c			\
		selib.c				\
		selib_bit.c			\
		selib_constants.c		\
		selib_core.c			\
		selib_header.c			\
		selib_netutil.c			\
		selib_packet.c			\
		script_engine.c			\
		threads.c

noinst_HEADERS =				\
		base.h				\
		capture.h			\
		debug.h				\
		decoder.h			\
		globals.h			\
		hashtable.h			\
		hook.h				\
		host.h				\
		inject.h			\
		netutil.h			\
		packet.h			\
		parse_options.h			\
		protos.h			\
		protos_name.h			\
		protocols/arp.h			\
		protocols/icmp.h		\
		protocols/ipv4.h		\
		protocols/ethernet.h		\
		protocols/pppoe.h		\
		protocols/raw.h			\
		protocols/tcp.h			\
		protocols/udp.h			\
		rp_processor.h			\
		rp_queue.h			\
		selib.h				\
		script_engine.h			\
		threads.h			\
		utlist.h			\
		uthash.h

groink_CFLAGS = $(LUA_CFLAGS)
groink_LDADD = $(LUA_LIBS)

CLEANFILES = *~ protocols/*~