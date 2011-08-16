bin_PROGRAMS = groink

groink_SOURCES =				\
		base.c				\
		debug.c				\
		decoder.c			\
		forward.c			\
		globals.c			\
		hook.c				\
		host.c				\
		iface.c				\
		inject.c			\
		main.c				\
		mitm.c				\
		mitm_arp_poisoning.c		\
		netutil.c			\
		packet.c			\
		parse_options.c			\
		protos.c			\
		protocols/arp.c			\
		protocols/icmp.c		\
		protocols/icmp6.c		\
		protocols/ipv4.c		\
		protocols/ipv6.c		\
		protocols/ethernet.c		\
		protocols/pppoe.c		\
		protocols/raw.c			\
		protocols/tcp.c			\
		protocols/udp.c			\
		protocols/http.c		\
		protocols/ftp.c			\
		selib.c				\
		selib_bit.c			\
		selib_constants.c		\
		selib_core.c			\
		selib_header.c			\
		selib_netutil.c			\
		selib_packet.c			\
		script_engine.c			\
		threads.c			\
		pcap_util.c

noinst_HEADERS =				\
		base.h				\
		debug.h				\
		decoder.h			\
		forward.h			\
		globals.h			\
		hashtable.h			\
		hook.h				\
		host.h				\
		inject.h			\
		mitm.h				\
		netutil.h			\
		packet.h			\
		parse_options.h			\
		protos.h			\
		protos_name.h			\
		protocols/arp.h			\
		protocols/icmp.h		\
		protocols/icmp6.h		\
		protocols/ipv4.h		\
		protocols/ipv6.h		\
		protocols/ethernet.h		\
		protocols/pppoe.h		\
		protocols/raw.h			\
		protocols/tcp.h			\
		protocols/udp.h			\
		protocols/http.h		\
		protocols/ftp.h			\
		selib.h				\
		script_engine.h			\
		threads.h			\
		utlist.h			\
		uthash.h			\
		pcap_util.h			\
		iface.h

groink_CFLAGS = $(LUA_CFLAGS)
groink_LDADD = $(LUA_LIBS)

CLEANFILES = *~ protocols/*~
