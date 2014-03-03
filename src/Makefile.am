lib_LTLIBRARIES = libnf_pktgen.la libnf10_pktgen.la
# noinst_LIBRARIES = libnf10_pktgen.a

libnf_pktgen_la_CFLAGS = -g -I$(top_srcdir)/include
libnf_pktgen_la_SOURCES = nf2.h  nf2util.c  nf2util.h  nf_pktgen.c \
	reg_defines.h  util.c  util.h reg_defines_packet_generator.h

libnf10_pktgen_la_CFLAGS = -I$(top_srcdir)/include -march=core2
libnf10_pktgen_la_LDFLAGS =  -lm -lpcap -lpthread
libnf10_pktgen_la_SOURCES =  nf10_pktgen.c util.c util.h
