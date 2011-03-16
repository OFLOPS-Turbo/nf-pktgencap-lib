bin_PROGRAMS = pkt_gen pkt_cap

#AM_CPPFLAGS = -g -I$(top_srcdir)/include

pkt_gen_LDADD = ../src/libnf_pktgten.la -lm -lpcap -lpthread
pkt_gen_CPPFLAGS = -g  -I$(top_srcdir)/include
pkt_gen_SOURCES = pkt_gen.c

pkt_cap_LDADD = ../src/libnf_pktgten.la -lm -lpcap -lpthread
pkt_cap_CPPFLAGS = -g  -I$(top_srcdir)/include
pkt_cap_SOURCES = pkt_cap.c
