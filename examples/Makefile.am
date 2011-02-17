bin_PROGRAMS = pkt_gen pkt_cap

AM_CPPFLAGS = -I$(top_srcdir)/include

pkt_gen_LDADD = ../src/libnf_pktgten.a -lm -lpcap
pkt_gen_SOURCES = pkt_gen.c

pkt_cap_LDADD = ../src/libnf_pktgten.a -lm -lpcap
pkt_cap_SOURCES = pkt_cap.c