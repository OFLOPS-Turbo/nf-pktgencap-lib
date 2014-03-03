bin_PROGRAMS = pkt_gen pkt_cap

pkt_gen_LDADD = -lm -lpcap -lpthread
pkt_gen_CFLAGS = -I$(top_srcdir)/include -march=core2
pkt_gen_SOURCES = pkt_gen.c ../src/nf10_pktgen.c ../src/util.c ../src/util.h

pkt_cap_LDADD = -L../src -lnf10_pktgen 
pkt_cap_CFLAGS = -I$(top_srcdir)/include -O2 
pkt_cap_SOURCES = pkt_cap.c 
