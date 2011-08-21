#ifndef NF_PKTGEN_H_
#define NF_PKTGEN_H_ 1

#include <pcap.h>
#include <stdint.h>

//#define DEBUG 1

struct nf_cap_stats {
  uint64_t byte_cnt;
  uint32_t pkt_cnt;
  uint32_t capture_packet_cnt;
  //double duration;
};

struct nf_gen_stats {
  uint32_t pkt_snd_cnt;  
};

#ifndef PKTGEN_HDR

#define PKTGEN_HDR 1
struct pktgen_hdr {
  uint32_t magic;
  uint32_t seq_num;
  uint32_t tv_sec;
  uint32_t tv_usec;
  struct timeval time;
};
#endif

FILE *test_output;

struct nf_cap_t;

//a function to control the state of the design state
int nf_init(int pad, int nodrop,int resolve_ns);

//function to load data
int nf_gen_load_pcap(const char *filename, int port, int32_t delay);
int nf_gen_load_packet(struct pcap_pkthdr *h, const unsigned char *data, 
		       int port, int32_t delay);
int nf_gen_reset_queue(int port);

int nf_gen_set_number_iterations(int number_iterations, int iterations_enable, 
			  int queue);

int nf_gen_rate_limiter_enable(int port, int cpu);
int nf_gen_rate_limiter_disable(int port, int cpu);
int nf_gen_rate_limiter_set(int port, int cpu, float rate);


int nf_gen_wait_end();
int nf_gen_finished();
int nf_restart();

struct nf_cap_t *nf_cap_enable(char *dev_name, int caplen);
int  nf_cap_fileno(struct nf_cap_t *cap);
const uint8_t *nf_cap_next(struct nf_cap_t *cap, struct pcap_pkthdr *h);

int nf_start(int wait);
int nf_finish();

int nf_gen_stat(int queue, struct nf_gen_stats *stat);
int nf_cap_stat(int queue, struct nf_cap_stats *stat);


void nf_cap_timeofday(struct timeval *now);

#endif
