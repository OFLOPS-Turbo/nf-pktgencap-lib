#include <pcap/pcap.h>
#include <sys/queue.h>
#include <nf10_lbuf_api.h>
#include <semaphore.h>

#include "ringbuffers.h"

#define PKTGEN_HDR_OFFSET 7

#define NUM_PORTS 4
#define MEM_HIGH_ADDR 512*1024

#define DATAPATH_FREQUENCY 160000000L
#define DEBUG 0

#define FILTER_RULE_COUNT 8

#define PAGE_SIZE 4096
#define BUFSIZE 7

#undef PKTGEN_HDR
#include "nf_pktgen.h"


struct __attribute__((packed)) osnt_cap_t {
    uint32_t metadata;
	uint32_t pkt_len;
	uint64_t timestamp;
    uint8_t pkt[PKTGEN_HDR_OFFSET*8 + 16];
	//remove 8 bytes for 2 pointers in the struct
	TAILQ_ENTRY(osnt_cap_t) entries;
};

struct nf_cap_t {
    int cap_fd;
	sem_t sem;
    int if_ix;
	struct pcap_pkthdr h;
};

struct str_nf_pktgen {
    int dev_fd;
    uint32_t queue_pages[NUM_PORTS];
    uint32_t queue_bytes[NUM_PORTS];
    uint32_t queue_pkts[NUM_PORTS];
    uint32_t queue_delay[NUM_PORTS];
    uint32_t num_pkts[NUM_PORTS];
    uint32_t queue_iter[NUM_PORTS];

    uint8_t *queue_data[NUM_PORTS];
    uint32_t *pkt_len[NUM_PORTS];
    uint32_t queue_data_len[NUM_PORTS];
	uint32_t pkt_snd_count;
	uint32_t pkt_dropped_count;
    
    uint32_t total_words;
    uint8_t pad, nodrop, resolve_ns;
    double gen_start;

    int terminate;

	RingBuffer *osnt_pkts;
	sem_t osnt_sem;

	TAILQ_HEAD(pcap_packet_h, osnt_cap_t) pcap_pkts[NUM_PORTS];
	int cap_fd[NUM_PORTS];
	sem_t *pcap_sem[NUM_PORTS];

    pthread_t osnt_tid, pcap_tid;  // thread ID
    pthread_mutex_t pkt_lock;
    void *buf[NR_LBUF];
	uint32_t pkt_count;
	uint32_t byte_count;
};
