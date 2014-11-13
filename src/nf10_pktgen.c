#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/queue.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <net/if.h>

#include <sched.h>

#include "global.h"
#include "nf10_pktgen_data.h"

int nf_osnt_run();
int nf_pcap_run();
void nf_cap_add_rule(int, uint8_t, uint32_t, uint32_t, uint16_t, uint8_t,
		uint32_t, uint32_t, uint16_t);
void nf_cap_clear_rule(int);
void nf_cap_clear_rules();

struct osnt_cap_t buf;

struct str_nf_pktgen nf10;

#define OSNT_MON_FILTER_BASE_ADDR 0x72200000
#define OSNT_MON_CUTTER_BASE_ADDR 0x77a00000
#define OSNT_MON_TIMER_BASE_ADDR  0x78a00000


#define NF10_IOCTL_CMD_READ_STAT (SIOCDEVPRIVATE+0)
#define NF10_IOCTL_CMD_WRITE_REG (SIOCDEVPRIVATE+9)
#define NF10_IOCTL_CMD_READ_REG (SIOCDEVPRIVATE+2)

#define NF10_IOCTL_CMD_INIT (SIOCDEVPRIVATE+3)
#define NF10_IOCTL_CMD_PREPARE_RX (SIOCDEVPRIVATE+4)
#define NF10_IOCTL_CMD_WAIT_INTR	(SIOCDEVPRIVATE+5)

int
rdaxi(uint32_t addr, uint32_t *ret) {
    uint64_t req = addr;
    if(ioctl(nf10.dev_fd, NF10_IOCTL_CMD_READ_REG, &req) < 0){
        perror("rdaxi");
        return -1;
    }
    *ret = (uint32_t)(req & 0xffffffffL);
    return 0;
}

int
wraxi(uint32_t addr, uint32_t val) {
    uint64_t req = (((uint64_t)addr)<<32) + ((uint64_t)val);
    if(ioctl(nf10.dev_fd, NF10_IOCTL_CMD_WRITE_REG, &req) < 0){
        perror("wraxi");
        return -1;
    }
    // printf("write %08x -> %08x %016lx\n", addr, val, req);
    return 0;
}

//function to load data
// TODO pcap_pkthdr is probably not required
int nf_gen_load_packet(struct pcap_pkthdr *h, const unsigned char *data,
		int port, uint64_t delay) {
	uint32_t len = h->len, word_len = (uint32_t)ceil(((float)len)/32.0) + 1;

	// Check if there is room in the queue for the entire packet
	// 	If there is no room return 1

	if ( (word_len + nf10.total_words) > MEM_HIGH_ADDR) {
		printf("Warning: unable to load all packets from pcap file. SRAM queues are full.\n");
		printf("Total output queue size: %u words\n", MEM_HIGH_ADDR);
		printf("Current queue occupancy: %u words\n", nf10.total_words);
		printf("Packet size:%u words\n", word_len);
		return -1;
	} else {
		nf10.total_words += word_len;
		nf10.queue_pages[port] += word_len;
		nf10.queue_bytes[port] += len;
		nf10.queue_pkts[port]++;
	}

	//Save packet in RAM
	nf10.queue_data[port] = (uint8_t *)realloc(nf10.queue_data[port], nf10.queue_bytes[port]);
	memcpy(nf10.queue_data[port] + nf10.queue_bytes[port] - len, data, len);
	nf10.pkt_len[port] = (uint32_t *)realloc(nf10.pkt_len[port], nf10.queue_pkts[port]*sizeof(uint32_t));
	nf10.pkt_len[port][nf10.queue_pkts[port] - 1] = len;

	nf10.queue_delay[port] = (delay*DATAPATH_FREQUENCY)/1000000000L;
	return 0;
}

int nf_gen_load_pcap(const char *filename, int port, uint64_t ns_delay) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    struct pcap_pkthdr h;
    const uint8_t *pkt;

    if ((pcap = pcap_open_offline(filename, errbuf)) == NULL) {
        printf("[nf10] error: %s\n", errbuf);
        perror("pcap_open_offline");
        return -1;
    }

    while((pkt = pcap_next(pcap, &h)) != NULL) {
        if (nf_gen_load_packet(&h, pkt,  port, ns_delay) < 0) {
            break;
        }
    }

    pcap_close(pcap);
    return 0;
}

#define PCAP_ENGINE_BASE_ADDR  0x76000000
#define PCAP_ENGINE_RESET      0x0
#define PCAP_ENGINE_REPLAY     0x4
#define PCAP_ENGINE_REPLAY_CNT 0x14
#define PCAP_ENGINE_MEM_LOW    0x24
#define PCAP_ENGINE_MEM_HIGH   0x28
#define PCAP_ENGINE_ENABLE     0x44

#define INTER_PKT_DELAY_BASE_ADDR   0x76600000
#define INTER_PKT_DELAY             0xc
#define INTER_PKT_DELAY_ENABLE      0x4
#define INTER_PKT_DELAY_USE_REG     0x8
#define INTER_PKT_DELAY_RST         0x0

#define TX_TIMESTAMP_BASE_ADDR 0x79a00000
#define TX_TIMESTAMP_ENABLE 0x0
#define TX_TIMESTAMP_OFFSET 0x4

int
generator_rst(uint32_t val) {
    int ret = wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_RESET, val);
    return ret;
}

int
rst_gen_mem() {
    int i;
    for (i=0;i<NUM_PORTS;i++)
        if ((wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_MEM_LOW + i*0x8, 0L) < 0) ||
                (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_MEM_HIGH + i*0x8, 0L) < 0) ||
                (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_ENABLE + i*0x4, 0L) < 0) ||
                (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY + i*0x4, 0L) < 0) ||
                (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY_CNT + i*0x4, 0L) < 0)) {
            perror("rst_gen_mem");
            return -1;
        }
    return 0;
}

int
stop_gen() {
    int i;
    for (i=0;i<NUM_PORTS;i++) {
        if ((wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_ENABLE + i*0x4, 0L) < 0) ||
                (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY + i*0x4, 0L) < 0) ) {
            perror("stop_gen");
            return -1;
        }
    }
    return 0;
}

int
start_gen() {
    int i;
    uint32_t enable = 0, en_tmstmp = 1;
    for (i=0;i<NUM_PORTS;i++) {
        enable = (int32_t)(nf10.queue_bytes[i] > 0);
        // enabling tx timestamp measurement
        if ((wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_ENABLE + i*0x4, enable) < 0) ||
                (wraxi(TX_TIMESTAMP_BASE_ADDR + TX_TIMESTAMP_OFFSET + i*0x100000, PKTGEN_HDR_OFFSET) < 0) ||
                (wraxi(TX_TIMESTAMP_BASE_ADDR + TX_TIMESTAMP_ENABLE + i*0x100000, en_tmstmp) < 0) ||
                (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY + i*0x4, enable) < 0) ) {
            perror("PCAP_ENGINE_ENABLE error");
            return -1;
        }
        // sleep(0.1);
    }
    return 0;
}

int
set_gen_mem() {
    int i;
    uint32_t offset = 0;
    for (i=0;i<NUM_PORTS;i++) {
//        printf("port %d: %d-%d iter %d\n", i, offset, offset + nf10.queue_pages[i], nf10.queue_iter[i]);
        if ((wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_MEM_LOW + i*0x8, offset) < 0)) {
            perror("set_gen_mem");
            return -1;
        }
        if (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_MEM_HIGH + i*0x8, 
					(offset + nf10.queue_pages[i])) < 0) {
            perror("set_gen_mem");
            return -1;
        }
		offset +=  nf10.queue_pages[i];
    }

    for (i=0;i<NUM_PORTS;i++) {
		if(wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY_CNT + i*0x4, nf10.queue_iter[i]) < 0) {
            perror("set_gen_mem");
            return -1;
        }
    }

    for (i=0;i<NUM_PORTS;i++) {
		uint32_t enable = (nf10.queue_bytes[i] > 0);
		wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_ENABLE + i*0x4, enable);
    }

    for (i=0;i<NUM_PORTS;i++) {
        if (nf10.queue_delay[i] > 0) {
            if ((wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY, nf10.queue_delay[i]) < 0) ||
                    (wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY_ENABLE, 1) < 0) ||
                    (wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY_USE_REG, 1) < 0) ) {
                perror("set_gen_mem");
                return -1;
            }
        } else {
            if ((wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY, 0) < 0) ||
                    (wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY_ENABLE, 0) < 0) ||
                    (wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY_USE_REG, 0) < 0) ) {
                perror("set_gen_mem");
                return -1;
            }
        }
    }
    return 0;
}

#define DELAY_HEADER_EXTRACTOR_BASE_ADDR 0x76e00000
#define DELAY_HEADER_EXTRACTOR_RST       0x0
#define DELAY_HEADER_EXTRACTOR_SET       0x4

int
nf_init(int pad, int nodrop,int resolve_ns) {
    int i;
    // bzero(&nf10, sizeof(struct str_nf_pktgen));
    if ( (nf10.dev_fd = open("/dev/nf10", O_RDWR)) < 0) {
        perror("/dev/nf10");
        return -1;
    }

    nf10.pad = pad;
    nf10.nodrop = nodrop;
    nf10.resolve_ns = resolve_ns;


	for (i=0;i<NUM_PORTS;i++) {
		nf10.cap_fd[i] = 0;	
		TAILQ_INIT(&nf10.pcap_pkts[i]);
	}

	sem_init(&nf10.osnt_sem, 0, 0);

    if (pthread_mutex_init(&nf10.pkt_lock, NULL) != 0)
    {
        printf("mutex init failed\n");
        exit(1);
    }

	nf10.osnt_pkts = RINGBUFFER_NEW(struct osnt_cap_t, 1024000); 

    wraxi(DELAY_HEADER_EXTRACTOR_BASE_ADDR + DELAY_HEADER_EXTRACTOR_RST, 0);
    wraxi(DELAY_HEADER_EXTRACTOR_BASE_ADDR + DELAY_HEADER_EXTRACTOR_SET, 0);


	nf_cap_clear_rules();

    return 0;
}

int nf_start(int wait) {
    int if_fd, i;
	uint32_t j;
    uint32_t ix, ret;
    char if_name[IFNAMSIZ];
    struct sockaddr_ll socket_address;
    struct ifreq ifr;

    pthread_attr_t attr; // thread attribute
    // set thread detachstate attribute to DETACHED
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	cpu_set_t cpu;
    socket_address.sll_halen = ETH_ALEN;

    stop_gen();
    generator_rst(1);
    rst_gen_mem();
    generator_rst(0);
    set_gen_mem();
    for ( i = 0; i < NUM_PORTS; i++) {
        sprintf(if_name, "nf%d", i);

        if_fd = socket(AF_PACKET, SOCK_RAW,  htons(ETH_P_ALL));
        if (if_fd < 0) {
            perror("socket");
            return -1;
        }

        memset(&ifr, 0, sizeof(struct ifreq));
        strncpy(ifr.ifr_name, if_name, IFNAMSIZ-1);
        if (ioctl(if_fd, SIOCGIFINDEX, &ifr) < 0) {
            perror("SIOCGIFINDEX");
            return -1;
        }
        socket_address.sll_ifindex = ifr.ifr_ifindex;
        socket_address.sll_family = PF_PACKET;
        socket_address.sll_protocol = htons(ETH_P_IP);

        /*target is another host*/
        socket_address.sll_pkttype  = PACKET_OTHERHOST;

        /*address length*/
        socket_address.sll_halen    = ETH_ALEN;

        ix = 0;
        printf("adding %d packet on port %s\n", nf10.queue_pkts[i], if_name);
        for (j = 0; j < nf10.queue_pkts[i]; j++) {
            if (sendto(if_fd, nf10.queue_data[i] + ix, nf10.pkt_len[i][j], 0,
                        (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
                perror("Send failed");
            ix += nf10.pkt_len[i][j];
            if (j%10 == 0) {
                // usleep(.1);
                printf("sleeping\n");
            }
        }
        close(if_fd);
    }

    if(ioctl(nf10.dev_fd, NF10_IOCTL_CMD_INIT, &ret) < 0){
        perror("nf10 reset dma failed");
        return -1;
    }

    for (i = 0; i < NR_LBUF; i++) {
        /* PROT_READ for rx only */
        nf10.buf[i] = mmap(NULL, LBUF_SIZE, PROT_READ, MAP_PRIVATE, nf10.dev_fd, 0);
        if (nf10.buf[i] == MAP_FAILED) {
            perror("mmap");
            return -1;
        }
        printf("lbuf[%d] is mmaped to vaddr=%p w/ size=%lu\n",
                i, nf10.buf[i], LBUF_SIZE);
    }

	CPU_ZERO(&cpu);
	CPU_SET(2, &cpu);
	pthread_create(&nf10.osnt_tid, &attr, (void *)nf_osnt_run, NULL);
	pthread_create(&nf10.pcap_tid, &attr, (void *)nf_pcap_run, NULL);
    pthread_setaffinity_np(nf10.osnt_tid, sizeof(cpu_set_t), &cpu);
    usleep(1);
    nf10.gen_start = ((double)time(NULL));
    pthread_yield();
    printf("finished doing stuff...\n");
    stop_gen();
    start_gen();

    return 0;
}

int nf_gen_reset_queue(int port) {
    printf("unimplemented nf_gen_reset_queue for queue %d\n", port);
    return 0;
}

int nf_gen_set_number_iterations(int number_iterations, int iterations_enable,
        int queue) {
    if (iterations_enable < 0) {
        fprintf(stderr, "[nf10] error: negative iteration number\n");
        return -1;
    }
    nf10.queue_iter[queue] = number_iterations;
    return 0;
}

int nf_gen_rate_limiter_enable(int port, int cpu) {
    fprintf(stderr, "unimplemented nf_gen_rate_limiter_enable %d and %d\n", port, cpu);
    return 0;
}

int nf_gen_rate_limiter_disable(int port, int cpu) {
    fprintf(stderr, "nf_gen_rate_limiter_disable unimplemented on port %d and %d\n", port, cpu);
    return 0;
}

int nf_gen_rate_limiter_set(int port, int cpu, float rate) {
    perror("nf_gen_rate_limiter_set unimplemented");
    return 0;
}

int nf_gen_wait_end() {
    int i;
    double last_pkt = 0, delta = 0, queue_last;
    for (i = 0; i < NUM_PORTS; i++) {
        if (nf10.queue_data_len[i]) {
            queue_last = nf10.queue_pkts[i] * nf10.queue_delay[i] * pow(10,-9) * nf10.queue_iter[i];
            if (queue_last > last_pkt) {
                last_pkt = queue_last;
            }
        }
    }

    printf("delta : %f, last_pkt: %.09f\n", delta, last_pkt);
    // Wait the requesite number of seconds
    while (delta <= last_pkt) {
        printf("\r%1.3f seconds elapsed...\n", delta);
        pthread_yield();
        delta = ((double)time(NULL)) - nf10.gen_start;
    }
    return 0;
}

int nf_gen_finished() {
    int i;
    double last_pkt = 0, queue_last;
    for (i = 0; i < NUM_PORTS; i++) {
        if (nf10.queue_data_len[i]) {
            queue_last = ((double)nf10.queue_delay[i]) / (double)(10*DATAPATH_FREQUENCY);
            queue_last *= nf10.queue_pkts[i] * nf10.queue_iter[i];
            if (queue_last > last_pkt) {
                last_pkt = queue_last;
           }
        }
    }

    //  printf("finished? %e %e < %ld %ld %ld %e\n", ((double)time(NULL)), nf10.gen_start, nf10.queue_delay[i], nf10.queue_pkts[i],
    //      nf10.queue_iter[i], last_pkt);
    //  return (((double)time(NULL) - nf10.gen_start) > last_pkt);
    return 0;

}

int nf_restart() {
    stop_gen();
    start_gen();
    return 0;
}

#define CUTTER_BASE_ADDR 0x77a00000
#define CUTTER_ENABLE 0x0
#define CUTTER_WORDS  0x4
#define CUTTER_OFFSET 0x8
#define CUTTER_BYTES  0xc

struct nf_cap_t *nf_cap_enable(char *dev_name, int caplen) {
    struct nf_cap_t *ret = NULL;
    int flags = EFD_SEMAPHORE | EFD_NONBLOCK;
    int port = 0;

	uint32_t words = ceil(((float)caplen)/32) - 2;
	uint32_t offset = 32 - (caplen % 32);
    uint32_t bytes = (0xffffffff << offset) & 0xffffffff;

	wraxi(CUTTER_BASE_ADDR + CUTTER_WORDS, words);
	wraxi(CUTTER_BASE_ADDR + CUTTER_OFFSET, bytes);
	wraxi(CUTTER_BASE_ADDR + CUTTER_BYTES, caplen);
	wraxi(CUTTER_BASE_ADDR + CUTTER_ENABLE, 1);

    ret = (struct nf_cap_t *) malloc(sizeof(struct nf_cap_t));

    if (strcmp(dev_name, "nf0") == 0)
        port = 0;
    else if (strcmp(dev_name, "nf1") == 0)
        port = 1;
    else if (strcmp(dev_name, "nf2") == 0)
        port = 2;
    else if (strcmp(dev_name, "nf3") == 0)
        port = 3;
    else {
        printf("invalid device %s \n", dev_name);
        return NULL;
    }

    if(nf10.cap_fd[port] == 0)
        nf10.cap_fd[port] = eventfd(0, flags);
    ret->cap_fd = nf10.cap_fd[port];
    ret->if_ix = port;
	sem_init(&ret->sem, 0, 0);
	nf10.pcap_sem[port] = &ret->sem;
    printf("created fd %d for dev %s port %d\n", nf10.cap_fd[port], dev_name, port);

    //TODO fix caplen
    return ret;
}
int nf_cap_fileno(struct nf_cap_t *cap) {return cap->cap_fd;}

int nf_finish() {
	uint32_t ret;

    stop_gen();
    nf10.terminate = 1;
    // close(nf10.dev_fd);
    printf("XXXXXXXX terminating generation thread XXXXXXXX\n");
	pthread_mutex_destroy(&nf10.pkt_lock);
    ioctl(nf10.dev_fd, NF10_IOCTL_CMD_INIT, &ret);
   	return 0;
}


#define OSNT_MON_STATS_BASE_ADDR  0x72220000
#define OSNT_MON_STATS_RST        0x0
#define OSNT_MON_STATS_PKT_CNT    0x8
#define OSNT_MON_STATS_BYTE_CNT   0x18


int nf_gen_stat(int queue, struct nf_gen_stats *stat) {
    printf("unimplemented nf_gen_stat\n");
    return -1;
}
int nf_cap_stat(int queue, struct nf_cap_stats *stat) {
    rdaxi( OSNT_MON_STATS_BASE_ADDR + OSNT_MON_STATS_PKT_CNT + queue*0x4, &stat->pkt_cnt);
    rdaxi( OSNT_MON_STATS_BASE_ADDR + OSNT_MON_STATS_BYTE_CNT + queue*0x4, &stat->byte_cnt);
    rdaxi( OSNT_MON_STATS_BASE_ADDR + OSNT_MON_STATS_PKT_CNT + queue*0x4, &stat->capture_packet_cnt);
    return 0;
}


#define  OSNT_MON_STATS_BASE_ADDR 0x72220000
#define  OSNT_MON_STATS_TIME_LOW  0x68
#define  OSNT_MON_STATS_TIME_HIGH 0x6c

void
nf_cap_timeofday(struct timeval *now) {
    uint32_t low, high;
    rdaxi(OSNT_MON_STATS_BASE_ADDR + OSNT_MON_STATS_TIME_LOW, &low);
    rdaxi(OSNT_MON_STATS_BASE_ADDR + OSNT_MON_STATS_TIME_HIGH, &high);
    now->tv_sec = (high & 0xffffffff);
    now->tv_usec = ((( ((uint64_t)low) & 0xffffffffL)*1000000000L)>>32);
    /*printf("timeofday %ld.%.6ld\n", now->tv_sec, now->tv_usec);*/
    return;
}

const uint8_t *
nf_cap_next(struct nf_cap_t *cap, struct pcap_pkthdr *h) {
	struct osnt_cap_t *pkt_osnt; 
	uint64_t val;

	if  ( (!nf10.cap_fd[cap->if_ix]) || (read(nf10.cap_fd[cap->if_ix], &val, 8) != 8) || 
			(val == 0)) { 
		return NULL;
	}

    if (!TAILQ_EMPTY(&nf10.pcap_pkts[cap->if_ix])) {
		pkt_osnt = TAILQ_FIRST(&nf10.pcap_pkts[cap->if_ix]);

		h->ts.tv_sec = ((pkt_osnt->timestamp>>32)&0xffffffff);
		h->ts.tv_usec = (((pkt_osnt->timestamp&0xffffffff)*1000000000)>>32);
		h->caplen = pkt_osnt->pkt_len;
		h->len = pkt_osnt->pkt_len;
//		pthread_mutex_lock(&nf10.pkt_lock);
		TAILQ_REMOVE(&nf10.pcap_pkts[cap->if_ix], pkt_osnt, entries);
//		pthread_mutex_unlock(&nf10.pkt_lock);
		return pkt_osnt->pkt;
   } else 
        return NULL;
}
static inline int 
metadata_to_port(uint32_t meta) {
	/* decode */
	int port_enc = (meta >> 16) & 0xff;
	switch (port_enc) {
		case 0x02:	return 0;
		case 0x08:	return 1;
		case 0x20:	return 2;
		case 0x80:	return 3;
		default:	return -1;
	}
	return -1;
}


int
nf_pcap_run() {
	int count, i;
	int port;
//	uint64_t pkts = 0;
	struct osnt_cap_t *pkt_osnt;
	uint64_t pkts[] = {0, 0, 0, 0};

	while (!nf10.terminate) {
		sem_wait(&nf10.osnt_sem); 

		if ( ((count = RingBuffer_getAvailable(nf10.osnt_pkts)) == 0)
				|| ((pkt_osnt = (struct osnt_cap_t*)malloc(count*sizeof(struct osnt_cap_t) )) == NULL) 
				|| (!RingBuffer_get(nf10.osnt_pkts, pkt_osnt, count) ) )
			continue;
		
		for (i=0; i < count; i++) {
			if (( (port = metadata_to_port(pkt_osnt[i].metadata)) < 0)
						|| (nf10.cap_fd[port] < 3) )
				continue;
			pkts[port]++;
			TAILQ_INSERT_TAIL(&nf10.pcap_pkts[port], &pkt_osnt[i], entries);
		}
		for (i=0; i < NUM_PORTS; i++) {
			if (pkts[i] && nf10.cap_fd[i]) {
				write(nf10.cap_fd[i], &pkts[i], sizeof(uint64_t));
			}
			pkts[i] = 0;
		}
	}
	return 0;
}

int
nf_osnt_run() {
	uint64_t ret;
	uint32_t rx_cons;
	uint8_t *buf_addr;
	uint32_t nr_dwords;
	uint32_t dword_idx;
	int port_num;
	uint32_t pkt_len;
	uint64_t records;

    while(!nf10.terminate){
		/* wait interrupt: blocked */
		ioctl(nf10.dev_fd, NF10_IOCTL_CMD_WAIT_INTR, &ret);
		rx_cons = (uint32_t)ret;

lbuf_poll_loop:
		buf_addr = nf10.buf[rx_cons];
		nr_dwords = LBUF_NR_DWORDS(buf_addr);
		dword_idx = LBUF_FIRST_DWORD_IDX();

		/* if lbuf is invalid, usually normal case at the end of the
		 * lbuf loop, BUT note that it could be caused by a DMA bug */
		if (!LBUF_IS_VALID(nr_dwords))
			continue;

		/* packet processing loop */
		records = 0;
		do {
			port_num = LBUF_PKT_PORT_NUM(buf_addr, dword_idx);
			pkt_len = LBUF_PKT_LEN(buf_addr, dword_idx);
			/* if you want to get timestamp of a packet,
			 * use LBUF_TIMESTAMP(buf_addr, dword_idx) */

			if (LBUF_IS_PKT_VALID(port_num, pkt_len)) {
				nf10.byte_count += pkt_len;
				nf10.pkt_count++;
				records++;
				if (nf10.pkt_count % 100000 == 0)
					printf("[%u] got a packet on port %d records %lu len %u\n", 
							nf10.pkt_count, port_num, records, pkt_len);
			} 
			else if (!LBUF_IS_PKT_VALID(port_num, pkt_len)) { 
				fprintf(stderr, "Error: rx_cons=%u lbuf contains invalid pkt len=%u\n",
						rx_cons, pkt_len);
				break;
			}
			
			dword_idx = LBUF_NEXT_DWORD_IDX(dword_idx, pkt_len);
		} while(dword_idx < nr_dwords);
		if (RingBuffer_getFree(nf10.osnt_pkts) >= records) { 
			RingBuffer_put(nf10.osnt_pkts, buf_addr + LBUF_FIRST_DWORD_IDX()*4, records);
			ioctl(nf10.dev_fd, NF10_IOCTL_CMD_PREPARE_RX, rx_cons);
			sem_post(&nf10.osnt_sem);
			nf10.pkt_snd_count += records;
		} else {
			ioctl(nf10.dev_fd, NF10_IOCTL_CMD_PREPARE_RX, rx_cons);
			nf10.pkt_dropped_count += records;
		}
		inc_pointer(rx_cons);
		goto lbuf_poll_loop;
    } 

    printf("XXXXXXXX terminating capturing thread (pkts = %u, bytes = %u) XXXXXXXX\n", 
			nf10.pkt_count, nf10.byte_count);
    return -1;
}

// int
// display_xmit_metrics(int queue, struct nf_gen_stats *stat) {
//     printf("Unimplemented function display_xmit_metrics\n");
//     return 0;
//     // readReg(&nf_pktgen.nf2,
//     //     OQ_QUEUE_0_NUM_PKTS_REMOVED_REG+(queue+8)*nf_pktgen.queue_addr_offset,
//     //     &stat->pkt_snd_cnt);
// }

struct str_nf_pktgen nf_pktgen;

struct pktgen_hdr *
nf_gen_extract_header(struct nf_cap_t *cap, const uint8_t *b, int len) {
    struct pktgen_hdr *ret;
    int ix = PKTGEN_HDR_OFFSET*8; 

    // sanity check
    if( (b == NULL) || (len < PKTGEN_HDR_OFFSET*8 + 16)) {
		printf("error buf %p, len %d\n", b, len);
        return NULL;
	}

    //constant distacne
    ret = (struct pktgen_hdr *)(b + ix);

    if((0xFFFFFFFF & ntohl(ret->magic)) != 0xdeadbeef) { //sometimes the 1st byte is messed up
        //if the vlan tag is stripped move the translation by 4 bytes.
#if DEBUG == 1
        printf("Packet gen packet received %08x\n",ntohl(ret->magic));
#endif
        ret = (struct pktgen_hdr *)((uint8_t *)b + ix - 2);
        if((0xFFFFFFFF & ntohl(ret->magic)) != 0xdeadbeef) {
#if DEBUG == 1
            printf("reading header %08x\n", 0xFFFFFFFF & ntohl(ret->magic));
#endif
            ret = (struct pktgen_hdr *)((uint8_t *)b + ix + 2);
            if((0xFFFFFFFF & ntohl(ret->magic)) != 0xdeadbeef) {
#if DEBUG == 1
                printf("reading header %08x\n", 0xFFFFFFFF & ntohl(ret->magic));
#endif
                return NULL;
            }
        }
    }

    //minor hack in case I am comparing against timestamp not made by the hw design
    ret->tv_sec = ntohl(ret->tv_sec);
    ret->tv_usec = (((uint64_t)ntohl(ret->tv_usec)) * 1000000000L) >> 32;

    ret->seq_num = ntohl(ret->seq_num);
#if DEBUG == 1
    printf("packet time %x %x %u.%06u\n", ntohl(ret->magic), ret->seq_num,
    	 ret->tv_sec, ret->tv_usec);
#endif
    return ret;
}

/* Definitions for peripheral OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0 */
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_FILTER_TABLE_DEPTH 16
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_BASEADDR 0x72220000
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_HIGHADDR 0x7222FFFF
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_STATS_RESET 0x72220000
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_STATS_FREEZE 0x72220004
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_COUNT_INTF0 0x72220008
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_COUNT_INTF1 0x7222000c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_COUNT_INTF2 0x72220010
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_COUNT_INTF3 0x72220014
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_BYTES_COUNT_INTF0 0x72220018
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_BYTES_COUNT_INTF1 0x7222001c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_BYTES_COUNT_INTF2 0x72220020
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_BYTES_COUNT_INTF3 0x72220024
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_VLAN_COUNT_INTF0 0x72220028
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_VLAN_COUNT_INTF1 0x7222002c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_VLAN_COUNT_INTF2 0x72220030
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_VLAN_COUNT_INTF3 0x72220034
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_IP_COUNT_INTF0 0x72220038
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_IP_COUNT_INTF1 0x7222003c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_IP_COUNT_INTF2 0x72220040
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_IP_COUNT_INTF3 0x72220044
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_UDP_COUNT_INTF0 0x72220048
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_UDP_COUNT_INTF1 0x7222004c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_UDP_COUNT_INTF2 0x72220050
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_UDP_COUNT_INTF3 0x72220054
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_TCP_COUNT_INTF0 0x72220058
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_TCP_COUNT_INTF1 0x7222005c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_TCP_COUNT_INTF2 0x72220060
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_TCP_COUNT_INTF3 0x72220064
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_STATS_TIME_LOW 0x72220068
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_STATS_TIME_HIGH 0x7222006c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_BASEADDR 0x72200000
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_HIGHADDR 0x7220FFFF
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP 0x72200000
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP_MASK 0x72200004
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_IP 0x72200008
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_MASK 0x7220000c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS 0x72200010
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS_MASK 0x72200014
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO 0x72200018
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO_MASK 0x7220001c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_WR_ADDR 0x72200020
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_RD_ADDR 0x72200024

void nf_cap_clear_rule(int entry) {
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO, 0))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO);
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP, 0))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP);
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_IP, 0))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_IP);
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS, 0))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS);
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO_MASK, 0xff))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO_MASK);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP_MASK, 0xffffffff))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP_MASK);
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_MASK, 0xffffffff))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_MASK);
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS_MASK, 0xffffffff))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS_MASK);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_WR_ADDR, entry))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_WR_ADDR);
}

void nf_cap_clear_rules() {
	int i;
	for (i = 0; i < XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_FILTER_TABLE_DEPTH; i++)
		nf_cap_clear_rule(i);

}

void nf_cap_add_rule(int entry, uint8_t proto, uint32_t src_ip, uint32_t dest_ip, 
		uint16_t l4ports, uint8_t proto_mask, uint32_t src_ip_mask, 
		uint32_t dest_ip_mask,  uint16_t l4ports_mask) {
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO, (uint32_t)proto))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP, src_ip))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_IP, dest_ip))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_IP);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS, l4ports))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO_MASK, proto_mask))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO_MASK);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP_MASK, src_ip_mask))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP_MASK);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_MASK, dest_ip_mask))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_MASK);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS_MASK, l4ports_mask))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS_MASK);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_WR_ADDR, entry))
	  printf("0x%08x: ERROR\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_WR_ADDR);
}
