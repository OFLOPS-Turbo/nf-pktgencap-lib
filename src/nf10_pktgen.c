#include "nf_pktgen.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <stdlib.h> 
#include <arpa/inet.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
// #include <linux/if_arp.h>
#include <pcap/pcap.h>
#include <net/if.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/queue.h>
#include <sys/eventfd.h>

#define NUM_PORTS 4
#define MEM_HIGH_ADDR 512*1024

#define DATAPATH_FREQUENCY 160000000L

int nf_cap_run();

struct pcap_packet_t {
  struct pcap_pkthdr h;
  uint8_t *pkt;
  TAILQ_ENTRY(pcap_packet_t) entries;
};

struct nf_cap_t {
//  pcap_t * pcap_handle;
  int cap_fd;
  int if_ix;
//  char *name;
//  struct pcap_pkthdr *cap_hdr;
//  uint8_t *packet_cache;
//  int caplen;
};



struct str_nf_pktgen {
  int dev_fd; 
  uint32_t queue_pages[NUM_PORTS];
  uint32_t queue_bytes[NUM_PORTS];
  uint32_t queue_pkts[NUM_PORTS];
  uint32_t queue_delay[NUM_PORTS];
  uint32_t num_pkts[NUM_PORTS];
  uint32_t queue_iter[NUM_PORTS];

  TAILQ_HEAD(pcap_packet_h, pcap_packet_t) cap_pkts[NUM_PORTS];

//  int queue_base_addr[NUM_PORTS];

  uint8_t *queue_data[NUM_PORTS];
  uint32_t *pkt_len[NUM_PORTS];
  uint32_t queue_data_len[NUM_PORTS];
  int cap_fd[NUM_PORTS];
  
  uint32_t iterations[NUM_PORTS];
  uint32_t total_words;
  uint8_t pad, nodrop, resolve_ns;

  int terminate;

  pthread_t cap_tid;  // thread ID
};

struct str_nf_pktgen nf10;



#define OSNT_MON_FILTER_BASE_ADDR 0x72200000
#define OSNT_MON_CUTTER_BASE_ADDR 0x77a00000
#define OSNT_MON_TIMER_BASE_ADDR  0x78a00000

#define NF10_IOCTL_CMD_READ_STAT (SIOCDEVPRIVATE+0)
#define NF10_IOCTL_CMD_WRITE_REG (SIOCDEVPRIVATE+9)
#define NF10_IOCTL_CMD_READ_REG (SIOCDEVPRIVATE+2)

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
  //printf("write %08x -> %08x %016lx\n", addr, val, req);
  return 0; 
}

//function to load data
// TODO pcap_pkthdr is probably not required
int nf_gen_load_packet(struct pcap_pkthdr *h, const unsigned char *data, 
		       int port, uint64_t delay) {
  uint32_t src_port = 0, dst_port = 0x100;
  uint32_t len = h->len, word_len = (uint32_t)ceil(((float)len)/32.0) + 1;
  uint32_t tmp_data,  pointer;
  uint32_t write_pad = 0;

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
  nf10.pkt_len[port] = (uint32_t *)realloc(nf10.pkt_len[port], nf10.queue_pkts[port]);
  nf10.pkt_len[port][nf10.queue_pkts[port] - 1] = len;

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
    if (nf_gen_load_packet(&h, pkt,  port, 0) < 0) {
      break;
    }
  }

  nf10.queue_delay[port] = (ns_delay*DATAPATH_FREQUENCY)/1000000000L;
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

int 
generator_rst(uint32_t val) {return wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_RESET, val);}

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
  uint32_t enable;
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
  uint32_t enable = 0; 
  for (i=0;i<NUM_PORTS;i++) {  
    enable = (int32_t)(nf10.queue_bytes[i] > 0); 
    if ((wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_ENABLE + i*0x4, enable) < 0) ||
        (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY + i*0x4, enable) < 0) ) {
      perror("PCAP_ENGINE_ENABLE error");
      return -1;
    }
    // sleep(1);
  }
  return 0;
}

int 
set_gen_mem() {
  int i;
  uint32_t offset = 0, enable = 0;
  for (i=0;i<NUM_PORTS;i++) {
    // printf("setting port nf%d = %d %d %d\n", i, offset, offset + nf10.queue_pages[i], nf10.queue_iter[i]);
    if ((wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_MEM_LOW + i*0x8, offset) < 0) ||
        (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_MEM_HIGH + i*0x8, (offset + nf10.queue_pages[i])) < 0) ||
        (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY_CNT + i*0x4, nf10.queue_iter[i]) < 0)) {
      perror("set_gen_mem");
      return -1;
    }

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
    // sleep(1);
    offset += nf10.queue_pages[i];
  }
  return 0;
}

#define DELAY_HEADER_EXTRACTOR_BASE_ADDR 0x76e00000
#define DELAY_HEADER_EXTRACTOR_RST       0x0
#define DELAY_HEADER_EXTRACTOR_SET       0x4

int 
nf_init(int pad, int nodrop,int resolve_ns) {
  int i;
  bzero(&nf10, sizeof(struct str_nf_pktgen));
  if ( (nf10.dev_fd = open("/dev/nf10", O_RDWR)) < 0) {
    perror("/dev/nf10");
    return -1;
  }

  nf10.pad = pad;
  nf10.nodrop = nodrop;
  nf10.resolve_ns = resolve_ns;

  for (i=0;i<NUM_PORTS;i++) {
//    nf10.cap_pkts[i] = TAILQ_HEAD_INITIALIZER(nf10.cap_pkts[i]);
    TAILQ_INIT(&nf10.cap_pkts[i]);
  }
    
  generator_rst(1);
  stop_gen();
  set_gen_mem();
  generator_rst(0); 

  wraxi(DELAY_HEADER_EXTRACTOR_BASE_ADDR + DELAY_HEADER_EXTRACTOR_RST, 0);
  wraxi(DELAY_HEADER_EXTRACTOR_BASE_ADDR + DELAY_HEADER_EXTRACTOR_SET, 0);

  return 0;
}

int nf_start(int wait) {
  int if_fd, i, j; 
  char if_name[10];
  struct sockaddr_ll socket_address;
  struct ifreq ifr;

  pthread_attr_t attr; // thread attribute
  // set thread detachstate attribute to DETACHED 
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  socket_address.sll_halen = ETH_ALEN;

  stop_gen();
  set_gen_mem();

  pthread_create(&nf10.cap_tid, &attr, (void *)nf_cap_run, NULL);
  for ( i = 0; i < 1; i++) {
    sprintf(if_name, "nf%d", i);

    if_fd = socket(AF_PACKET, SOCK_RAW,  IPPROTO_RAW);
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
    for (j = 0; j < nf10.queue_pkts[i]; j++) {
      if (sendto(if_fd, nf10.queue_data[i], nf10.pkt_len[i][j], 0, 
            (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
        perror("Send failed");
    }
    // printf("sending packet\n");
    close(if_fd);
  } 
  start_gen();

  return 0;
}

int nf_gen_reset_queue(int port) {
  return 0;
}

int nf_gen_set_number_iterations(int number_iterations, int iterations_enable, 
			  int queue) {
  if (iterations_enable < 0) {
    printf("[nf10] error: negative iteration number\n");
    return -1;
  }
  nf10.queue_iter[queue] = number_iterations;
  return 0;
}

int nf_gen_rate_limiter_enable(int port, int cpu) {
  return 0;
}

int nf_gen_rate_limiter_disable(int port, int cpu) {
  perror("nf_gen_rate_limiter_disable unimplemented");
  return 0;
}

int nf_gen_rate_limiter_set(int port, int cpu, float rate) {
  perror("nf_gen_rate_limiter_set unimplemented");
  return 0;
}

int nf_gen_wait_end() {
  return 0;
}

int nf_gen_finished() {
  return 0;
}

int nf_restart() {
  return 0;
}

struct nf_cap_t *nf_cap_enable(char *dev_name, int caplen) {
  struct nf_cap_t *ret = NULL;
  int flags = /*EFD_NONBLOCK|*/EFD_SEMAPHORE;
  int port = 0;

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

  //TODO fix caplen
  return ret;
}
int  nf_cap_fileno(struct nf_cap_t *cap) {
  return cap->cap_fd;
}

const uint8_t *nf_cap_next(struct nf_cap_t *cap, struct pcap_pkthdr *h) {
  uint64_t i;
  struct pcap_packet_t *pkt;
  uint8_t *ret;

  read(nf10.cap_fd[cap->if_ix], &i, sizeof(i));

  pkt = TAILQ_FIRST(&nf10.cap_pkts[cap->if_ix]);
  TAILQ_REMOVE(&nf10.cap_pkts[cap->if_ix], pkt, entries);

  memcpy(h, &pkt->h, sizeof(struct pcap_pkthdr));
  ret = pkt->pkt;
  free(pkt);
  return ret;
}

int nf_finish() {
  nf10.terminate = 1;
  close(nf10.dev_fd);
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

void nf_cap_timeofday(struct timeval *now) {
 return;
}

#define PAGE_SIZE 4096
#define BUFSIZE 7

#define NF10_IOCTL_CMD_READ_STAT (SIOCDEVPRIVATE+0)
#define NF10_IOCTL_CMD_READ_REG (SIOCDEVPRIVATE+2)
#define NF10_IOCTL_CMD_RESET_DMA (SIOCDEVPRIVATE+3)
#define NF10_IOCTL_CMD_SET_RX_DNE_HEAD (SIOCDEVPRIVATE+4)
#define NF10_IOCTL_CMD_SET_RX_BUFF_HEAD (SIOCDEVPRIVATE+5)
#define NF10_IOCTL_CMD_SET_RX_PKT_HEAD (SIOCDEVPRIVATE+6)
#define NF10_IOCTL_CMD_START_DMA (SIOCDEVPRIVATE+7)
#define NF10_IOCTL_CMD_STOP_DMA (SIOCDEVPRIVATE+8)

#include <sys/mman.h>
#include <signal.h>
int rx_dne_file;
int rx_buff_file;
uint64_t rx_dne_head = 0;
uint64_t rx_pkt_head = 0;
uint64_t rx_buff_head = 0;
uint64_t pkt_count = 0;
struct pcap_packet_t *cap = NULL;

char *rx_dne = NULL;
char *rx_buff = NULL;

int 
nf_cap_run() {
  uint64_t v;
  uint64_t rx_int;
  uint64_t addr;
  uint64_t len;
  uint64_t port_encoded;
  uint64_t timestamp;
  uint64_t fd_ix = 1;

  struct pcap_pkthdr pcap_pkt_header;

  uint64_t rx_dne_mask = 0x00000fffULL;
  uint64_t rx_pkt_mask = 0x0000ffffULL;
  uint64_t rx_buff_mask = 0xffffULL;
    	
  rx_dne_file = open("/sys/kernel/debug/nf10_rx_dne_mmap", O_RDWR);
  if(rx_dne_file < 0) {
    perror("nf10_rx_dne_mmap");
    goto error_out;
  }

  rx_buff_file = open("/sys/kernel/debug/nf10_rx_buff_mmap", O_RDWR);
  if(rx_buff_file < 0) {
    perror("nf10_rx_buff_mmap");
    goto error_out;
  }

  rx_dne = mmap(NULL, rx_dne_mask+1, PROT_READ|PROT_WRITE, MAP_SHARED, rx_dne_file, 0);
  if (rx_dne == MAP_FAILED) {
    perror("mmap rx_dne error");
    goto error_out;
  }

  rx_buff = mmap(NULL, rx_buff_mask+1+PAGE_SIZE, PROT_READ, MAP_SHARED, rx_buff_file, 0);
  if (rx_buff == MAP_FAILED) {
    perror("mmap rx_buff error");
    goto error_out;
  }

  if(ioctl(nf10.dev_fd, NF10_IOCTL_CMD_RESET_DMA, v) < 0){
    perror("nf10 reset dma failed");
    goto error_out;
  }

  if(ioctl(nf10.dev_fd, NF10_IOCTL_CMD_START_DMA, v) < 0){
    perror("nf10 start dma failed");
    goto error_out;
  }
  while(!nf10.terminate){
    rx_int = *(((uint64_t*)rx_dne) + rx_dne_head/8);
    if( ((rx_int >> 48) & 0xffff) != 0xffff ){

      pkt_count++;

      timestamp = *(((uint64_t*)rx_dne) + (rx_dne_head)/8 + 1);
      len = rx_int & 0xffff;
      port_encoded = (rx_int >> 16) & 0xffff;

      *(((uint64_t*)rx_dne) + rx_dne_head/8) = 0xffffffffffffffffULL;

      cap = (struct pcap_packet_t *)malloc(sizeof(struct pcap_packet_t));
      cap->h.ts.tv_sec = ((timestamp>>32)&0xffffffff);
      cap->h.ts.tv_usec = (((timestamp&0xffffffff)*1000000000)>>32);
      cap->h.caplen = len;
      cap->h.len = len;
      cap->pkt = (uint8_t *) malloc(len);
      memcpy(cap->pkt, rx_buff+rx_buff_head, len);

      int port = 0;
      if(port_encoded & 0x0200) 
        port=0;
      else if(port_encoded & 0x0800) 
        port=1;
      else if(port_encoded & 0x2000) 
        port=2;
      else if(port_encoded & 0x8000) 
        port=3;
      
      TAILQ_INSERT_TAIL(&nf10.cap_pkts[port], cap, entries);
      write(nf10.cap_fd[port], &fd_ix, sizeof(uint64_t));

      rx_dne_head = ((rx_dne_head + 64) & rx_dne_mask);
      rx_buff_head = ((rx_buff_head + ((len-1)/64 + 1)*64) & rx_buff_mask);
      rx_pkt_head = ((rx_pkt_head + ((len-1)/64 + 1)*64) & rx_pkt_mask);
      if(ioctl(nf10.dev_fd, NF10_IOCTL_CMD_SET_RX_DNE_HEAD, rx_dne_head) < 0){
        perror("nf10 set rx dne head failed");
        goto error_out;
      }

      if(ioctl(nf10.dev_fd, NF10_IOCTL_CMD_SET_RX_BUFF_HEAD, rx_buff_head) < 0){
        perror("nf10 set rx buff head failed");
        goto error_out;
      }

      if(ioctl(nf10.dev_fd, NF10_IOCTL_CMD_SET_RX_PKT_HEAD, rx_pkt_head) < 0){
        perror("nf10 set rx pkt head failed");
        goto error_out;
      }

    }
  }

error_out:
  ioctl(nf10.dev_fd, NF10_IOCTL_CMD_STOP_DMA, v);
  close(rx_dne_file);
  close(rx_buff_file);
  return -1;
}

