#include "nf_pktgen.h"

#include <stdio.h>
#define __USE_ISOC99 1
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <strings.h>
#include <math.h>
#include <stdlib.h>
#include <inttypes.h>

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/if.h> 
#include <sys/ioctl.h> 
#include <net/ethernet.h>

#include "constants.h"
#include "nf2util.h"
#include "reg_defines_packet_generator.h"

struct nf_cap_t {
  int cap_fd;
  int intf_ix;
  char *name;
  struct pcap_pkthdr *cap_hdr;
  uint8_t *packet_cache;
  int caplen;
};

struct str_nf_pktgen {
  uint32_t *queue_words;
  uint32_t *queue_bytes;
  uint32_t *queue_pkts;
  uint32_t *num_pkts;
  int *queue_base_addr;

  uint32_t *sec_current;
  uint32_t *usec_current;

  char **queue_data;
  uint32_t *queue_data_len;

  float *rate;
  float *clks_between_tokens;
  float *number_tokens;
  
  uint32_t *last_len;
  uint32_t *last_sec;
  uint32_t *last_nsec;

  uint32_t *final_pkt_delay;
  uint32_t *iterations;
  float *delay;

  struct nf_cap_t *obj_cap;

  float *usec_per_byte;
 
  int pad;
  int resolve_ns;
  int xmit_done;

  int nodrop;
  int send_enable;
  int capture_enable;
  int total_words;
  int queue_addr_offset;
  int gen_start;

  struct nf2device nf2;
};

struct str_nf_pktgen nf_pktgen;

/*
 * Util internal functions 
 */
int get_queue_size(int port);
int packet_generator_enable(unsigned status);
const char *queue_name(int queue );
int get_queue_size(int port);
int queue_reorganize();
uint32_t time();
int load_queues(int queue);

/*
 * TODO:
 * - add code to verify that the right bitfile is downloaded.
 */

/////////////////////////////////////////////////////////////
// Name: nf_init
// Initialize the library main object
// Arguements: queue		Queue number
////////////////////////////////////////////////////////////
int
nf_init(int pad, int nodrop,int resolve_ns) {
  int i;

  printf("Initializing pkt gen library\n");
  free(nf_pktgen.queue_words);
  nf_pktgen.queue_words = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  bzero(nf_pktgen.queue_words, NUM_PORTS*sizeof(uint32_t));
  free(nf_pktgen.queue_bytes);
  nf_pktgen.queue_bytes = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  bzero(nf_pktgen.queue_bytes, NUM_PORTS*sizeof(uint32_t));
  free(nf_pktgen.queue_pkts);
  nf_pktgen.queue_pkts = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  bzero(nf_pktgen.queue_pkts, NUM_PORTS*sizeof(uint32_t));
  free(nf_pktgen.queue_base_addr);
  nf_pktgen.queue_base_addr = (int *)xmalloc(NUM_PORTS*sizeof(int));
  bzero(nf_pktgen.queue_base_addr, NUM_PORTS*sizeof(int));
  free(nf_pktgen.num_pkts);
  nf_pktgen.num_pkts = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  bzero(nf_pktgen.num_pkts, NUM_PORTS*sizeof(uint32_t));

  free(nf_pktgen.sec_current);
  nf_pktgen.sec_current = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  bzero(nf_pktgen.sec_current, NUM_PORTS*sizeof(uint32_t));
  free(nf_pktgen.usec_current);
  nf_pktgen.usec_current = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  bzero(nf_pktgen.usec_current, NUM_PORTS*sizeof(uint32_t));

  free(nf_pktgen.queue_data);
  nf_pktgen.queue_data = (char **)xmalloc(NUM_PORTS*sizeof(char *));
  bzero(nf_pktgen.queue_data, NUM_PORTS*sizeof(char *));
  free(nf_pktgen.queue_data_len);
  nf_pktgen.queue_data_len = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  bzero(nf_pktgen.queue_data_len, NUM_PORTS*sizeof(uint32_t));

  free(nf_pktgen.rate);
  nf_pktgen.rate = (float *)xmalloc(NUM_PORTS*sizeof(float));
  bzero(nf_pktgen.rate, NUM_PORTS*sizeof(float));
  free(nf_pktgen.clks_between_tokens);
  nf_pktgen.clks_between_tokens = (float *)xmalloc(NUM_PORTS*sizeof(float));
  bzero(nf_pktgen.clks_between_tokens, NUM_PORTS*sizeof(float));
  free(nf_pktgen.number_tokens);
  nf_pktgen.number_tokens = (float *)xmalloc(NUM_PORTS*sizeof(float));
  bzero(nf_pktgen.number_tokens, NUM_PORTS*sizeof(float));

  free(nf_pktgen.last_len);
  nf_pktgen.last_len = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  bzero(nf_pktgen.last_len, NUM_PORTS*sizeof(uint32_t));
  free(nf_pktgen.last_nsec);
  nf_pktgen.last_nsec = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  bzero(nf_pktgen.last_nsec, NUM_PORTS*sizeof(uint32_t));
  free(nf_pktgen.last_sec);
  nf_pktgen.last_sec = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  bzero(nf_pktgen.last_sec, NUM_PORTS*sizeof(uint32_t));

  free(nf_pktgen.usec_per_byte);
  nf_pktgen.usec_per_byte = (float *)xmalloc(NUM_PORTS*sizeof(float));
  for (i = 0; i< NUM_PORTS; i++) {
    nf_pktgen.usec_per_byte[i] = USEC_PER_BYTE;
  }

  free(nf_pktgen.final_pkt_delay);
  nf_pktgen.final_pkt_delay = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  bzero(nf_pktgen.final_pkt_delay, NUM_PORTS*sizeof(uint32_t));
  free(nf_pktgen.iterations);
  nf_pktgen.iterations = (uint32_t *)xmalloc(NUM_PORTS*sizeof(uint32_t));
  for (i = 0 ; i < NUM_PORTS ; i++)
    nf_pktgen.iterations[i] = 1;
  free(nf_pktgen.delay);
  nf_pktgen.delay = (float *)xmalloc(NUM_PORTS*sizeof(float));
  bzero(nf_pktgen.delay, NUM_PORTS*sizeof(float));

  free(nf_pktgen.obj_cap);
  nf_pktgen.obj_cap = (struct nf_cap_t *)xmalloc(NUM_PORTS*sizeof(struct nf_cap_t));
  for (i = 0; i< NUM_PORTS; i++) {
    nf_pktgen.obj_cap[i].cap_fd = -1;
    nf_pktgen.obj_cap[i].intf_ix = i;
    nf_pktgen.obj_cap[i].name = (char *)xmalloc(sizeof("nf2cX"));
    sprintf(nf_pktgen.obj_cap[i].name, "nf2c%1d", i);
    nf_pktgen.obj_cap[i].cap_hdr = (struct pcap_pkthdr *)xmalloc(sizeof(struct pcap_pkthdr));
    bzero(nf_pktgen.obj_cap[i].cap_hdr,sizeof(struct pcap_pkthdr));
    nf_pktgen.obj_cap[i].packet_cache = NULL;
    nf_pktgen.obj_cap[i].caplen = 0;
  }

  nf_pktgen.capture_enable = 0;
  nf_pktgen.send_enable = 0;
  nf_pktgen.nodrop = nodrop;
  nf_pktgen.pad = pad;
  nf_pktgen.resolve_ns = resolve_ns;
  nf_pktgen.xmit_done = 0;
  nf_pktgen.total_words = 0;
  nf_pktgen.queue_addr_offset = OQ_QUEUE_GROUP_INST_OFFSET;
  nf_pktgen.gen_start = 0;

  //open the write device and 
  nf_pktgen.nf2.device_name = DEFAULT_IFACE;
  if (check_iface(&nf_pktgen.nf2)) 
    exit(1);
  
  if (openDescriptor(&nf_pktgen.nf2))
    exit(1);


  if(packet_generator_enable(0x0)) {
    perror("packet_generator_enable");
    exit(1);
  }
}

////////////////////////////////////////////////////////////
// Name: packet_generator_enable
// Set the control register vaule to enable each queue
// Arguments: status                    the bitmap for the enabled queues
////////////////////////////////////////////////////////////
int 
packet_generator_enable(unsigned status) {
  //Start the queues that are passed into the function
  return writeReg(&nf_pktgen.nf2, PKT_GEN_CTRL_ENABLE_REG, status);
}

/////////////////////////////////////////////////////////////
// Name: get_queue_size
// Get the size of a queue
// Arguements: queue		Queue number
////////////////////////////////////////////////////////////
int
get_queue_size(int port) {
  return (nf_pktgen.queue_words[port] < MIN_TX_QUEUE_SIZE)?
    MIN_TX_QUEUE_SIZE:nf_pktgen.queue_words[port];
}

//////////////////////////////////////////////////////////
// Name: load_queues
//
// Loads the packets into NetFPGA RAM from the hosts memory
//
// Arguments: queue              Queue to load the Pcap into
//
///////////////////////////////////////////////////////////
int 
load_queues(int queue) {
  uint32_t sram_addr = SRAM_BASE_ADDR + nf_pktgen.queue_base_addr[queue] * 16;
  int i;

#if DEBUG
    printf("queue %d len:%d\n", queue, nf_pktgen.queue_data_len[queue]);
#endif
  for (i=0; i<nf_pktgen.queue_data_len[queue];i+=9) {
    writeReg(&nf_pktgen.nf2, (sram_addr+0x4), 
	     *((uint8_t *)(nf_pktgen.queue_data[queue] + i)));
    writeReg(&nf_pktgen.nf2, (sram_addr+0x8), 
	     htonl(*((uint32_t *)(nf_pktgen.queue_data[queue] + i + 1))));
    writeReg(&nf_pktgen.nf2, (sram_addr+0xc), 
	     htonl(*(uint32_t *)(nf_pktgen.queue_data[queue] + i + 5)));

#if DEBUG
        printf("%x %08x %08x %08lx\n",  
    	   (sram_addr+0x4), *((uint8_t *)(nf_pktgen.queue_data[queue] + i)),  
	       htonl(*((uint32_t *)(nf_pktgen.queue_data[queue] + i + 1))),  
	       htonl(*((uint32_t *)(nf_pktgen.queue_data[queue] + i + 5)))); 

#endif 
    sram_addr += 16;
  }
  return 0;
}

////////////////////////////////////////////////////////////
// Name: load_packet
// Append a packet on the local data cache of the data send out of a specific port
// Arguments: data             A pointer to the data cache
//            port             The number of the port we want to output the packet
//            delay            Delay from the previous packet
////////////////////////////////////////////////////////////
int
nf_gen_load_packet(struct pcap_pkthdr *h, const unsigned char *data, int port, int32_t delay) {
  uint32_t src_port = 0, dst_port = 0x100;
  uint32_t sec = h->ts.tv_sec, usec = h->ts.tv_usec;
  uint32_t len = h->len, caplen = h->caplen, word_len = ceil(((float)len)/8), packet_words;
  uint32_t tmp_data,  pointer;
  uint32_t non_pad_len = len;
  uint32_t non_pad_word_len = word_len;
  uint32_t write_pad = 0;
  
  dst_port = (dst_port << port);
  
  //If the delay is not specified assign based on the Pcap file
  if (delay == -1) {
    delay = sec - nf_pktgen.sec_current[port];
    delay = delay * 1000000; // convert to usec
    delay = ((usec + delay) - nf_pktgen.usec_current[port]);
    delay = delay * 1000; // convert to nsec
  }
  
  // Work out if this packet should be padded
  if ((nf_pktgen.pad) && (non_pad_len > 64)) {
    write_pad = 1;
    non_pad_len = 64;
    non_pad_word_len = 8;
  }
  
  // Check if there is room in the queue for the entire packet
  // 	If there is no room return 1

  packet_words = non_pad_word_len + 1 + (delay > 0) + (write_pad);
  if ( (packet_words + nf_pktgen.total_words) > MAX_TX_QUEUE_SIZE) {
    printf("Warning: unable to load all packets from pcap file. SRAM queues are full.\n");
    printf("Total output queue size: %d words\n",MAX_TX_QUEUE_SIZE);
    printf("Current queue occupancy: %lu words\n", nf_pktgen.total_words);
    printf("Packet size:%lu words\n", packet_words);
    return 0;
  } else {
    nf_pktgen.total_words += packet_words;
    nf_pktgen.queue_words[port] += packet_words;
    nf_pktgen.queue_bytes[port] += len;
     nf_pktgen.queue_pkts[port]++;
  }
  
  //Update the current time
  nf_pktgen.sec_current[port] = sec;
  nf_pktgen.usec_current[port] = usec;
  
  nf_pktgen.usec_current[port] += (len + 4) * nf_pktgen.usec_per_byte[port];
  
  while ( nf_pktgen.usec_current[port] > pow(10,6)) {
    nf_pktgen.usec_current[port] -= pow(10,6);
    nf_pktgen.sec_current[port]++;
  }
  
  // Load module hdr into SRAM
  pointer = nf_pktgen.queue_data_len[port];
  nf_pktgen.queue_data_len[port] += 9;
  nf_pktgen.queue_data[port] = realloc(nf_pktgen.queue_data[port], nf_pktgen.queue_data_len[port]);
  nf_pktgen.queue_data[port][pointer] = IO_QUEUE_STAGE_NUM;
  tmp_data = ntohl(non_pad_word_len | (dst_port << 16));
  memcpy(nf_pktgen.queue_data[port] + pointer + 1,  &tmp_data, 4);
  tmp_data =  ntohl(non_pad_len | (src_port << 16));
  memcpy(nf_pktgen.queue_data[port] + pointer + 5,  &tmp_data, 4);

#if DEBUG
  printf("0x%02x 0x%02x%02lx%02lx%02lx 0x%02x%02lx%02lx%02lx\n",
	 (unsigned char)IO_QUEUE_STAGE_NUM,
	 (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 1),
	 (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 2),
	 (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 3),
	 (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 4),
	 (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 5),
	 (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 6),
	 (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 7),
	 (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 8));
#endif

  // Load pad hdr into SRAM
  if (write_pad) {
    pointer = nf_pktgen.queue_data_len[port];
    nf_pktgen.queue_data_len[port] += 9;
    nf_pktgen.queue_data[port] = realloc(nf_pktgen.queue_data[port], nf_pktgen.queue_data_len[port]);
    nf_pktgen.queue_data[port][pointer] = PAD_CTRL_VAL;
    tmp_data = ntohl(word_len | (dst_port << 16));
    memcpy(nf_pktgen.queue_data[port] + pointer + 1,  &tmp_data, 4);
    tmp_data =  ntohl( len | (src_port << 16));
    memcpy(nf_pktgen.queue_data[port] + pointer + 5,  &tmp_data, 4);
#if DEBUG
    printf("0x%02x 0x%02x%02lx%02lx%02lx 0x%02x%02lx%02lx%02lx\n",
	   (unsigned char) PAD_CTRL_VAL,
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 1),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 2),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 3),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 4),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 5),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 6),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 7),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 8));
#endif
  }
  
  //Load delay into SRAM if it exists
  if (delay > 0) {
  
    lldiv_t res;
    res = lldiv(delay, powl(2,32));
    
    printf("delay : %ld\n", delay);
    pointer = nf_pktgen.queue_data_len[port];
    nf_pktgen.queue_data_len[port] += 9;
    nf_pktgen.queue_data[port] = realloc(nf_pktgen.queue_data[port], nf_pktgen.queue_data_len[port]);
    nf_pktgen.queue_data[port][pointer] = DELAY_CTRL_VAL;
    printf("div: %f, res : %ld\n", pow(2,32), res.quot);
    tmp_data =  ntohl((int32_t) res.quot);
    memcpy(nf_pktgen.queue_data[port] + pointer + 1,  &tmp_data, 4);
    printf("div: %f, res : %ld\n", pow(2,32), res.rem);
    tmp_data = ntohl((int32_t)fmod(delay, pow(2, 32)));
    memcpy(nf_pktgen.queue_data[port] + pointer + 5,  &tmp_data, 4);
#if DEBUG
    printf("0x%02x 0x%02x%02lx%02lx%02lx 0x%02x%02lx%02lx%02lx\n",
	   (unsigned char) DELAY_CTRL_VAL, 
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 1),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 2),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 3),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 4),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 5),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 6),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 7),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 8));
#endif
  }
  
  //Store the packet into SRAM
  uint32_t i;
  uint32_t count = (nf_pktgen.pad)?non_pad_len:len;

  for(i = 0; i < count; i += 8){
    uint16_t ctrl = 0x0;
    if ((i/8) == non_pad_word_len - 1) {
      ctrl = 0x100 >> (non_pad_len % 8);
      ctrl = ((ctrl & 0xff) | (ctrl == 0x100)); //in case control is 0?
    }

    pointer = nf_pktgen.queue_data_len[port];
    nf_pktgen.queue_data_len[port] += 9;
    nf_pktgen.queue_data[port] = realloc(nf_pktgen.queue_data[port], 
					  nf_pktgen.queue_data_len[port]);
    nf_pktgen.queue_data[port][pointer] = (uint8_t)ctrl;
    bzero(nf_pktgen.queue_data[port] + pointer + 1, 8);
    memcpy(nf_pktgen.queue_data[port] + pointer + 1, data + i, 8);
#if DEBUG
    printf("0x%02x 0x%02x%02lx%02lx%02lx 0x%02x%02lx%02lx%02lx\n",  
	   ctrl, (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 1), 
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 2),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 3),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 4),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 5),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 6),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 7),
	   (unsigned char)*(nf_pktgen.queue_data[port] + pointer + 8)); 
#endif
  }

  //Calculate the delay between the preceding packet and this packet
  //It should be the maximum of the delay specified in the header
  // and the delay introduced by the rate limiter
  uint32_t delay_hdr = delay;
  uint32_t delay_rate = 0;
  if (nf_pktgen.rate[port] >= 1) {
    delay_rate = ceil(nf_pktgen.last_len[port] / nf_pktgen.number_tokens[port]);
    delay_rate *= nf_pktgen.clks_between_tokens[port] * NSEC_PER_BYTE;
  }
  uint32_t delay_max = delay_hdr > delay_rate ? delay_hdr : delay_rate;
  delay_max -= (nf_pktgen.last_len[port] + FCS_LEN) * NSEC_PER_BYTE;
  delay_max = (delay_max < 0)?0:delay_max;
  delay_max += ((len > MIN_PKT_SIZE ? len : MIN_PKT_SIZE) +
		 FCS_LEN + OVERHEAD_LEN) * NSEC_PER_BYTE;

  // Update packet transmit time
  nf_pktgen.last_nsec[port] += delay_max;
  nf_pktgen.last_len[port] = len;

  while (nf_pktgen.last_nsec[port] > pow(10,9)) {
    nf_pktgen.last_nsec[port] -= pow(10,9);
    nf_pktgen.last_sec[port]++;
  }

  // Assume this is the last packet and update the amount of extra time
  // to wait for this packet to pass through the delay module. (We'll
  // eventually guess right that this is the last packet.)
  nf_pktgen.final_pkt_delay[port] = 0;
  if (nf_pktgen.rate[port] >= 1) {
    nf_pktgen.final_pkt_delay[port] = ceil((len + FCS_LEN) / nf_pktgen.number_tokens[port]);
    nf_pktgen.final_pkt_delay[port] *= nf_pktgen.clks_between_tokens[port];
    nf_pktgen.final_pkt_delay[port] -= len + FCS_LEN;
    nf_pktgen.final_pkt_delay[port] *= NSEC_PER_BYTE;
  }

  return 0;
}

////////////////////////////////////////////////////////////
// Name: load_pcap
// Append the packets of the pcap capture on the local data cacheof the specific port
// Arguments: filename         A pointer to the location where the packet will be send
//            port             The number of the port we want to output the packet (0-3)
//            delay            Delay from the previous packet
////////////////////////////////////////////////////////////
int
nf_gen_load_pcap(const char *filename, int port, int32_t delay) {
  pcap_t *pcap; 
  const unsigned char *data;
  struct pcap_pkthdr h;
  char errbuf[PCAP_ERRBUF_SIZE];

  if((pcap = pcap_open_offline(filename, errbuf)) == NULL) {
    fprintf(stderr, "pcap_open_offline:%s\n", errbuf);
    exit(1);
  }
  printf("laod file %s with delay %ld\n", filename, delay);

  while((data = pcap_next(pcap, &h)) != NULL) {
    if (h.len != h.caplen) {
      fprintf(stderr, "Warning: The capture length was less than the packet length for one");
      fprintf(stderr, " or more packets in '$pcap_filename'. Packets will be0001fffc padded with zeros.\n");
    }

#if DEBUG
    printf("load packet on queue %d, with delay %ld\n", 
	   port, delay);
#endif
    if(nf_pktgen.sec_current[port] == 0) {
      nf_pktgen.sec_current[port] = h.ts.tv_sec;
      nf_pktgen.usec_current[port] = h.ts.tv_usec;
    }

    if(nf_gen_load_packet(&h, data, port, delay) == 0) 
      nf_pktgen.num_pkts[port]++;
    else
      break;
  }

  pcap_close(pcap);
}

/////////////////////////////////////////////////////////////////
// Name: set_number_iterations
// Sets the number of iterations for a Packet Generator Queue
// Arguments: number_iterations number of iterations for queue
//            iterations        enable the number of iterations
//            queue             queue number (0-3)
// Control register
//       bit 0 -- enable queueIO_QUEUE_STAGE_NUM
//       bit 1 -- initialize queue (set to 1)
/////////////////////////////////////////////////////////////////
int 
nf_gen_set_number_iterations(int number_iterations, int iterations_enable, int queue) {
  writeReg(&nf_pktgen.nf2, 
	   OQ_QUEUE_0_CTRL_REG+(queue+2*NUM_PORTS)*nf_pktgen.queue_addr_offset, 
	   0x1);
  printf("%X %X\n",
	 OQ_QUEUE_0_CTRL_REG+(queue+2*NUM_PORTS)*nf_pktgen.queue_addr_offset, 0x1);

   writeReg(&nf_pktgen.nf2, 
	   OQ_QUEUE_0_MAX_ITER_REG+(queue+2*NUM_PORTS)*nf_pktgen.queue_addr_offset, 
	   number_iterations);
  printf("%X %X\n",
	 OQ_QUEUE_0_MAX_ITER_REG+(queue+2*NUM_PORTS)*nf_pktgen.queue_addr_offset,
	 number_iterations);
  nf_pktgen.iterations[queue] = number_iterations;
   return 1;
}

/////////////////////////////////////////////////////////////////
// Name: rate_limiter_enable
// Enables the rate limiter for a queue
// Arguments: queue    queue to enable the rate limiter on
/////////////////////////////////////////////////////////////////
int
nf_gen_rate_limiter_enable(int port, int cpu) {
  uint32_t rate_limit_offset = RATE_LIMIT_1_CTRL_REG - RATE_LIMIT_0_CTRL_REG;
  int queue = 2*port + cpu;
  return writeReg(&nf_pktgen.nf2, RATE_LIMIT_0_CTRL_REG+(queue*rate_limit_offset), 0x1);
}

//////////////////////////////////////////////////////////////
// Name: rate_limiter_set
// Set the rate limiter value of an output queue
// Arguments: queue  queue to enable the rate limiter on
//            rate   the rate to set for the output queue
/////////////////////////////////////////////////////////////
int
nf_gen_rate_limiter_set(int port, int cpu, float rate) {
  uint32_t clks_between_tokens = 1000000;
  float number_tokens = 1;

  float epsilon = 0.001;
  uint32_t MAX_TOKENS = 84;
  uint32_t BITS_PER_TOKEN = 8;
  int queue = 2*port + cpu;

  // Check if we really need to limit this port
  if (rate < 1)
    return 0;
  
  clks_between_tokens = 1;
  rate = (rate * 1000) / BITS_PER_TOKEN;
  number_tokens = (rate * clks_between_tokens) / CLK_FREQ;
  
  // Attempt to get the number of tokens as close as possible to a
  // whole number without being too large
  float token_inc = number_tokens;
  uint32_t min_delta = 1;
  uint32_t min_delta_clk = 1;
  while (((number_tokens < 1) || (number_tokens - floor(number_tokens) > epsilon)) &&
	 (number_tokens < MAX_TOKENS)) {
    number_tokens += token_inc;
    clks_between_tokens += 1;

    // Verify that number_tokens exceeds 1
    if (number_tokens > 1) {
      // See if the delta is lower than the best we've seen so far
      int delta = number_tokens - floor(number_tokens);
      if (delta < min_delta) {
	min_delta = delta;
	min_delta_clk = clks_between_tokens;
      }
    }
  }

  // Adjust the number of tokens/clks between tokens to get the closest to a whole number of
  // tokens per increment
  if (number_tokens - floor(number_tokens) > epsilon) {
    clks_between_tokens = min_delta_clk;
    number_tokens = floor(token_inc * clks_between_tokens);
  }

  // Calculate what the actual rate will be
  rate = number_tokens * CLK_FREQ / clks_between_tokens;
  rate = (rate * BITS_PER_TOKEN) / 1000;
  
  printf("Limiting %s  to %f (", queue_name(queue), rate);
  printf("tokens = %f, ", number_tokens);
  printf("clks = %d)\n", clks_between_tokens);
  
  int rate_limit_offset = RATE_LIMIT_1_CTRL_REG - RATE_LIMIT_0_CTRL_REG;
  
  writeReg(&nf_pktgen.nf2, RATE_LIMIT_0_TOKEN_INTERVAL_REG + (queue * rate_limit_offset), clks_between_tokens);
  writeReg(&nf_pktgen.nf2, RATE_LIMIT_0_TOKEN_INC_REG + (queue * rate_limit_offset), number_tokens);
  
  if(!cpu) {
    nf_pktgen.clks_between_tokens[port] = clks_between_tokens;
    nf_pktgen.number_tokens[port] = number_tokens;
  }
  
  return 1;
}

//////////////////////////////////////////////////////////////////
// Name: rate_limiter_disable
// Disables the rate limiter for a queue
// Arguments: queue    queue to disable the rate limiter on
////////////////////////////////////////////////////////////////
int
nf_gen_rate_limiter_disable(int port, int cpu) {
  int queue = 2*port + 1;
  uint32_t rate_limit_offset = RATE_LIMIT_1_CTRL_REG - RATE_LIMIT_0_CTRL_REG;
   return writeReg(&nf_pktgen.nf2, 
		   RATE_LIMIT_0_CTRL_REG+(queue*rate_limit_offset), 0x0);
   //return 0;
}

///////////////////////////////////////////////////
// Name: reset_delay
// Reset the delay modules
//////////////////////////////////////////////////
void 
reset_delay() {
	writeReg(&nf_pktgen.nf2, DELAY_RESET_REG, 1);
}

////////////////////////////////////////////////////////////////
// Name: queue_name
// Convert a queue number to a name
// Arguments: queue      Queue number
///////////////////////////////////////////////////////////////
char queue_name_buf[100];
const char *
queue_name(int queue ) {
  if (queue < 0 || queue >= 12) 
    return "Invalid queue";
  else if (queue < 8) {
    if (queue % 2 == 0) 
      snprintf(queue_name_buf, 100, "MAC Queue %d", queue/2);
    else 
      snprintf(queue_name_buf, 100, "CPU Queue %d", (queue-1)/2);
  } else 
      snprintf(queue_name_buf, 100, "MAC Queue %d", queue - 8);
  return queue_name_buf;
}

///////////////////////////////////////////////////////////
// Name: queue_reorganize
// Reorganizes the queues
// Arguments: None
//////////////////////////////////////////////////////////
int
queue_reorganize() {

  uint32_t queue_addr_offset = OQ_QUEUE_1_ADDR_LO_REG - OQ_QUEUE_0_ADDR_LO_REG;
  
  uint32_t curr_addr = 0;
  uint32_t rx_queue_size[] = {0,0,0,0};
  
  // Calculate the size of the receive queues
  //  - all unallocated memory given to rx queues
  //  - all receive queues are sized equally
  //    (first queue given any remaining memory)
  uint32_t queue_free = MEM_SIZE - NUM_PORTS * XMIT_QUEUE_SIZE;
  int i;
  for (i = 0; i < NUM_PORTS; i++) 
    queue_free -= get_queue_size(i);
  
  for(i=0; i< NUM_PORTS; i++) 
    rx_queue_size[i] = floor( ((float)queue_free) / NUM_PORTS);

  rx_queue_size[0] += queue_free - NUM_PORTS * rx_queue_size[0]; //what's left, added up to the first queue

  for(i=0; i< NUM_PORTS; i++) {
    printf("queue %d: %d (count %d %f)\n", i,  rx_queue_size[i], queue_free, (((float)queue_free)/NUM_PORTS) );
  }
  
  
  // Disable output queues
  // Note: 3 queues per port -- rx, tx and tx-during-setup
  for (i = 0; i < 3 * NUM_PORTS; i++) {
    writeReg(&nf_pktgen.nf2, OQ_QUEUE_0_CTRL_REG + (i*queue_addr_offset), 0x00);
    printf("%08lx %08lx\n", OQ_QUEUE_0_CTRL_REG + (i*queue_addr_offset), 0x00);
  }
  
  // Resize the queues
  for (i = 0; i < NUM_PORTS; i++) {
    // Set queue sizes for tx-during-setup queues
    writeReg(&nf_pktgen.nf2,
	     (OQ_QUEUE_0_ADDR_LO_REG + (i * 2)*queue_addr_offset), curr_addr);
    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_LO_REG + (i * 2)*queue_addr_offset), curr_addr);
		 
    writeReg(&nf_pktgen.nf2, 
	     (OQ_QUEUE_0_ADDR_HI_REG + (i*2)*queue_addr_offset), 
	     curr_addr + XMIT_QUEUE_SIZE - 1);
    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_HI_REG + (i*2)*queue_addr_offset), curr_addr + XMIT_QUEUE_SIZE - 1);

    writeReg(&nf_pktgen.nf2, 
	     (OQ_QUEUE_0_CTRL_REG + (i*2)*queue_addr_offset), 0x02);
    printf("%08lx %08lx\n", (OQ_QUEUE_0_CTRL_REG + (i*2)*queue_addr_offset), 0x02);
    curr_addr += XMIT_QUEUE_SIZE;

    // Set queue sizes for RX queues
    writeReg(&nf_pktgen.nf2, 
	     (OQ_QUEUE_0_ADDR_LO_REG + (i*2+1)*queue_addr_offset), curr_addr);
    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_LO_REG + (i*2+1)*queue_addr_offset), curr_addr);
    
    writeReg(&nf_pktgen.nf2, 
	     (OQ_QUEUE_0_ADDR_HI_REG + (i*2+1)*queue_addr_offset), curr_addr + rx_queue_size[i] - 1);
    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_HI_REG + (i*2+1)*queue_addr_offset), curr_addr + rx_queue_size[i] - 1);
    
    writeReg(&nf_pktgen.nf2,
	     (OQ_QUEUE_0_CTRL_REG + (i*2 + 1) * queue_addr_offset), 0x02);
    printf("%08lx %08lx\n", (OQ_QUEUE_0_CTRL_REG + (i*2 + 1) * queue_addr_offset), 0x02);
    curr_addr += rx_queue_size[i];
  }

  for (i = 0; i < NUM_PORTS; i++) {
    uint32_t queue_size = get_queue_size(i);

    // Set queue sizes for TX queues
    writeReg(&nf_pktgen.nf2, 
	     (OQ_QUEUE_0_ADDR_LO_REG + (i + 2*NUM_PORTS)*queue_addr_offset), 
	     curr_addr);
    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_LO_REG + (i + 2*NUM_PORTS)*queue_addr_offset), curr_addr);
    
    writeReg(&nf_pktgen.nf2,(OQ_QUEUE_0_ADDR_HI_REG+(i+2*NUM_PORTS)*queue_addr_offset), 
	     curr_addr + queue_size - 1);
    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_HI_REG + (i + 2*NUM_PORTS)*queue_addr_offset), curr_addr + queue_size - 1);
    
    writeReg(&nf_pktgen.nf2,(OQ_QUEUE_0_CTRL_REG+(i+2*NUM_PORTS)*queue_addr_offset),0x02);
    printf("%08lx %08lx\n",(OQ_QUEUE_0_CTRL_REG + (i + 2*NUM_PORTS)*queue_addr_offset),0x02);

    nf_pktgen.queue_base_addr[i] = curr_addr;
    curr_addr += queue_size;
  }

  // Enable Output Queues that are not associated with Packet Generation
  for (i = 0; i < 2*NUM_PORTS; i++) {
    writeReg(&nf_pktgen.nf2, 
	     (OQ_QUEUE_0_CTRL_REG + i*queue_addr_offset), 0x01);
    printf("%08lx %08lx\n",(OQ_QUEUE_0_CTRL_REG + i*queue_addr_offset), 0x01);
  }

  return 0;
}

//////////////////////////////////////////////////
// Name: disable_queue
// Disable one of the queues
// Arguments: queue             queue number (0-11)
//////////////////////////////////////////////////
void
disable_queue(int queue) { 
  writeReg(&nf_pktgen.nf2, 
	   OQ_QUEUE_0_CTRL_REG + queue * nf_pktgen.queue_addr_offset, 
	   0x0);
}

/////////////////////////////////////////////////////////
// Name: time
// A simple action to get current second since epoch
/////////////////////////////////////////////////////////
uint32_t 
time() {
  struct timeval now;
  gettimeofday(&now, NULL);
  return now.tv_sec;
}

//////////////////////////////////////////////////////////////////
// name: nf_start
// A function to load data and put the generator to start capturing data.
// 
/////////////////////////////////////////////////////////////////
int
nf_start(int  wait) {
  int i;

  //organize the queue sizes
  queue_reorganize();

  // Load the packets into sram
  for (i = 0; i < NUM_PORTS; i++) {
    if (nf_pktgen.queue_data_len[i]) {
      printf("loading data on queue %d\n", i);
      load_queues(i);
    }
  }

  //set on the cpu queues a rate limiter
/*   for (i = 0; i < 4; i++) { */
/*     nf_gen_rate_limiter_set(i,1, 200000.0); */
/*     nf_gen_rate_limiter_enable(i, 1); */
    
/*   } */

  //Enable the packet generator hardware to send the packets
  int drop = 0;
  if (!nf_pktgen.nodrop) { // in case we are not capturing on some queue, don't drop packets
    for (i = 0; i < NUM_PORTS; i++) 
      if (nf_pktgen.obj_cap[i].cap_fd != -1) {
	printf("receive data on port %d\n", i);
	drop |= (1 << i);
      }    
    drop <<= 8;
  }

#if DEBUG
  //set to drop packets on queues that we don't receive data
  printf("droping mask: %x\n", drop | 0xF);
#endif
  packet_generator_enable (drop | 0xF);
  nf_pktgen.gen_start = time();

  if(wait) 
    nf_gen_wait_end();
}

int
nf_finish() {
  // Disable the packet generator
  //  1. disable the output queues
  //  2. reset the delay module
  //   -- do this multiple times to flush any remaining packets
  //       The syncfifo is 1024 entries deep -- we should need far
  //       fewer than this to ensure the FIFO is flushed
  //  3. disable the packet generator
  int i;
  for (i = 0; i < NUM_PORTS; i++) {
    disable_queue(i + 8);
  }
  sleep(1);
  for (i = 0; i < 1024; i++) {
    reset_delay();
  }
  sleep(1);
  packet_generator_enable(0x0);
  reset_delay();
}

//////////////////////////////////////////////////////////////////
// name: nf_gen_finished
// The function after the last packet has been send. 
//////////////////////////////////////////////////////////////////
int
nf_gen_wait_end() {
  int i;
  double last_pkt = 0, delta = 0;
  for (i = 0; i < NUM_PORTS; i++) {
    if (nf_pktgen.queue_data_len[i]) {
      double queue_last = ((double)nf_pktgen.last_sec[i]) + 
	((double)nf_pktgen.last_nsec[i] * pow(10,-9));
      queue_last = queue_last *((double)nf_pktgen.iterations[i]);
      queue_last += (nf_pktgen.final_pkt_delay[i] * pow(10, -9)) * 
      	(nf_pktgen.iterations[i] - 1.0);
      printf("queue %d last sec : %lu.%09lu, last: %f, iterations : %d, len : %d\n", 
	     i, nf_pktgen.last_sec[i], nf_pktgen.last_nsec[i], 
	     queue_last, nf_pktgen.iterations[i], nf_pktgen.queue_data_len[i]);
      if (queue_last > last_pkt) {
	  last_pkt = queue_last;
      }
    }
  }
  
  printf("delta : %f, last_pkt: %.09f\n", delta, last_pkt);
  // Wait the requesite number of seconds
  while (delta <= last_pkt) {
    printf("\r%1.3f seconds elapsed...\n", delta);
    sleep(1);
    delta = ((double)time()) - nf_pktgen.gen_start;
  }  
}

//////////////////////////////////////////////////////////////////
// name: nf_gen_finished
// A funtction that return 0 in case the packet generation is not finished,
// otherwise 1.
//////////////////////////////////////////////////////////////////
int
nf_gen_finished() {
  int delta, i;
  float last_pkt = 0;
  for (i = 0; i < NUM_PORTS; i++) {
    if (nf_pktgen.queue_data_len[i]) {
      double queue_last = (nf_pktgen.last_sec[i] * 1.0) + 
	(nf_pktgen.last_nsec[i] * pow(10,-9));
      queue_last *= (nf_pktgen.iterations[i] * 1.0);
      queue_last += (nf_pktgen.final_pkt_delay[i] * pow(10, -9)) * (nf_pktgen.iterations[i] - 1.0);
      if (queue_last > last_pkt) {
	  last_pkt = queue_last;
      }
    }
  }
  return ((time() - nf_pktgen.gen_start) > last_pkt);
}

/////////////////////////////////////////////////////////////
// Name: display_capture_metrics
// Display the metrics capture by the card
/////////////////////////////////////////////////////////////
int
nf_cap_stat(int queue, struct nf_cap_stats *stat) {
  int offset = 0;
  uint32_t time_first_hi = 0, time_first_lo = 0;
  uint32_t time_last_hi = 0, time_lsdt_lo = 0;
  uint32_t byte_cnt_hi = 0, byte_cnt_lo = 0;
  uint32_t delta_hi = 0, delta_lo = 0;
  uint64_t res = 0;

  if((queue < 0) || (queue >= NUM_PORTS)) {
    printf("nf_cap_stat: queue number is incorrect\n");
    return -1;
  }

  offset = queue*(PKT_GEN_CTRL_1_PKT_COUNT_REG-PKT_GEN_CTRL_0_PKT_COUNT_REG);
    
  readReg(&nf_pktgen.nf2, PKT_GEN_CTRL_0_PKT_COUNT_REG+offset, &stat->pkt_cnt);
  readReg(&nf_pktgen.nf2, PKT_GEN_CTRL_0_BYTE_COUNT_HI_REG+offset, &byte_cnt_hi);
  readReg(&nf_pktgen.nf2, PKT_GEN_CTRL_0_BYTE_COUNT_LO_REG+offset, &byte_cnt_lo);

  stat->byte_cnt = ((uint64_t)byte_cnt_hi)*pow(2,32) + (byte_cnt_lo);
/*   readReg(nf_pktgen.nf2, PKT_GEN_CTRL_0_TIME_FIRST_HI_REG+offset, &time_first_hi); */
/*   readReg(nf_pktgen.nf2, PKT_GEN_CTRL_0_TIME_FIRST_LO_REG+offset, &time_first_lo); */
  
/*   readReg(nf_pktgen.nf2, PKT_GEN_CTRL_0_TIME_LAST_HI_REG+offset, &time_last_hi); */
/*   readReg(nf_pktgen.nf2, PKT_GEN_CTRL_0_TIME_LAST_LO_REG+offset, &time_last_lo); */
     
/*   delta_hi = time_last_hi - time_first_hi; */
/*   delta_lo = time_last_lo - time_first_lo; */
    
/*   if (time_first_lo > time_last_lo) { */
/*     delta_hi--; */
/*     delta_lo += 2**32; */
/*   } */
    
/*   res = ((uint64_t)delta_hi)*pow(2,32); */
/*   sec = (delta_lo+())/pow(10,9); */
/* nsec = (($delta_lo+($delta_hi*2^32))%pow(10,9)); */
    
/*     my $time = $sec + ($nsec / 10**9); */
/*     my $rate_data_only = 0; */
/*     my $rate_all = 0; */
/*     if ($time != 0) { */
/*       $rate_data_only = $byte_cnt / $time / 1000 * 8; */
/*       $rate_all = ($byte_cnt + 20 * $pkt_cnt) / $time / 1000 * 8; */
/*     } */
/*     printf "%s:\n", queue_name($i + 8); */
/*     printf "\tPackets: %u\n", $pkt_cnt; */
/*     if ($pkt_cnt > 0) { */
/*       printf "\tBytes: %1.0f\n", $byte_cnt; */
/*       printf "\tTime: %1d.%09d s\n", $sec, $nsec; */
/*       printf "\tRate: %s (packet data only)\n", rate_str($rate_data_only); */
/*       printf "\tRate: %s (including preamble/inter-packet gap)\n", rate_str($rate_all); */
/*     } */
/*   } */
/*   print "\n\n"; */
  return 1;
}

/////////////////////////////////////////////////////////////
// Name: nf_gen_stat
// Display the metrics of sent packets maintained by the card
/////////////////////////////////////////////////////////////
int
display_xmit_metrics(int queue, struct nf_gen_stats *stat) {
  return readReg(&nf_pktgen.nf2,
		 OQ_QUEUE_0_NUM_PKTS_REMOVED_REG+(queue+8)*nf_pktgen.queue_addr_offset,
		 &stat->pkt_snd_cnt);
/*   nf_regread(nf_pktgen.nf2,  */
/* 	     OQ_QUEUE_0_CURR_ITER_REG+(i+8)*nf_pktgen.queue_addr_offset, */
/* 	      &stat->pkt_cnt); */
} 



struct nf_cap_t *
nf_cap_enable(char *dev_name, int caplen) {
  struct sockaddr_ll sockaddr;
  struct ifreq ifr;
  int ix;
  struct nf_cap_t *cap;
  
  //check data
  if((!dev_name) || (caplen <= 0) ) {
    printf("Invalid data");
    return NULL;
  }

  //find dev ix
  for(ix = 0 ; ix < NUM_PORTS; ix++) 
    if(strcmp(nf_pktgen.obj_cap[ix].name, dev_name) == 0) break;

  if(ix == NUM_PORTS) {
    printf("Invalid device name\n");
    return NULL;
  } else 
    cap = &nf_pktgen.obj_cap[ix];

  //open fd
  cap->cap_fd = socket(PF_PACKET, SOCK_RAW, ETH_P_ALL);
  if(cap->cap_fd == -1) {
    perror("socket():");
    return NULL;
  }

  //TODO: check if capturing has started and warn

  //retrieve ethernet interface index
  strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
  if (ioctl(cap->cap_fd, SIOCGIFINDEX, &ifr) == -1) {
    perror("SIOCGIFINDEX");
    return NULL;
  }

  sockaddr.sll_family = AF_PACKET; /* Always AF_PACKET */
  sockaddr.sll_protocol =  htons(ETH_P_ALL); /* Physical layer protocol */
  sockaddr.sll_ifindex =  ifr.ifr_ifindex; /* Interface number */

  //bind interface to the socket
  if( bind(cap->cap_fd, (struct sockaddr*)&sockaddr,sizeof(sockaddr)) == -1) {
    printf("Error 20008\nCould not bind Socket to Device!");
    return NULL;
  }

  //set it in promiscuous mode
  strncpy(ifr.ifr_name, dev_name, 16);
  ioctl(cap->cap_fd,SIOCGIFFLAGS,&ifr);
  ifr.ifr_flags |= IFF_PROMISC;
  ioctl(cap->cap_fd, SIOCSIFFLAGS, &ifr);

  //allocate memory for the packet
  cap->caplen = caplen;
  cap->packet_cache = (uint8_t *)xmalloc(caplen);
  if(cap->packet_cache) {
    return NULL;
  }
  
  return cap;
};

//////////////////////////////////////////////
// name: nf_cap_fileno
// Rertrieve a selectable filedescriptor 
// param: cap               the capturing object of the relecant field
//////////////////////////////////////////////
int  
nf_cap_fileno(struct nf_cap_t *cap) {
  if(cap) return cap->cap_fd;
  else return -1;
};

const uint8_t *
nf_cap_next(struct nf_cap_t *cap, struct pcap_pkthdr *h) {
  uint8_t data[2048];
  int len;
  uint64_t time_count;

  if((cap == NULL) || (cap->cap_fd != 1)) {
#if DEBUG
    fprintf(stderr, "enable capturing first");
#endif
    return NULL;
  }

  len = recv(cap->cap_fd, data, 2048, 0);
  if(len <= 24) return NULL;
  h->len = len -24;
  len = (cap->caplen >= (len -24))? (len-24):cap->caplen;
  h->caplen = len;
  
  //set timestamp of packet
  memcpy(&time_count, data + 16, sizeof(uint64_t));

  lldiv_t res;
  if(nf_pktgen.resolve_ns) 
    res = lldiv(time_count, powl(10,9));
  else
    res = lldiv(time_count, powl(10,6));
    
  h->ts.tv_sec = (uint32_t) res.quot;
  h->ts.tv_usec = (uint32_t) res.rem;

  //return data
  memcpy(cap->packet_cache, data + 24, len);

  return cap->packet_cache;
}
