#include "nf_pktgen.h"
  
int
main(int argc, char *argv[]) {
  int i;
  uint32_t start;
  int32_t pkt_gap = 1000000000;

  printf("Initiating packet generator\n");

  //enable padding
  nf_init(1, 0, 0); 


  nf_gen_set_number_iterations (20, 1, 0);


  struct nf_cap_t * cap1 = nf_cap_enable("nf1", 2000);
  if(cap1 == NULL) {
    perror("nf_cap_enable");
  }
  struct nf_cap_t * cap0 = nf_cap_enable("nf2", 2000);
  if(cap0 == NULL) {
    perror("nf_cap_enable");
  }

  //load the pcap capture file
  nf_gen_load_pcap("/root/OSNT/code/osnt_sw/apps/nf1.cap", 0,  1000000);

  nf_start(0);
  int count = 0;
  uint8_t *data;
  struct pcap_pkthdr h;
  printf("trying to get data\n");
  while( ((data = nf_cap_next(cap1, &h)) != NULL)  && (count < 40)){
    printf("packet %d,%u.%06u \n", ++count, h.ts.tv_sec, h.ts.tv_usec);
    
  }

  sleep(10);
  
  // Wait until the correct number of packets is sent
  nf_finish();

  return 0;

}


