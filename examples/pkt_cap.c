#include "nf_pktgen.h"
  
int
main(int argc, char *argv[]) {
  int i;
  uint32_t start;
  int32_t pkt_gap = 1000000000;

  printf("Initiating packet generator\n");

  //enable padding
  nf_init(1, 0, 0); 

/*   // Set the number of iterations for the queues with pcap files */
/*   nf_gen_rate_limiter_disable(1, 0); */
/*   nf_gen_rate_limiter_disable(2, 0); */
/*   nf_gen_rate_limiter_disable(3, 0); */

/*   nf_gen_rate_limiter_disable(0, 0);   */
  //nf_gen_rate_limiter_set(2, 0, 2.0);

  nf_gen_set_number_iterations (1, 1, 0);


  struct nf_cap_t * cap2 = nf_cap_enable("nf2c2", 2000);
  if(cap2 == NULL) {
    perror("nf_cap_enable");
  }
  struct nf_cap_t * cap3 = nf_cap_enable("nf2c3", 2000);
  if(cap3 == NULL) {
    perror("nf_cap_enable");
  }

  //load the pcap capture file
  nf_gen_load_pcap("/root/netfpga/projects/packet_generator/sw/http.pcap", 0, 0);

  nf_start(0);
  int count = 0;
  uint8_t *data;
  struct pcap_pkthdr h;
  while( ((data = nf_cap_next(cap3, &h)) != NULL)  && (count < 40)){
    printf("packet %d,%u.%06u \n", ++count, h.ts.tv_sec, h.ts.tv_usec);
    
  }

  printf("nothing captured \n");
  sleep(10);
  
  // Wait until the correct number of packets is sent
  nf_finish();

  return 0;

}


