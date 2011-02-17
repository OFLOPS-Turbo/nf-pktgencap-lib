#include "nf_pktgen.h"

//int queue_addr_offset = OQ_QUEUE_GROUP_INST_OFFSET;

int
main(int argc, char *argv[]) {
  int i;
  uint32_t start;
  int32_t pkt_gap = 1000000000;

  printf("Initiating packet generator\n");

  nf_init(1, 0, 0);
  nf_gen_load_pcap("/root/netfpga/projects/packet_generator/sw/http.pcap", 2, 0);  
  nf_gen_set_number_iterations (10, 1, 2);

/*   queue_reorganize(); */

/*   // Load the packets into sram */
  nf_gen_rate_limiter_set(2, 0, 1000); 
/*   load_queues(2); */

/*   // Set the number of iterations for the queues with pcap files */
  nf_gen_rate_limiter_disable(0, 0);   
  nf_gen_rate_limiter_disable(1, 0); 
  //nf_gen_rate_limiter_disable(2, 0); 
  nf_gen_rate_limiter_disable(3, 0); 

  nf_gen_rate_limiter_enable(2, 0);
  nf_start(1);

  //Enable the packet generator hardware to send the packets
  //packet_generator_enable (0xf);

  // Wait until the correct number of packets is sent
  nf_finish();
  //  system (PKT_CMD);

  return 0;

}
