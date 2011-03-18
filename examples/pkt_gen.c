#include "nf_pktgen.h"

//int queue_addr_offset = OQ_QUEUE_GROUP_INST_OFFSET;

int
main(int argc, char *argv[]) {
  int i;
  uint32_t start;
  int32_t pkt_gap = 1000000000;

  printf("Initiating packet generator\n");

  //enable padding
  nf_init(1, 0, 1); 

/*   // Set the number of iterations for the queues with pcap files */
  nf_gen_rate_limiter_disable(0, 0);
  nf_gen_rate_limiter_disable(1, 0);
  nf_gen_rate_limiter_disable(2, 0);
  nf_gen_rate_limiter_disable(3, 0);
  nf_gen_set_number_iterations (10, 1, 0);
  //nf_gen_set_number_iterations (10, 1, 1);
  nf_gen_set_number_iterations (10, 1, 2);
  //nf_gen_set_number_iterations (10, 1, 3);

  //load the pcap capture file
  nf_gen_load_pcap("/root/netfpga/projects/packet_generator/sw/http.pcap", 0, 0);
  nf_gen_load_pcap("/root/netfpga/projects/packet_generator/sw/http.pcap", 2, 0);

  nf_start(1);


  // Wait until the correct number of packets is sent
  nf_finish();

  return 0;

}




