#include "nf_pktgen.h"

#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

FILE *out = NULL;

void session_terminate(int signum) {
    fclose(out);
    nf_finish();
    usleep(10);
    printf("terminating session\n");
    exit(0);
}

void print_help(int argc, char *argv[]) {
    printf("error using command options\n");
    printf("usage: ./%s -i input_trace -d interpkt_delay_nsec -o output_file -c iterations -v\n", argv[0]);
}

int main(int argc, char *argv[]) {
    //capture session parameters
    char *filename = "data.pcap";
    uint32_t pkt_gap = 1000000000;
    uint32_t iterations = 1;
    struct pktgen_hdr *pktgen;
    int debug = 0;
    struct nf_cap_t * cap1;
 
    //captured packets data.
    struct pcap_pkthdr h;
    const uint8_t *data;
    // getopt parameters
    int c, i, fd, ret, count = 0;
    // polling informations
    struct pollfd poll_set[1];


    while((c = getopt(argc, argv, "i:d:o:c:vh")) != -1) {
        switch (c) {
            case 'i':
                filename = malloc(strlen(optarg) + 1);
                strcpy(filename, optarg);
                break;
            case 'd':
                pkt_gap = atol(optarg);
                break;
            case 'o':
                out = fopen(optarg, "w");
                break;
            case 'c':
                iterations = atol(optarg);
                break;
            case 'v':
                debug=1;
                break;
            default:
                print_help(argc, argv);
                exit(1);
        }
    }

    if (out == NULL) {
        printf("Invalid output file\n");
        print_help(argc, argv);
        exit(1);
    }

    if (iterations <= 0) {
        printf("invalid iteration number %ld\n", iterations);
        print_help(argc, argv);
        exit(1);
    }

    printf("Initiating packet generator\n");
    signal(SIGINT, session_terminate);

    //enable padding
    nf_init(1, 0, 0);

    //send packet from nf0.
    nf_gen_set_number_iterations (iterations, 1, 0);

    //capture packets on port 1
    cap1 = nf_cap_enable("nf1", 2000);
    if(cap1 == NULL) {
        perror("nf_cap_enable");
    }

    //load the pcap capture file
    nf_gen_load_pcap(filename, 0, pkt_gap);
    nf_start(0);
    while (1) {
        data = nf_cap_next(cap1, &h);
        if (data) {
            pktgen = nf_gen_extract_header(cap1, data, h.caplen);
            if (pktgen) {
                if (debug)
                    printf("packet %d,%u.%09u,%u.%09u\n", ++count, pktgen->seq_num,
                            (uint32_t)h.ts.tv_sec, (uint32_t)h.ts.tv_usec,
                            (uint32_t)pktgen->tv_sec, (uint32_t)pktgen->tv_usec);
                fprintf(out, "%d;%u.%09u;%u.%09u\n", pktgen->seq_num,
                       (uint32_t)h.ts.tv_sec, (uint32_t)h.ts.tv_usec,
                        (uint32_t)pktgen->tv_sec, (uint32_t)pktgen->tv_usec);
                if(count%100 == 0) {
                    printf("captured %d pkts...\n", count);
                }
            } else {
		    printf("packet %d not captured\n", ++count);
	    }
	}
//        } else
//            printf("packet %d not captured\n", ++count);
    }

    session_terminate(SIGINT);
    return 0;

}


