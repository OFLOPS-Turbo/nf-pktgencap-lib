#include "nf_pktgen.h"

#include <poll.h>
#include <strings.h>

int main(int argc, char *argv[])
{
    int i, fd, ret;
    uint32_t start;
    int32_t pkt_gap = 1000000000;
    /*fd_set fds;*/
    struct pollfd poll_set[1];

    int count = 0;
    const uint8_t *data;
    struct pcap_pkthdr h;

    //enable padding
    nf_init(1, 0, 0);
    nf_gen_set_number_iterations (1, 1, 0);
    struct nf_cap_t *cap1 = nf_cap_enable("nf1", 2000);
    if(cap1 == NULL) {
        perror("nf_cap_enable");
    }

    //load the pcap capture file
    nf_gen_load_pcap("/root/test.cap", 0,  1000000);

    nf_start(0);
    printf("trying to get data\n");

    fd = nf_cap_fileno(cap1);
    while( (count < 100)){
        /*FD_ZERO(&fds);*/
        /*FD_SET(fd, &fds);*/
        /*select(fd+1, &fds, NULL, NULL, NULL);*/

        bzero(poll_set, sizeof(struct pollfd));
        poll_set[0].fd = fd;
        poll_set[0].events |= POLLIN;
        ret = poll(poll_set, 1, 1);

        if(!ret) {
            continue;
        }
        data = nf_cap_next(cap1, &h);
        if (data)
            printf("packet %d,%u.%06u \n", ++count, (uint32_t)h.ts.tv_sec, (uint32_t)h.ts.tv_usec);
        else
            printf("packet %d not captured\n", ++count);

    }
    // Wait until the correct number of packets is sent
    nf_finish();
    usleep(10);
    return 0;
}
