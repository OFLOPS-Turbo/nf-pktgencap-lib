#define DEFAULT_IFACE	"nf2c0"

// Total memory size in NetFPGA (words)
#define MEM_SIZE 0x80000

//Number of ports
#define NUM_PORTS 4

//Queue sizes (words)
//  Xmit queue is used for transmission during setup
#define XMIT_QUEUE_SIZE 4096

// Min RX queue size is the minimum size for the RX queue.
//  - we have 2 * NUM_PORTS queues (tx + rx)
//  - arbitrarily chosen 1/2 * fair sharing b/w all queues
#define MIN_RX_QUEUE_SIZE (MEM_SIZE/(2*NUM_PORTS)/2)

//   Minimum TX queue size
#define MIN_TX_QUEUE_SIZE  4

// Maximum TX queue size -- allow as much as possible
#define MAX_TX_QUEUE_SIZE (MEM_SIZE-NUM_PORTS*(MIN_RX_QUEUE_SIZE+XMIT_QUEUE_SIZE+MIN_TX_QUEUE_SIZE))

//Clock frequency (Hz)
#define CLK_FREQ  (125*(pow(10, 6)))

// Time between bytes
#define USEC_PER_BYTE 0.008
#define NSEC_PER_BYTE (USEC_PER_BYTE*1000)

//Various overheads
#define FCS_LEN 4
#define PREAMBLE_LEN 8
#define INTER_PKT_GAP 12
#define OVERHEAD_LEN (PREAMBLE_LEN+INTER_PKT_GAP)

// Minimum packet size
#define MIN_PKT_SIZE 60
