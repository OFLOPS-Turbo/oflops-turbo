#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/time.h>

#include <pcap.h>

#include "common/nf2util.h"

#include "reg_defines_packet_generator.h"

#define DEFAULT_IFACE	"nf2c0"

#define PKT_CMD "perl -I /usr/local/netfpga/lib/Perl5/ "\
  " /root/netfpga/projects/packet_generator/sw/packet_generator.pl "\
  " -q2 /root/netfpga/projects/packet_generator/sw/udp_lite_full_coverage_0.pcap"

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

char errbuf[PCAP_ERRBUF_SIZE];

//Globals
//#define MAX_ITER 2**(OQ_PKT_GEN_ITER_WIDTH()-1);/////////////////////////////////////////////////////////////////

#define USEC_PER_BYTE 0.008

int queue_addr_offset = OQ_QUEUE_GROUP_INST_OFFSET;

int total_words = 0;

uint32_t queue_words[] = {0, 0, 0, 0};
uint32_t queue_bytes[] = {0, 0, 0, 0};
uint32_t queue_pkts[] = {0, 0, 0, 0};
uint32_t num_pkts[] = {0, 0, 0, 0};

int queue_base_addr[] = {0, 0, 0, 0};
uint32_t sec_current[] = {0, 0, 0, 0};
uint32_t usec_current[] = {0, 0, 0, 0};

char *queue_data[] = {NULL, NULL, NULL, NULL};
uint32_t queue_data_len[] = {0, 0, 0, 0};

uint32_t caplen_warned[] = {0, 0, 0, 0};

char *pcap_filename[] = {"", "", "", ""};
char *capture_filename[] = {"", "", "", ""};

float rate[] = {-1, -1, -1, -1};
float clks_between_tokens[] = {-1, -1, -1, -1};
float number_tokens[] = {-1, -1, -1, -1};
uint32_t last_len[] = {0, 0, 0, 0};
uint32_t last_nsec[] = {0, 0, 0, 0};
uint32_t last_sec[] = {0, 0, 0, 0};
uint32_t final_pkt_delay[] = {0, 0, 0, 0};
uint32_t iterations[] = {1, 1, 1, 1};
float delay[] = {-1, -1, -1, -1};

int threads;
int capture_enable = 0;
int send_enable = 0;

char *help = "";

int saw_sigusr1 = 0;
int wait = 0;

int final_capture_filename;
int capture_interfaces;

uint32_t usec_per_byte[] = {USEC_PER_BYTE, USEC_PER_BYTE, USEC_PER_BYTE, USEC_PER_BYTE};
int err;
int xmit_done = 0;
int resolve_ns = 0;
int pad = 0;
int nodrop = 0;


struct nf2device nf2;

void
init() {
  //open the write device and 
  nf2.device_name = DEFAULT_IFACE;
  if (check_iface(&nf2)) 
    exit(1);
  
  if (openDescriptor(&nf2))
    exit(1);
}

int 
packet_generator_enable(unsigned status) {
  //Start the queues that are passed into the function
  return writeReg(&nf2, PKT_GEN_CTRL_ENABLE_REG, status);
}

int
load_packet(struct pcap_pkthdr *h, const unsigned char *data, int port, int delay) {
  uint32_t src_port = 0, dst_port = 0x100;
  uint32_t sec = h->ts.tv_sec, usec = h->ts.tv_usec;
  uint32_t len = h->len, caplen = h->caplen, word_len = ceil(((float)len)/8), packet_words;
  uint32_t tmp_data,  pointer;
  //  printf("word_len:%d\n", word_len);
  
  dst_port = (dst_port << port);
  
  //If the delay is not specified assign based on the Pcap file
  if (delay == -1) {
    delay = sec - sec_current[port];
    delay = delay * 1000000; // convert to usec
    delay = ((usec + delay) - usec_current[port]);
    delay = delay * 1000; // convert to nsec
  }
  
  // Work out if this packet should be padded
  uint32_t non_pad_len = len;
  uint32_t non_pad_word_len = word_len;
  uint32_t write_pad = 0;
  if (pad && non_pad_len > 64) {
    printf("%d\n", pad);
    write_pad = 1;
    non_pad_len = 64;
    non_pad_word_len = 8;
  }
  
  // Check if there is room in the queue for the entire packet
  // 	If there is no room return 1

  //  printf("delay %d %d %d\n",delay, (delay > 0),  (delay <= 0));
  packet_words = non_pad_word_len + 1 + (delay > 0) + (write_pad);
  if ( (packet_words + total_words) > MAX_TX_QUEUE_SIZE) {
    printf("Warning: unable to load all packets from pcap file. SRAM queues are full.\n");
    printf("Total output queue size: %d words\n",MAX_TX_QUEUE_SIZE);
    printf("Current queue occupancy: %lu words\n", total_words);
    printf("Packet size:%lu words\n", packet_words);
    return 0;
  } else {
    total_words += packet_words;
    queue_words[port] += packet_words;
    queue_bytes[port] += len;
    queue_pkts[port]++;
  }
  
  //Update the current time
  sec_current[port] = sec;
  usec_current[port] = usec;
  
  usec_current[port] += (len + 4) * usec_per_byte[port];
  
  while (usec_current[port] > pow(10,6)) {
    usec_current[port] -= pow(10,6);
    sec_current[port]++;
  }
  
  // Load module hdr into SRAM
  pointer = queue_data_len[port];
  queue_data_len[port] += 9;
  queue_data[port] = realloc(queue_data[port], queue_data_len[port]);
  queue_data[port][pointer] = IO_QUEUE_STAGE_NUM;
  tmp_data = ntohl(non_pad_word_len | (dst_port << 16));
  memcpy(queue_data[port] + pointer + 1,  &tmp_data, 4);
  tmp_data =  ntohl(non_pad_len | (src_port << 16));
  memcpy(queue_data[port] + pointer + 5,  &tmp_data, 4);
/*      printf("0x%02x 0x%02x%02lx%02lx%02lx 0x%02x%02lx%02lx%02lx\n",   */
/* 	    (unsigned char)IO_QUEUE_STAGE_NUM,  */
/* 	    (unsigned char)*(queue_data[port] + pointer + 1),  */
/* 	    (unsigned char)*(queue_data[port] + pointer + 2), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 3), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 4), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 5), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 6), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 7), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 8)); */ 
  
  // Load pad hdr into SRAM
  if (write_pad) {
    pointer = queue_data_len[port];
    queue_data_len[port] += 9;
    queue_data[port] = realloc(queue_data[port], queue_data_len[port]);
    queue_data[port][pointer] = PAD_CTRL_VAL;
    tmp_data = ntohl(word_len | (dst_port << 16));
    memcpy(queue_data[port] + pointer + 1,  &tmp_data, 4);
    tmp_data =  ntohl( len | (src_port << 16));
    memcpy(queue_data[port] + pointer + 5,  &tmp_data, 4);
/*     printf("0x%02x 0x%02x%02lx%02lx%02lx 0x%02x%02lx%02lx%02lx\n",   */
/* 	   (unsigned char) PAD_CTRL_VAL,  */
/* 	   (unsigned char)*(queue_data[port] + pointer + 1),  */
/* 	   (unsigned char)*(queue_data[port] + pointer + 2), */
/* 	   (unsigned char)*(queue_data[port] + pointer + 3), */
/* 	   (unsigned char)*(queue_data[port] + pointer + 4), */
/* 	   (unsigned char)*(queue_data[port] + pointer + 5), */
/* 	   (unsigned char)*(queue_data[port] + pointer + 6), */
/* 	   (unsigned char)*(queue_data[port] + pointer + 7), */
/* 	   (unsigned char)*(queue_data[port] + pointer + 8));  */
  }
  
  //Load delay into SRAM if it exists
/*   if (delay > 0) { */
/*     pointer = queue_data_len[port]; */
/*     queue_data_len[port] += 9; */
/*     queue_data[port] = realloc(queue_data[port], queue_data_len[port]); */
/*     queue_data[port][pointer] = DELAY_CTRL_VAL; */
/*     tmp_data = floor(delay / (uint32_t)pow(2, 32)); */
/*     memcpy(queue_data[port] + pointer + 1,  &tmp_data, 4); */
/*     tmp_data = delay %  (uint32_t)pow(2, 32); */
/*     memcpy(queue_data[port] + pointer + 5,  &tmp_data, 4); */
/*     printf("0x%02x 0x%08lx 0x%08lx\n",  */
/* 	   DELAY_CTRL_VAL, (floor(delay / (uint32_t)pow(2, 32))), */
/* 	   (delay%(uint32_t)pow(2, 32))); */
/*   } */
  
  //Store the packet into SRAM
  //int pkt = unpack_packet_and_pad($packet, $len, $caplen);
  uint32_t i;
  uint32_t count = (pad)?non_pad_word_len:len;

  for(i = 0; i < count; i += 8){
    uint16_t ctrl = 0x0;
    if ((i/8) == non_pad_word_len - 1) {
      ctrl = 0x100 >> (non_pad_len % 8);
      ctrl = ((ctrl & 0xff) | (ctrl == 0x100)); //in case control is 0?
    }

    pointer = queue_data_len[port];
    queue_data_len[port] += 9;
    queue_data[port] = realloc(queue_data[port], queue_data_len[port]);
    queue_data[port][pointer] = (uint8_t)ctrl;
    memcpy(queue_data[port] + pointer + 1, data + i, 8);
/*      printf("0x%02x 0x%02x%02lx%02lx%02lx 0x%02x%02lx%02lx%02lx\n",   */
/* 	    ctrl,  */
/* 	    (unsigned char)*(queue_data[port] + pointer + 1),  */
/* 	    (unsigned char)*(queue_data[port] + pointer + 2), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 3), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 4), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 5), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 6), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 7), */
/* 	    (unsigned char)*(queue_data[port] + pointer + 8));  */
  }


  //Calculate the delay between the preceding packet and this packet
  //It should be the maximum of the delay specified in the header
  // and the delay introduced by the rate limiter
  uint32_t delay_hdr = delay;
  uint32_t delay_rate = 0;
  if (rate[port] >= 1) {
    delay_rate = ceil(last_len[port] / number_tokens[port]);
    delay_rate *= clks_between_tokens[port] * NSEC_PER_BYTE;
  }
  uint32_t delay_max = delay_hdr > delay_rate ? delay_hdr : delay_rate;
  delay_max -= (last_len[port] + FCS_LEN) * NSEC_PER_BYTE;
  delay_max = (delay_max < 0)?0:delay_max;
  delay_max += ((len > MIN_PKT_SIZE ? len : MIN_PKT_SIZE) +
		 FCS_LEN + OVERHEAD_LEN) * NSEC_PER_BYTE;

  // Update packet transmit time
  last_nsec[port] += delay_max;
  last_len[port] = len;

  while (last_nsec[port] > pow(10,9)) {
    last_nsec[port] -= pow(10,9);
    last_sec[port]++;
  }

  // Assume this is the last packet and update the amount of extra time
  // to wait for this packet to pass through the delay module. (We'll
  // eventually guess right that this is the last packet.)
  final_pkt_delay[port] = 0;
  if (rate[port] >= 1) {
    final_pkt_delay[port] = ceil((len + FCS_LEN) / number_tokens[port]);
    final_pkt_delay[port] *= clks_between_tokens[port];
    final_pkt_delay[port] -= len + FCS_LEN;
    final_pkt_delay[port] *= NSEC_PER_BYTE;
  }

  return 0;
}

int
load_pcap(const char *filename, int port, int delay) {
  pcap_t *pcap; 
  const unsigned char *data;
  struct pcap_pkthdr h;

  if((pcap = pcap_open_offline(filename, errbuf)) == NULL) {
    fprintf(stderr, "pcap_open_offline:%s\n", errbuf);
    exit(1);
  }

  while((data = pcap_next(pcap, &h)) != NULL) {
    if (h.len != h.caplen) {
      fprintf(stderr, "Warning: The capture length was less than the packet length for one");
      fprintf(stderr, " or more packets in '$pcap_filename'. Packets will be0001fffc padded with zeros.\n");
    }


    //    printf("load packet on queue %d, with delay %d\n", 
    //	   port, delay);

    if(load_packet(&h, data, port, delay) == 0) 
      num_pkts[port]++;
    else
      break;
  }

  pcap_close(pcap);
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Name: set_number_iterations
//
// Sets the number of iterations for a Packet Generator Queue
//
// Arguments: number_iterations number of iterations for queue
//            iterations        enable the number of iterations
//            queue             queue number (0-3)
//
// Control register
//       bit 0 -- enable queueIO_QUEUE_STAGE_NUM
//       bit 1 -- initialize queue (set to 1)
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int 
set_number_iterations(int number_iterations, int iterations_enable, int queue) {
  writeReg(&nf2, OQ_QUEUE_0_CTRL_REG+(queue+2*NUM_PORTS)*queue_addr_offset, 0x1);
  writeReg(&nf2, OQ_QUEUE_0_MAX_ITER_REG+(queue+2*NUM_PORTS)*queue_addr_offset, number_iterations);
  return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Name: rate_limiter_enable
//
// Enables the rate limiter for a queue
//
// Arguments: queue    queue to enable the rate limiter on
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int
rate_limiter_enable(int queue) {
  uint32_t rate_limit_offset = RATE_LIMIT_1_CTRL_REG - RATE_LIMIT_0_CTRL_REG;
  writeReg(&nf2, RATE_LIMIT_0_CTRL_REG+(queue*rate_limit_offset), 0x1);
  return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Name: rate_limiter_disable
//
// Disables the rate limiter for a queue
//
// Arguments: queue    queue to disable the rate limiter on
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int
rate_limiter_disable(int queue) {
  uint32_t rate_limit_offset = RATE_LIMIT_1_CTRL_REG - RATE_LIMIT_0_CTRL_REG;
  printf("rate limiter port %d %08x\n", queue, RATE_LIMIT_0_CTRL_REG+(queue*rate_limit_offset));
   writeReg(&nf2, RATE_LIMIT_0_CTRL_REG+(queue*rate_limit_offset), 0x0);
   return 0;
}

////////////////////////////////////////////////////////////////
// Name: queue_name
//
// Convert a queue number to a name
//
// Arguments: queue      Queue number
//
///////////////////////////////////////////////////////////////

char *
queue_name(int queue ) {

  if (queue < 0 || queue >= 12) 
    return "Invalid queue";
  else if (queue < 8) {
    if (queue % 2 == 0) 
      return "MAC Queue ";// . (queue / 2);
    else 
      return "CPU Queue ";// . (($queue - 1) / 2);
  } else 
    return "MAC Queue ";// . ($queue - 8);
  
}

//////////////////////////////////////////////////////////////
// Name: rate_limiter_set
//
// Set the rate limiter value of an output queue
//
// Arguments: queue  queue to enable the rate limiter on
//            rate   the rate to set for the output queue
//
/////////////////////////////////////////////////////////////

int
rate_limiter_set(int queue, float rate) {
  uint32_t clks_between_tokens = 1000000;
  uint32_t number_tokens = 1;

  float epsilon = 0.001;
  uint32_t MAX_TOKENS = 84;
  uint32_t BITS_PER_TOKEN = 8;

  // Check if we really need to limit this port
  if (rate < 1)
    return 0;
  
  clks_between_tokens = 1;
  rate = (rate * 1000) / BITS_PER_TOKEN;
  number_tokens = (rate * clks_between_tokens) / CLK_FREQ;
  
  // Attempt to get the number of tokens as close as possible to a
  // whole number without being too large
  uint32_t token_inc = number_tokens;
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
  printf("tokens = %d, ", number_tokens);
  printf("clks = %d)\n", clks_between_tokens);
  
  int rate_limit_offset = RATE_LIMIT_1_CTRL_REG - RATE_LIMIT_0_CTRL_REG;
  
  writeReg(&nf2, RATE_LIMIT_0_TOKEN_INTERVAL_REG + (queue * rate_limit_offset), clks_between_tokens);
  writeReg(&nf2, RATE_LIMIT_0_TOKEN_INC_REG + (queue * rate_limit_offset), number_tokens);
  
  return 1;
}


/////////////////////////////////////////////////////////////
// Name: get_queue_size
//
// Get the size of a queue
//
// Arguements: queue		Queue number
//
////////////////////////////////////////////////////////////

int
get_queue_size(int port) {
  return (queue_words[port] < MIN_TX_QUEUE_SIZE)?MIN_TX_QUEUE_SIZE:queue_words[port];
}

///////////////////////////////////////////////////////////
// Name: queue_reorganize
//
// Reorganizes the queues
//
// Arguments: None
//
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
    writeReg(&nf2, OQ_QUEUE_0_CTRL_REG + (i*queue_addr_offset), 0x00);
    //printf("%08lx %08lx\n", OQ_QUEUE_0_CTRL_REG + (i*queue_addr_offset), 0x00);
  }
  
  // Resize the queues
  for (i = 0; i < NUM_PORTS; i++) {
    // Set queue sizes for tx-during-setup queues
    writeReg(&nf2,(OQ_QUEUE_0_ADDR_LO_REG + (i * 2)*queue_addr_offset), curr_addr);
    //    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_LO_REG + (i * 2)*queue_addr_offset), curr_addr);
		 
    writeReg(&nf2, (OQ_QUEUE_0_ADDR_HI_REG + (i*2)*queue_addr_offset), curr_addr + XMIT_QUEUE_SIZE - 1);
    //    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_HI_REG + (i*2)*queue_addr_offset), curr_addr + XMIT_QUEUE_SIZE - 1);

    writeReg(&nf2, (OQ_QUEUE_0_CTRL_REG + (i*2)*queue_addr_offset), 0x02);
    //    printf("%08lx %08lx\n", (OQ_QUEUE_0_CTRL_REG + (i*2)*queue_addr_offset), 0x02);
    curr_addr += XMIT_QUEUE_SIZE;

    // Set queue sizes for RX queues
    writeReg(&nf2, (OQ_QUEUE_0_ADDR_LO_REG + (i*2+1)*queue_addr_offset), curr_addr);
    //    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_LO_REG + (i*2+1)*queue_addr_offset), curr_addr);
    
    writeReg(&nf2, (OQ_QUEUE_0_ADDR_HI_REG + (i*2+1)*queue_addr_offset), curr_addr + rx_queue_size[i] - 1);
    //    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_HI_REG + (i*2+1)*queue_addr_offset), curr_addr + rx_queue_size[i] - 1);
    
    writeReg(&nf2,(OQ_QUEUE_0_CTRL_REG + (i*2 + 1) * queue_addr_offset), 0x02);
    //    printf("%08lx %08lx\n", (OQ_QUEUE_0_CTRL_REG + (i*2 + 1) * queue_addr_offset), 0x02);
    curr_addr += rx_queue_size[i];
  }

  for (i = 0; i < NUM_PORTS; i++) {
    uint32_t queue_size = get_queue_size(i);

    // Set queue sizes for TX queues
    writeReg(&nf2, (OQ_QUEUE_0_ADDR_LO_REG + (i + 2*NUM_PORTS)*queue_addr_offset), curr_addr);
    //    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_LO_REG + (i + 2*NUM_PORTS)*queue_addr_offset), curr_addr);
    //
    writeReg(&nf2, (OQ_QUEUE_0_ADDR_HI_REG + (i + 2*NUM_PORTS)*queue_addr_offset), curr_addr + queue_size - 1);
    //    printf("%08lx %08lx\n", (OQ_QUEUE_0_ADDR_HI_REG + (i + 2*NUM_PORTS)*queue_addr_offset), curr_addr + queue_size - 1);
    
    writeReg(&nf2, (OQ_QUEUE_0_CTRL_REG + (i + 2*NUM_PORTS)*queue_addr_offset),0x02);
    //    printf("%08lx %08lx\n", (OQ_QUEUE_0_CTRL_REG + (i + 2*NUM_PORTS)*queue_addr_offset),0x02);

    queue_base_addr[i] = curr_addr;
    curr_addr += queue_size;
  }

  // Enable Output Queues that are not associated with Packet Generation
  for (i = 0; i < 2*NUM_PORTS; i++)
    writeReg(&nf2, (OQ_QUEUE_0_CTRL_REG + i*queue_addr_offset), 0x01);
  //    printf("%08lx %08lx\n",(OQ_QUEUE_0_CTRL_REG + i*queue_addr_offset), 0x01);

  return 0;
}

uint32_t 
time() {
  struct timeval now;
  gettimeofday(&now, NULL);
  return now.tv_sec;
}

//////////////////////////////////////////////////////////
// Name: load_queues
  float epsilon = 0.001;
//
// Loads the packets into NetFPGA RAM from the hosts memory
//
// Arguments: queue              Queue to load the Pcap into
//
///////////////////////////////////////////////////////////

int 
load_queues(int queue) {
  uint32_t sram_addr = SRAM_BASE_ADDR + queue_base_addr[queue] * 16;
  int i;
  printf("queue %d len:%d\n", queue, queue_data_len[queue]);
  for (i=0; i<queue_data_len[queue];i+=9) {
    writeReg(&nf2, (sram_addr+0x4), 
	     *((uint8_t *)(queue_data[queue] + i)));
    writeReg(&nf2, (sram_addr+0x8), 
	     htonl(*((uint32_t *)(queue_data[queue] + i + 1))));
    writeReg(&nf2, (sram_addr+0xc), 
	     htonl(*(uint32_t *)(queue_data[queue] + i + 5)));
    printf("%x %x %x %08lx %x %08lx\n",
	   (sram_addr+0x4), *((uint8_t *)(queue_data[queue] + i)),
 	   (sram_addr+0x8), htonl(*((uint32_t *)(queue_data[queue] + i + 1))),
 	   (sram_addr+0xc), htonl(*((uint32_t *)(queue_data[queue] + i + 5))));
    sram_addr += 16;
  }
  return 0;
}

/////////////////////////////////////////////////////////////
// Name: wait_for_last_packet
//
// Wait until the last packet is scheduled to be sent
//
/////////////////////////////////////////////////////////////
void
wait_for_last_packet(uint32_t start) {
  float last_pkt = 0;
  float delta = 0;
  float last;

  int i;

  // Work out when the last packet is to be sent
  for (i = 0; i < NUM_PORTS; i++) {
    if (queue_data_len[i]) {
      double queue_last = (last_sec[i] * 1.0) + (last_nsec[i] * pow(10,-9));
      queue_last *= (iterations[i] * 1.0);
      queue_last += (final_pkt_delay[i] * pow(10, -9)) * (iterations[i] - 1.0);
      if (queue_last > last_pkt) {
	last_pkt = queue_last;
      }
    }
  }
  
  // Wait the requesite number of seconds
  printf("Last packet scheduled for transmission at %1.3f seconds\n", last_pkt);
  while (delta <= last_pkt) {
    sleep(1);
    delta = time() - start;
  }

  printf( "\n\n");
}

///////////////////////////////////////////////////
// Name: reset_delay
//
// Reset the delay modules
//
//////////////////////////////////////////////////
void 
reset_delay() {
	writeReg(&nf2, DELAY_RESET_REG, 1);
}

//////////////////////////////////////////////////
// Name: disable_queue
//
// Disable one of the queues
//
// Arguments: queue             queue number (0-11)
//
//////////////////////////////////////////////////
void
disable_queue(int queue) { 
  writeReg(&nf2, OQ_QUEUE_0_CTRL_REG + queue * queue_addr_offset, 0x0);
}

void
finish_gen() {
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

  //display_xmit_metrics();
  //display_capture_metrics();
  
  if (capture_enable) {
    printf("Ignore warnings about scalars leaked...\n");
  }
}


int 
main(int argc, char *argv[]) {
  int i;
  uint32_t start;

  printf("Initiating packet generator\n");

  init();

  float epsilon = 0.001;
  if(packet_generator_enable(0x0)) {
    perror("packet_generator_enable");
    exit(1);
  }


/*   load_pcap("/root/netfpga/projects/packet_generator/sw/udp_lite_full_coverage_0.pcap", 2,  */
/* 	    0); */
  send_enable = 1;
  pad = 0;
  load_pcap("/root/netfpga/projects/packet_generator/sw/http.pcap", 2, 0);
  //  load_pcap("/root/netfpga/projects/packet_generator/sw/udp_lite_full_coverage_0.pcap", 2, 0);
  queue_reorganize();

  // Load the packets into sram
  for (i = 0; i < NUM_PORTS; i++) {
    if (queue_data_len[i]) {
      load_queues(i);
    }
  }

  //Set the rate limiter for CPU queues
  //  for (i = 0; i < 4; i++) {
  // rate_limiter_set(i*2+1, 200000);
  //}

  // Set the number of iterations for the queues with pcap files
  for (i = 0; i < NUM_PORTS; i++) {
    if (queue_data_len[i])
      set_number_iterations (iterations[i], 1, i);

    // Enable the rate limiter
    if (rate[i] > 0)
      rate_limiter_enable(i * 2);
    else
      rate_limiter_disable(i * 2);
  }
  rate_limiter_set(4, 200000);
  rate_limiter_enable(4);

  // Enable the rate limiter on the CPU queues
  for (i = 0; i < 4; i++) {
    rate_limiter_enable(i*2 + 1);
  }

  //Enable the packet generator hardware to send the packets
  int drop = 0;
  if (!nodrop) {
    for (i = 0; i < NUM_PORTS; i++) 
      if (queue_data_len[i]) {
	printf("send data on port %d\n", i);
	drop |= (1 << i);
      }
    
    drop <<= 8;
  }

  for (i = 0; i < NUM_PORTS; i++) 
    printf("queue size %d : %d %x\n", i, queue_data_len[i], drop);

  packet_generator_enable (0xF);

  // Wait until the correct number of packets is sent
  start = time();
  if (send_enable) {
    printf("Sending packets...\n");    
    wait_for_last_packet(start);
    //leep(100);
  }
  finish_gen();
  //  system (PKT_CMD);

  return 0;
  
}
