#include "msg.h"
#include "of_parser.h"

#define INITIAL_BUF_SIZE 5120

/* 
 * A buffer to store temporary tcp stream data
 */
void *buff[2];
/* 
 * the total size of the buffer
 */
size_t buff_size[2];

/*
 * the size of the data currently in the buffer. 
 */
size_t content_length[2];

#define MAX_OFP_SIZE 10240
struct timeval last_pkt_ts;
struct pcap_event *ofp_msg;

void 
msg_init() {
  buff[0] = xmalloc(INITIAL_BUF_SIZE);
  buff[1] = xmalloc(INITIAL_BUF_SIZE);

  buff_size[0] = INITIAL_BUF_SIZE;
  buff_size[1] = INITIAL_BUF_SIZE;
  content_length[0] = 0;
  content_length[1] = 0;
  ofp_msg = (struct pcap_event *)xmalloc(sizeof(struct pcap_event));
  ofp_msg->data = xmalloc(MAX_OFP_SIZE);
}


int 
parse_ip_packet_header(const void *b, int len, struct flow *fl) {
  // assume we have ethernet packets.
  // skip first bytes of the ether because they are
  // in the simple case of static length.
  if (len < sizeof(struct ether_header))
    return -1;
  b = b + sizeof(struct ether_header);
  len -= sizeof(struct ether_header);
  if (len < sizeof(struct iphdr))
    return -1;
  struct iphdr *ip_p = (struct iphdr *) b;
  if (len < 4*ip_p->ihl)
    return -1;
  b = b + 4*ip_p->ihl;
  len -=  4*ip_p->ihl;
  
  if(ip_p->protocol != IPPROTO_TCP)
    return -1;
  fl->nw_src = ip_p->saddr;
  fl->nw_dst = ip_p->daddr;
  
  if(len <  sizeof(struct tcphdr))
    return -1;
  struct tcphdr *tcp_p = (struct tcphdr *)b;
  if (len < 4*tcp_p->doff)
    return -1;
  b = b + 4*tcp_p->doff;
  len -=  4*tcp_p->doff;
  fl->tp_src = tcp_p->source;
  fl->tp_dst = tcp_p->dest;
  return sizeof(struct ether_header) + 4*ip_p->ihl + 4*tcp_p->doff;
}


int
append_data_to_flow(const  void *b, struct pcap_pkthdr hdr) {
  size_t len = hdr.caplen;
  struct flow fl;
  int dir = 0;
  
  //since this is a packet capture, strip packet from all the l1-l4 headers.
  int start = parse_ip_packet_header(b, len, &fl);
  if(ntohs(fl.tp_src) < ntohs(fl.tp_dst))
    dir = 1; //switch to controller 
  if(len - start == 0) 
    return -1;

  b += start;
  len -= start;
  while(buff_size[dir] < content_length[dir] + len) {
    buff_size[dir] += INITIAL_BUF_SIZE;
    buff[dir] = realloc(buff[dir], buff_size[dir]);
  }
  //append new packet to the buffer
  memcpy(buff[dir] + content_length[dir], b, len);
  content_length[dir] += len;
  
  last_pkt_ts.tv_sec = hdr.ts.tv_sec;
  last_pkt_ts.tv_usec = hdr.ts.tv_usec;

  return dir;
}

int 
contains_next_msg(int dir) {
  if ((dir < 0) || (dir > 1))
     return 0;
  struct ofp_header *ofp = (struct ofp_header *)buff[dir];
  if ((content_length[dir] >= sizeof(struct ofp_header)) 
      && (ntohs(ofp->length) <= content_length[dir]))
	  return 1;
  return 0;
}


/*
 * @TODO : the function breaks if retransmition occur. A better approach should be used
 * that takes under consideration the window. 
 */
int 
get_next_msg(int dir, struct pcap_event **pe) {
  int count = 0;
  struct ofp_header *ofp =  buff[dir];

  if ((content_length[dir] < sizeof(struct ofp_header)) 
      || (ntohs(ofp->length) > content_length[dir]))
    return -1;
  
  assert(ntohs(ofp->length));
  count = ntohs(ofp->length);
  *pe = ofp_msg;
  memcpy(ofp_msg->data, buff[dir], count);
  (*pe)->pcaphdr.len = count;
  (*pe)->pcaphdr.caplen = count;
  memcpy(&ofp_msg->pcaphdr.ts, &last_pkt_ts, sizeof(struct timeval));
  content_length[dir] -= count;
  memmove(buff[dir], buff[dir] + count,  content_length[dir]);

  return count;
}


int
ofp_msg_log(const void *b, struct pcap_pkthdr hdr) {
  size_t len = hdr.caplen;
  struct ofp_error_msg *err_p = NULL;
  struct ofp_header *ofp = NULL;
  int ret = GENERIC_MSG;
  struct flow fl;

  struct ofp_stats_request *reqp = NULL;
  struct ofp_stats_reply *repp = NULL;
  int count = 0;
  //random inary value to distinguish wether the packet is from the larger
  //port number to the lowest or vice versa. 
  int dir = 0; //client to server

  //since this is a packet capture, strip packet from all the l1-l4 headers.
  int start = parse_ip_packet_header(b, len, &fl);
  if(ntohs(fl.tp_src) < ntohs(fl.tp_dst))
    dir = 1; //server to client 
  if(len - start == 0) {
    //printf("no data in tcp packet\n");
    return -1;
  }
  //printf("initial length: %d, packet length = %d, direction: %d\n", content_length[dir], len - start, dir);

  b += start;
  len -= start;
  while(buff_size[dir] < content_length[dir] + len) {
    buff_size[dir] += INITIAL_BUF_SIZE;
    buff[dir] = realloc(buff[dir], buff_size[dir]);
  }
  //append new packet to the buffer
  memcpy(buff[dir] + content_length[dir], b, len);
  content_length[dir] += len;

  ofp = (struct ofp_header *)buff[dir];

  while((content_length[dir] - count >= sizeof(struct ofp_header)) 
	&& (ntohs(ofp->length) <= (content_length[dir] - count))) {
    //printf("start length: %d, count: %d, length: %d\n", ntohs(ofp->length), count, (content_length[dir] - count));
    assert(ntohs(ofp->length));
//	exit(1);
    switch(ofp->type) {
    case OFPT_HELLO:
      //printf("ofp hello\n");
      oflops_log(hdr.ts, OFPT_HELLO_MSG, "hello message");
      ret = OFPT_HELLO_MSG;
      break;
    case OFPT_STATS_REQUEST:
      reqp = (struct ofp_stats_request *) ofp;
      //printf("stats request\n");
      if (ntohs(reqp->type) == OFPST_FLOW) {
        oflops_log(hdr.ts, OFPT_STATS_REQUEST_FLOW, "stats request send");
        ret = OFPT_STATS_REQUEST_FLOW;
      } 
      break;
    case OFPT_STATS_REPLY:
      repp = (struct ofp_stats_reply *) ofp;
      printf("stats reply\n");
      if (ntohs(repp->type) == OFPST_FLOW) {
        oflops_log(hdr.ts, OFPT_STATS_REPLY_FLOW, "flow stats reply received");
        ret = OFPT_STATS_REPLY_FLOW;
      } else if (ntohs(repp->type) == OFPST_PORT) {
        oflops_log(hdr.ts, OFPT_STATS_REPLY_PORT, "port stats reply received");
        ret = OFPT_STATS_REPLY_PORT;
      }
      break;
    case OFPT_ERROR:
      err_p = (struct ofp_error_msg *)ofp;
      char *msg = xmalloc(sizeof("OFPT_ERROR(type: XXXXXXXXXX, code: XXXXXXXXXX)"));
      sprintf(msg, "OFPT_ERROR(type: %d, code: %d)", ntohs(err_p->type), ntohs(err_p->code));
      oflops_log(hdr.ts, OFPT_ERROR_MSG, msg);
      ret = OFPT_ERROR_MSG;
      break;   
    //default:
    //  printf("msg type: %d, length: %d, code: %d\n", ofp->type, ntohs(ofp->length), count);
    }  
    count += ntohs(ofp->length);
    ofp = (struct ofp_header *)(buff[dir] + count);
    //printf("end length: %d, count: %d, length: %d\n", ntohs(ofp->length), count, (content_length[dir]- count));
  }

  //need to rearrange buffer
  if(count < content_length[dir]) {
    memmove(buff[dir], buff[dir] + count, (content_length[dir] - count));
    content_length[dir] -= count;
  } else
    content_length[dir] = 0;
  return ret;
}

