#include "msg.h"
#include "utils.h"

void
ofp_init(struct ofp_header *oh, int type, int len) {
  oh->version = OFP_VERSION;
  oh->type = type;
  oh->length = htons(len);
  oh->xid = 0;
}

int
make_ofp_hello(void **buferp) {
  struct ofp_hello *p;
  *buferp = xmalloc(sizeof(struct ofp_hello));
  p = *(struct ofp_hello **)buferp;
  ofp_init(&p->header, OFPT_HELLO, sizeof(struct ofp_hello));
  return sizeof(struct ofp_hello);
}

int
make_ofp_echo_req(void **buferp) {
  struct ofp_header *p;
  *buferp = xmalloc(sizeof(struct ofp_header));
  p = *(struct ofp_header **)buferp;
  ofp_init(p, OFPT_ECHO_REQUEST, sizeof(struct ofp_header));
  return sizeof(struct ofp_header);
}

int
make_ofp_feat_req(void **buferp) {
  struct ofp_hello *p;
  *buferp = xmalloc(sizeof(struct ofp_hello));
  p = *(struct ofp_hello **)buferp;
  ofp_init(&p->header, OFPT_FEATURES_REQUEST, sizeof(struct ofp_hello));
  return sizeof(struct ofp_hello);
}

/*
 * A function the creates a simple flow modification message 
 * based on the content of the  flow structure and the mask details.
 * @param ofp The bufer where we create the packet.
 * @param command the type of message we want to create. 
 * @param flow The flow structure from we create the match rule.
 * @param mask T
 */
int
make_flow_mod(void *ofp, uint16_t command, uint32_t len, 
	      struct flow *flow) {
  struct ofp_flow_mod *ofm = ofp;
  memset(ofp, 0, len);
  ofm->header.version = OFP_VERSION;
  ofm->header.type = OFPT_FLOW_MOD;
  ofm->header.length = htons(len);
  ofm->match.wildcards = htonl(flow->mask);
  ofm->match.in_port = flow->in_port;
  memcpy(ofm->match.dl_src, flow->dl_src, sizeof ofm->match.dl_src);
  memcpy(ofm->match.dl_dst, flow->dl_dst, sizeof ofm->match.dl_dst);
  ofm->match.dl_vlan = flow->dl_vlan;
  ofm->match.dl_type = flow->dl_type;
  ofm->match.nw_src = flow->nw_src;
  ofm->match.nw_dst = flow->nw_dst;
  ofm->match.nw_proto = flow->nw_proto;
  ofm->match.tp_src = flow->tp_src;
  ofm->match.tp_dst = flow->tp_dst;
  ofm->command = htons(command);
  return 0;
}

/**
 * This function can be used to create a flow modification maching @fl flow
 * match and forwarding  the packet to the @out_port.  
 * @param buferp a pointer to the location of the memory on which the new packet can be found.  
 * @param fl the flow definition parameter
 * @param out_port the output port of the action.
 * @param buffer_id a buffer id for the OpenFlow header.
 * @param idle_timeout a value to timeout the respecitve flow in the flow table. 
 */
int
make_ofp_flow_add(void **buferp, struct flow *fl, uint32_t out_port,
		  uint32_t buffer_id, uint16_t idle_timeout) {
  //size of the packet we are sending .
  size_t len = sizeof(struct ofp_flow_mod) + sizeof(struct ofp_action_output);
  struct ofp_action_output *p = NULL;
  *buferp = xmalloc(len);
  if(make_flow_mod(*buferp, OFPFC_ADD, len, fl) < 0 ) 
    fail("Error: falied to create flow modification packet.");
  struct ofp_flow_mod *ofm = *buferp;
  p = (struct ofp_action_output *)ofm->actions;
  ofm->idle_timeout = htons(idle_timeout);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->buffer_id = htonl(-1); //buffer_id);
  ofm->command = htons(OFPFC_ADD);
  ofm->flags = htons(OFPFF_SEND_FLOW_REM);
  p->type = htons(OFPAT_OUTPUT);
  p->len = htons(8);
  p->port = htons(out_port);
  p->max_len = htons(2000);
  return len;
}

/*
 * This function can be used to create a flow modification maching @fl flow
 * match and forwarding  the packet to the @out_port.  
 * @param buferp a pointer to the location of the memory on which the new packet can be found.  
 * @param fl the flow definition parameter
 * @param out_port the output port of the action.
 * @param buffer_id a buffer id for the OpenFlow header.
 * @param idle_timeout a value to timeout the respecitve flow in the flow table. 
 */
int
make_ofp_flow_add_actions(void **buferp, struct flow *fl, uint8_t *actions, uint8_t action_len,
		  uint32_t buffer_id, uint16_t idle_timeout) {
  //size of the packet we are sending .
  size_t len = sizeof(struct ofp_flow_mod) + action_len;
  *buferp = xmalloc(len);
  if(make_flow_mod(*buferp, OFPFC_ADD, len, fl) < 0 ) 
    fail("Error: falied to create flow modification packet.");
  struct ofp_flow_mod *ofm = *buferp;
  ofm->idle_timeout = htons(idle_timeout);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->buffer_id = htonl(buffer_id);
  ofm->command = htons(OFPFC_ADD);
  ofm->flags = htons(OFPFF_SEND_FLOW_REM);
  memcpy(ofm->actions, actions, action_len);
  return len;
}

int
make_ofp_flow_modify_output_port(void **buferp, struct flow *fl, uint32_t out_port,
		  uint32_t buffer_id, uint16_t idle_timeout) {
  //size of the packet we are sending .
  size_t len = sizeof(struct ofp_flow_mod) + sizeof(struct ofp_action_output);
  struct ofp_action_output *p = NULL;
  *buferp = xmalloc(len);
  if(make_flow_mod(*buferp, OFPFC_MODIFY, len, fl) < 0 ) 
    fail("Error: falied to create flow modification packet.");
  struct ofp_flow_mod *ofm = *buferp;
  p = (struct ofp_action_output *)ofm->actions;
  ofm->idle_timeout = htons(idle_timeout);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->buffer_id = htonl(-1); //buffer_id);
  ofm->command = htons(OFPFC_ADD);
  ofm->flags = htons(OFPFF_SEND_FLOW_REM);
  p->type = htons(OFPAT_OUTPUT);
  p->len = htons(8);
  p->port = htons(out_port);
  p->max_len = htons(2000);
  return len;
}

int
make_ofp_flow_modify(void **buferp, struct flow *fl, char *actions,  uint16_t action_len,
		  uint32_t buffer_id, uint16_t idle_timeout) {
  //size of the packet we are sending .
  size_t len = sizeof(struct ofp_flow_mod) + action_len;
  *buferp = xmalloc(len);
  if(make_flow_mod(*buferp, OFPFC_MODIFY, len, fl) < 0 ) 
    fail("Error: falied to create flow modification packet.");
  struct ofp_flow_mod *ofm = *buferp;
  memcpy(((void *)ofm)+sizeof(struct ofp_flow_mod), (void *)actions, action_len);
  ofm->idle_timeout = htons(idle_timeout);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->buffer_id = htonl(-1); //buffer_id);
  ofm->command = htons(OFPFC_ADD);
  return len;
}


/*
 * This function can be used to create a flow modification message that creates
 * a match regarding the source and destination i pgiven as parameters. The packet 
 * matched is forwarded to the out_port.
 * @param buferp a pointer to the location of the memory on which the new packet can be found.
 * @param dst_ip a string of the destination ip to which the rule will reference. 
 */
int
make_ofp_flow_del(void **buferp) {
  // the field I am interested to check on the TCAM
  uint32_t mask = OFPFW_ALL;

  //size of the packet we are sending .
  size_t len = sizeof(struct ofp_flow_mod);
  *buferp = xmalloc(len);
  struct ofp_flow_mod *ofm = *buferp;
  memset(ofm, 0, len);

  ofm->header.version = OFP_VERSION;
  ofm->header.type = OFPT_FLOW_MOD;
  ofm->header.length = htons(len);

  ofm->match.wildcards = htonl(mask);

  ofm->idle_timeout = 0;
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->buffer_id = htonl(-1);
  ofm->priority = htons(32768);
  ofm->command = htons(OFPFC_DELETE);
  ofm->out_port = htons(OFPP_NONE); //htons(OFPP_NONE); //

  return len;
}



int
make_ofp_flow_get_stat(void **buferp, int trans_id) {
  struct ofp_flow_stats_request *reqp = NULL;
  struct ofp_stats_request *headp = NULL;
  
  int len = sizeof(struct ofp_stats_request) + sizeof(struct ofp_flow_stats_request);

  //allocate memory
  *buferp = xmalloc(len);
  memset(*buferp, 0, len);
  headp =  (struct ofp_stats_request *)*buferp;

  headp->header.version = OFP_VERSION;
  headp->header.type = OFPT_STATS_REQUEST;
  headp->header.length = htons(len);
  headp->header.xid = htonl(trans_id);
  headp->type = htons(OFPST_FLOW);

  reqp = (struct ofp_flow_stats_request *)(*(buferp)+sizeof(struct ofp_stats_request));
  reqp->match.wildcards = htonl(OFPFW_ALL);
  reqp->table_id = 0xFF;
  reqp->out_port = OFPP_NONE;

  return len;
}

int
make_ofp_aggr_flow_stats(void **buferp, int trans_id) {
  struct ofp_aggregate_stats_request *reqp = NULL;
  struct ofp_stats_request *headp = NULL;
  
  int len = sizeof(struct ofp_stats_request) + 
    sizeof(struct ofp_aggregate_stats_request);

  //allocate memory
  *buferp = xmalloc(len);
  memset(*buferp, 0, len);
  headp =  (struct ofp_stats_request *)*buferp;

  headp->header.version = OFP_VERSION;
  headp->header.type = OFPT_STATS_REQUEST;
  headp->header.length = htons(len);
  headp->header.xid = htonl(trans_id);
  headp->type = htons(OFPST_AGGREGATE);

  reqp = (struct ofp_aggregate_stats_request *)(*(buferp)+sizeof(struct ofp_stats_request));
  reqp->match.wildcards = htonl(OFPFW_ALL);
  reqp->table_id = 0xFF;
  reqp->out_port = OFPP_NONE;

  return len;
}

int 
make_ofp_port_get_stat(void **buferp) {
#if OFP_VERSION == 0x97
  struct ofp_stats_request *headp = NULL;
  *buferp = xmalloc(sizeof(struct ofp_stats_request));
  headp =  (struct ofp_stats_request *)*buferp;
  headp->header.version = OFP_VERSION;
  headp->header.type = OFPT_STATS_REQUEST;
  headp->header.length = htons(sizeof(struct ofp_stats_request));
  headp->type = htons(OFPST_PORT);
  return sizeof(struct ofp_stats_request);
#elif OFP_VERSION == 0x01  
  struct ofp_stats_request *headp = NULL;
  struct ofp_port_stats_request *port = NULL;
  int len = sizeof(struct ofp_stats_request) + sizeof(struct ofp_port_stats_request);
  *buferp = xmalloc(len);
  headp =  (struct ofp_stats_request *)*buferp;
  headp->header.version = OFP_VERSION;
  headp->header.type = OFPT_STATS_REQUEST;
  headp->header.length = htons(len);
  headp->type = htons(OFPST_PORT);
  port = (struct ofp_port_stats_request *)(*buferp+sizeof(struct ofp_stats_request));
  port->port_no = htons(OFPP_NONE);
  return len;
#endif
} 

char *
generate_packet(struct flow test, size_t len) {
  char *buf = (char *)xmalloc(len); 
  printf("flow:%x\n", test.dl_dst[5]);
  bzero((void *)buf, len);
  if(len < sizeof(struct ether_vlan_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
    printf("packet size is too small\n");
    return NULL;
  }

  //ethernet header with default values
  struct ether_vlan_header * eth = (struct ether_vlan_header * ) buf;
  memcpy(eth->ether_dhost, test.dl_dst,  OFP_ETH_ALEN);
  memcpy(eth->ether_shost, test.dl_src,  OFP_ETH_ALEN);
  eth->tpid = htons(0x8100);
  eth->vid = test.dl_vlan>>4;
  eth->ether_type = test.dl_type;
  //ip header with default values
  struct iphdr * ip = (struct iphdr *) (buf + sizeof(struct ether_vlan_header));
  ip->protocol=1;
  ip->ihl=5;
  ip->version=4;
  ip->check = htons(0x9a97);
  //total packet size without ethernet header
  ip->tot_len=htons(len - sizeof(struct ether_vlan_header)); 
  ip->ttl = 10;
  ip->protocol = test.nw_proto; //udp protocol
  ip->saddr = test.nw_src; 
  ip->daddr = test.nw_dst;

  if(test.nw_proto == IPPROTO_UDP) {
    //  case IPPROTO_UDP:
    //udp header with default values
    struct udphdr *udp = (struct udphdr *)
      (buf + sizeof(struct ether_vlan_header) + sizeof(struct iphdr));
    udp->source = test.tp_src;
    udp->dest = test.tp_dst;
    udp->len = htons(len - sizeof(struct ether_vlan_header) - sizeof(struct iphdr));
    //   break;
    //default:
  } else {
    printf("unimplemented protocol %x\n", test.nw_proto);
    return NULL;
  }
  return buf;
  
}

uint32_t
extract_pkt_id(const char *b, int len) {
  struct ether_header *ether = (struct ether_header *)b;
  struct ether_vlan_header *ether_vlan = (struct ether_vlan_header *)b;
  
  //  printf("%x %x\n",ntohl(ether->ether_type),ntohl(ether_vlan->ether_type));

  if( (ntohs(ether->ether_type) == 0x8100) && (ntohs(ether_vlan->ether_type) == 0x0800)) {
    b = b + sizeof(struct ether_vlan_header);
    len -= sizeof(struct ether_vlan_header);
  } else if(ntohs(ether->ether_type) == 0x0800) {
    b = b + sizeof(struct ether_header);
    len -= sizeof(struct ether_header);
  } else {
    return 0;
  }

  struct iphdr *ip_p = (struct iphdr *) b;
  if (len < 4*ip_p->ihl)
    return 0;
  b = b + 4*ip_p->ihl;
  len -=  4*ip_p->ihl;
  
  b += sizeof(struct udphdr);
  uint32_t ret = *((uint32_t *)b); 
  return ret;
}
