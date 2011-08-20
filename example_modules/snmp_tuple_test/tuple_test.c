#include <sys/queue.h>
#include <math.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>
#include <gsl/gsl_combination.h>
#include <gsl/gsl_sf_gamma.h>
 
#include "context.h"
#include "utils.h"
#include "log.h"
#include "traffic_generator.h"

/** @ingroup modules
 * queue delay module.
 * This module send a a single packet probe in 
 * order define at which rate  packet buffering ,ay appear.
 *
 * Copyright (C) Computer Laboratory, University of Cambridge, 2011
 * @author crotsos
 * @date February, 2011
 * 
 * @return name of module */
char * name() {
	return "snmp_queue_delay";
}

/** Some constants to help me with conversions
 */
const uint64_t sec_to_usec = 1000000;
const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

/** packet size limits
 */
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

/** Send sequence
 */
uint32_t sendno;

char local_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
int finished;
int pkt_size = 1500;

int tuple_field_num = 12;
char *tuple_field_name[] = {
  "OFPFW_IN_PORT", "OFPFW_DL_VLAN", "OFPFW_DL_SRC", "OFPFW_DL_DST",
  "OFPFW_DL_TYPE","OFPFW_NW_PROTO", "OFPFW_TP_SRC", "OFPFW_TP_DST",
  "OFPFW_NW_SRC_ALL", "OFPFW_NW_DST_ALL", "OFPFW_DL_VLAN_PCP", "OFPFW_NW_TOS"
};

int tuple_field_val[] = {
  OFPFW_IN_PORT, OFPFW_DL_VLAN, OFPFW_DL_SRC, OFPFW_DL_DST,
  OFPFW_DL_TYPE,OFPFW_NW_PROTO, OFPFW_TP_SRC, OFPFW_TP_DST,
  OFPFW_NW_SRC_ALL, OFPFW_NW_DST_ALL, OFPFW_DL_VLAN_PCP, OFPFW_NW_TOS
};

/** The rate at which data will be send between the data ports (In Mbits per sec.). 
 */
uint64_t duration = 30;

uint32_t
get_snmp_packet_counter(struct oflops_context *ctx, uint32_t *in, uint32_t *out) {
  struct snmp_pdu *pdu, *response;
  struct snmp_session *ss;
  netsnmp_variable_list *vars;
  int status;
  uint32_t ret = 0;

  //initialize snmp seesion and variables
  if(!(ss = snmp_open(&(ctx->snmp_channel_info->session)))) {
    snmp_perror("snmp_open");
    return 1;
  }
    
  do {
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, ctx->channels[OFLOPS_DATA1].inOID, 
		      ctx->channels[OFLOPS_DATA1].inOID_len);
    /*
     * Send the Request out.
     */  
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
      for(vars = response->variables; vars; vars = vars->next_variable)  { 
	*in = (uint32_t)*(vars->val.integer);
      }
    }
  } while(status != STAT_SUCCESS || response->errstat != SNMP_ERR_NOERROR);
  
  if (response)
    snmp_free_pdu(response);
  response = NULL;

  do {
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, ctx->channels[OFLOPS_DATA2].outOID, 
		      ctx->channels[OFLOPS_DATA1].outOID_len);
    /*
     * Send the Request out.
     */  
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
      for(vars = response->variables; vars; vars = vars->next_variable)  { 
	*out = (uint32_t)*(vars->val.integer);
      }
    }
  } while(status != STAT_SUCCESS || response->errstat != SNMP_ERR_NOERROR);
  
  if (response)
    snmp_free_pdu(response);
  response = NULL;

  snmp_close(ss);

  return ret;
}


int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  //open file for storing measurement
  while(*config_str == ' ') {
    config_str++;
  }
  param = config_str;
  while(1) {
    pos = index(param, ' ');

    if((pos == NULL)) {
      if (*param != '\0') {
        pos = param + strlen(param) + 1;
      } else
        break;
    }
    *pos='\0';
    pos++;
    value = index(param,'=');
    *value = '\0';
    value++;
    if(value != NULL) {
      if(strcmp(param, "pkt_size") == 0) {
        pkt_size = atoi(value);
        if((pkt_size <= 70) || (pkt_size > 1500))  
          perror_and_exit("Invalid pkt size param(Values between 70 and 1500 bytes)", 1);
        
      } else if(strcmp(param, "duration") == 0) {
        duration = (uint64_t)atoi(value);
	if((duration < 10) )  
          perror_and_exit("Invalid duration param(Values larger than 10 sec)", 1);
        
      }
      param = pos;
    }
  } 
  return 0;
}

/** Initialization
 * @param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx) { 
  void *b;
  msg_init();  
  int ret;
  //get the mac address of channel 1
  get_mac_address(ctx->channels[OFLOPS_DATA1].dev, local_mac);
  printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ctx->channels[OFLOPS_DATA1].dev,
	 (unsigned char)local_mac[0], (unsigned char)local_mac[1], 
	 (unsigned char)local_mac[2], (unsigned char)local_mac[3], 
	 (unsigned char)local_mac[4], (unsigned char)local_mac[5]);


  make_ofp_hello(&b);
  ret = write(ctx->control_fd, b, sizeof(struct ofp_hello));
  free(b);  

  return 0;
}

/** Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap
 * @param buflen length of buffer
 */
int get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen) {
  if(ofc == OFLOPS_DATA2) return 1;
    return 0;
}

int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  char msg[1024];
  int datarate=256;
  int len, res, ret, k;
  void *b;
  struct flow fl;
  uint64_t data_snd_interval;
  float loss;
  struct timeval now;
  uint32_t  start_rcv_count, end_rcv_count, start_snd_count, end_snd_count;
  struct nf_gen_stats gen_stat;
  struct nf_cap_stats stat;
  gsl_combination * c;
  char tuple[1024];
  
  init_traf_gen(ctx);
  
  //background dadatata
  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"10.1.1.2");
  strcpy(det.dst_ip_max, "10.1.1.2");
  
  if(ctx->trafficGen == PKTGEN)
    strcpy(det.mac_src,"00:00:00:00:00:00"); //"00:1e:68:9a:c5:74");
  else 
    snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
	     (unsigned char)local_mac[0], (unsigned char)local_mac[1], 
	     (unsigned char)local_mac[2], (unsigned char)local_mac[3], 
	     (unsigned char)local_mac[4], (unsigned char)local_mac[5]);
      
  //claculate interpacket gap
  data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec*1000) / (datarate * mbits_to_bits);
  det.delay = data_snd_interval;

  //calculate packets send
  if(data_snd_interval)
    det.pkt_count = ((uint64_t)(duration*1000000000) / (data_snd_interval));
  else 
    det.pkt_count = (uint64_t)(duration*1000000000);
  
  strcpy(det.mac_dst,"00:1e:68:9a:c5:75");
  det.vlan = 0xffff;
  det.vlan_p = 1;
  det.vlan_cfi = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  strcpy(det.flags, "");

  fprintf(stderr, "Sending data interval : %u nsec (duration: %d sec, pkt_size: %u bytes, rate: %u Mbits/sec %llu packets)\n", 
	  (uint32_t)data_snd_interval, duration, (uint32_t)pkt_size, (uint32_t)datarate,  det.pkt_count);
  //calculating interpacket gap
  for (len = 1; len <= tuple_field_num; len++) {
    c = gsl_combination_calloc (tuple_field_num, len);
    do {
      get_snmp_packet_counter(ctx, &start_rcv_count, &start_snd_count);
      
      //start packet generator
      add_traffic_generator(ctx, OFLOPS_DATA1, &det);
      
      // clean up flow table
      printf("cleaning up flow table...\n");
      res = make_ofp_flow_del(&b);
      ret = write(ctx->control_fd, b, res);
      free(b);

      size_t *data = gsl_combination_data (c);
      int val = 0;
      tuple[0] = '\0';
      for (k = 0; k< gsl_combination_k(c); k++) {
	snprintf(tuple, 1024, "%s|%s", tuple, tuple_field_name[data[k]]);
	val = val | tuple_field_val[data[k]];
      }
      //Send a singe ruke to route the traffic we will generate
      bzero(&fl, sizeof(struct flow));
      fl.mask = val;
      fl.in_port = htons(ctx->channels[OFLOPS_DATA1].of_port); 
      fl.dl_type = htons(ETHERTYPE_IP); 
      memcpy(fl.dl_src, local_mac, ETH_ALEN); 
      memcpy(fl.dl_dst, "\x00\x1e\x68\x9a\xc5\x75", ETH_ALEN); 
      fl.dl_vlan = 0xffff;
      fl.nw_proto = IPPROTO_UDP;
      fl.nw_src =  inet_addr("10.1.1.1");
      fl.nw_dst =  inet_addr("10.1.1.2");
      fl.tp_src = htons(8080);            
      fl.tp_dst = htons(8080);  
      ret = make_ofp_flow_add(&b, &fl, ctx->channels[OFLOPS_DATA2].of_port, 0, 
			      OFP_FLOW_PERMANENT);
      write(ctx->control_fd, b, ret);
      free(b);
      sleep(1);
      start_traffic_generator(ctx);
      get_snmp_packet_counter(ctx, &end_rcv_count, &end_snd_count);
      
      if(ctx->trafficGen == NF_PKTGEN) { 
	display_xmit_metrics(0, &gen_stat);
	gettimeofday(&now, NULL);
	nf_cap_stat(1, &stat);
	loss = (float)(gen_stat.pkt_snd_cnt - stat.pkt_cnt)/(float)gen_stat.pkt_snd_cnt;
	snprintf(msg, 1024, "loss:%s:%08x:%f:%d:%d:%d:%d", tuple, val, loss,
		   gen_stat.pkt_snd_cnt, stat.pkt_cnt, (end_rcv_count - start_rcv_count)
		 , (end_snd_count - start_snd_count));
	oflops_log(now, GENERIC_MSG, msg);
	printf("%s\n", msg);
      }
    } while (gsl_combination_next (c) == GSL_SUCCESS);
    
    gsl_combination_free (c);
  }
  
  oflops_end_test(ctx,1);
  return 1;
}

int 
of_event_echo_request(struct oflops_context *ctx, const struct ofp_header * ofph) {
  void *b;
  int res;
  make_ofp_hello(&b);
  ((struct ofp_header *)b)->type = OFPT_ECHO_REPLY;
  ((struct ofp_header *)b)->xid = ofph->xid;
  res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  free(b);
  return 0;
}

