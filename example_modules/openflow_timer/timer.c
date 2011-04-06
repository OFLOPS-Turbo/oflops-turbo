#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <math.h>
#include <limits.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>


#include <arpa/inet.h>

#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>

#include "log.h"
#include "traffic_generator.h"
#include "utils.h"
#include "context.h"

/** @ingroup modules
 * Openflow action install.
 * A module to measure delay and swiutching perfomance of the openflow actions.
 * The rate, count and delay then determined.
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 * 
 * @return name of module
 */
char * name() {
	return "openflow_timer";
}

/** 
 * String for scheduling events
 */
#define BYESTR "bye bye"
#define SNMPGET "snmp get"

//logging filename
#define LOG_FILE "action_aggregate.log"
char *logfile = LOG_FILE;

/** 
 * Some constants to help me with conversions
 */
const uint64_t sec_to_usec = 1000000;
const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

/**
 * packet size limits
 */
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

/**
 * Probe packet size
 */
uint32_t pkt_size = 1500;

uint64_t proberate = 100; 
uint64_t datarate = 100; 

/**
 * calculated sending time interval (measured in usec). 
 */
uint64_t probe_snd_interval;
uint64_t data_snd_interval;

int table = 0;
char *network = "192.168.2.0";

//control if a per packet measurement trace is stored
int print = 0;

/**
 * Number of flows to send. 
 */
int flows = 100;
int flow_gap = 0;
char *cli_param;

//char local_mac[] = {0x00, 0x04, 0x23, 0xb4, 0x74, 0x95};
char local_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

struct entry {
  struct timeval snd,rcv;
  int ch, id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
}; 
TAILQ_HEAD(tailhead, entry) head;
			    
int *ip_received;
int ip_received_count;

/**
 * Initialization
 * @param ctx pointer to opaque context
 */
int 
start(struct oflops_context * ctx) {  
  struct flow *fl = (struct flow*)xmalloc(sizeof(struct flow));
  void *b; //somewhere to store message data
  int res, len, i;
  struct timeval now;
  char msg[1024];
  struct timespec req, rem;

  //init h
  TAILQ_INIT(&head); 

  //Initialize pap-based  tcp flow reassembler for the communication 
  //channel
  msg_init();  
  snprintf(msg, 1024,  "Intializing module %s", name());

  get_mac_address(ctx->channels[OFLOPS_DATA1].dev, local_mac);
  get_mac_address(ctx->channels[OFLOPS_DATA2].dev, data_mac);

  //log when I start module
  gettimeofday(&now, NULL);
  oflops_log(now, GENERIC_MSG, msg);
  oflops_log(now,GENERIC_MSG , cli_param);

  //start openflow session with switch
  make_ofp_hello(&b);
  res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  free(b);  
  
  //send a message to clean up flow tables. 
  printf("cleaning up flow table...\n");
  res = make_ofp_flow_del(&b);
  res = oflops_send_of_mesg(ctx, b);  
  free(b);
  
  /**
   * Send flow records to start routing packets.
   */
  printf("Sending measurement probe flow...\n");
  bzero(fl, sizeof(struct flow));
  if(table == 0)
    fl->mask = 0; //if table is 0 the we generate an exact match */
  else 
    fl->mask =  OFPFW_IN_PORT | OFPFW_DL_DST | OFPFW_DL_SRC | 
      (0 << OFPFW_NW_SRC_SHIFT) | (0 << OFPFW_NW_DST_SHIFT) | 
      OFPFW_DL_VLAN | OFPFW_TP_DST | OFPFW_NW_PROTO | 
      OFPFW_TP_SRC | OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS;

  //fl->mask = OFPFW_ALL;
  fl->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
  fl->dl_type = htons(ETHERTYPE_IP);         
  memcpy(fl->dl_src, local_mac, 6);
  memcpy(fl->dl_dst, "\x00\x15\x17\x7b\x92\x0a", 6);

  fl->dl_vlan = 0xffff;
  fl->nw_proto = IPPROTO_UDP;
  fl->nw_src =  inet_addr("10.1.1.1");
  fl->nw_dst =  inet_addr("10.1.1.2");
  fl->tp_src = htons(8080);
  fl->tp_dst = htons(8080);
  len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA3].of_port, 1, 120);
//  ((struct ofp_flow_mod *)b)->priority = htons(128);
  res = oflops_send_of_mesg(ctx, b);
  free(b);


  memcpy(fl->dl_src, data_mac, 6);
  fl->in_port = htons(ctx->channels[OFLOPS_DATA2].of_port);
  fl->nw_dst =  inet_addr(network);

  for(i = 0; i < flows; i++) {
    len = make_ofp_flow_add(&b, fl, OFPP_IN_PORT, 1, 1200);
    ((struct ofp_flow_mod *)b)->flags = htons(OFPFF_SEND_FLOW_REM);
    ((struct ofp_flow_mod *)b)->idle_timeout = OFP_FLOW_PERMANENT;
    ((struct ofp_flow_mod *)b)->hard_timeout = htons(10);
    oflops_send_of_mesgs(ctx, b, len);
    free(b);

    req.tv_sec = flow_gap;
    req.tv_nsec = 0;
    //nanosleep(&req, &rem);
    fl->nw_dst =  ntohl(htonl(fl->nw_dst) + 1);
    
  }

  ip_received = xmalloc(flows*sizeof(int));
  memset(ip_received, 0, flows*sizeof(int));

  /**
   * Shceduling events
   */

  //get port and cpu status from switch 
  gettimeofday(&now, NULL);
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx,&now, SNMPGET);

  //end process 
  gettimeofday(&now, NULL);
  add_time(&now, 60, 0);
  oflops_schedule_timer_event(ctx,&now, BYESTR);
  return 0;
}

int destroy(struct oflops_context *ctx) {
  return 0;
}

/** Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te) {  
  char *str = te->arg; 
  int i;
  struct timeval now;

  //terminate process 
  if (strcmp(str, BYESTR) == 0) {
    printf("terminating test....\n");
    oflops_end_test(ctx,1);
    return 0;    
  } else if(strcmp(str, SNMPGET) == 0) {
    for(i = 0; i < ctx->cpuOID_count; i++) {
      oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);
    }
    for(i=0;i<ctx->n_channels;i++) {
      oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);
      oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);
    }      
    gettimeofday(&now, NULL);
    add_time(&now, 1, 0);
    oflops_schedule_timer_event(ctx,&now, SNMPGET);
  } 
  return 0;
}

/** Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap * @param buflen length of buffer
 */
int 
get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, 
		char * filter, int buflen) {
  if (ofc == OFLOPS_CONTROL) {
    //return 0;
    return snprintf(filter, buflen, "port %d",  ctx->listen_port);
  } else if ((ofc == OFLOPS_DATA1) ||  (ofc == OFLOPS_DATA2) || (ofc == OFLOPS_DATA3)) {
    return snprintf(filter, buflen, "udp");
  }
  return 0;
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

int 
handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  netsnmp_variable_list *vars;
  int len = 1024, i;
  char msg[1024], log[1024];
  struct timeval now;

  for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {
    snprint_value(msg, len, vars->name, vars->name_length, vars);

    for (i = 0; i < ctx->cpuOID_count; i++) {
      if((vars->name_length == ctx->cpuOID_len[i]) &&
	 (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
	snprintf(log, len, "cpu:%ld:%d:%s",
		 se->pdu->reqid, 
		 (int)vars->name[ vars->name_length - 1], msg);
	oflops_log(now, SNMP_MSG, log);
      }
    }

    for(i=0;i<ctx->n_channels;i++) {
      if((vars->name_length == ctx->channels[i].inOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].inOID,  
		 ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
	snprintf(log, len, "port:rx:%ld:%d:%s",  
		 se->pdu->reqid, 
		 (int)(int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	oflops_log(now, SNMP_MSG, log);
	break;
      }
	
      if((vars->name_length == ctx->channels[i].outOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].outOID,  
		 ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
	snprintf(log, len, "port:tx:%ld:%d:%s",  
		 se->pdu->reqid, 
		 (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	//	printf("port %d : tx %s pkts\n",  (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	oflops_log(now, SNMP_MSG, log);
	break;
      }
    } //for
  }// if cpu
  return 0;
}

int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  struct in_addr ip_addr;

  init_traf_gen(ctx);

  //background data
/*   strcpy(det.src_ip,"10.1.1.1"); */
/*   strcpy(det.dst_ip_min,"192.168.2.0"); */

/*   ip_addr.s_addr = ntohl(inet_addr("192.168.2.0")); */
/*   //if(table == 1) */
/*   //  ip_addr.s_addr += ((flows-1) << 8); */
/*   //else  */
/*   ip_addr.s_addr += (flows-1); */
/*   ip_addr.s_addr = htonl(ip_addr.s_addr); */
/*   //str_ip = inet_ntoa(ip_addr); */
/*   strcpy(det.dst_ip_max,  inet_ntoa(ip_addr)); */
/*   if(ctx->trafficGen == PKTGEN) */
/*     strcpy(det.mac_src,"00:00:00:00:00:00"); //"00:1e:68:9a:c5:74"); */
/*   else  */
/*     snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x", */
/* 	     (unsigned char)data_mac[0], (unsigned char)data_mac[1],  */
/* 	     (unsigned char)data_mac[2], (unsigned char)data_mac[3],  */
/* 	     (unsigned char)data_mac[4], (unsigned char)data_mac[5]); */
    
/*   strcpy(det.mac_dst,"00:15:17:7b:92:0a"); */
/*   det.vlan = 0xffff; */
/*   det.vlan_p = 0; */
/*   det.vlan_cfi = 0; */
/*   det.udp_src_port = 8080; */
/*   det.udp_dst_port = 8080; */
/*   det.pkt_size = pkt_size; */
/*   det.delay = data_snd_interval*1000; */
/*   strcpy(det.flags, ""); */
/*   add_traffic_generator(ctx, OFLOPS_DATA2, &det); */

  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"10.1.1.2");
  strcpy(det.dst_ip_max,"10.1.1.2");
  if(ctx->trafficGen == PKTGEN)
    strcpy(det.mac_src,"00:00:00:00:00:00"); //"00:1e:68:9a:c5:74");
  else 
    snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
	     (unsigned char)local_mac[0], (unsigned char)local_mac[1], 
	     (unsigned char)local_mac[2], (unsigned char)local_mac[3], 
	     (unsigned char)local_mac[4], (unsigned char)local_mac[5]);
  strcpy(det.mac_dst,"00:15:17:7b:92:0a");
  det.vlan = 0xffff;
  det.vlan_p = 0;
  det.vlan_cfi = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  det.delay = probe_snd_interval*1000;
  strcpy(det.flags, "");
  add_traffic_generator(ctx, OFLOPS_DATA1, &det);  
  
  start_traffic_generator(ctx);
  return 1;
}

/**
 * Initialization code with parameters
 * @param ctx 
 */
int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  struct timeval now;

  //init counters
  gettimeofday(&now, NULL);

  cli_param = strdup(config_str);


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
    //fprintf(stderr, "param = %s, value = %s\n", param, value);
    if(value != NULL) {
      if(strcmp(param, "pkt_size") == 0) {
        //parse int to get pkt size
        pkt_size = strtol(value, NULL, 0);
        if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))
          perror_and_exit("Invalid packet size value", 1);
      }  else if(strcmp(param, "probe_rate") == 0) {
        //parse int to get measurement probe rate
        proberate = strtol(value, NULL, 0);
        if((proberate <= 0) || (proberate >= 1010)) 
          perror_and_exit("Invalid probe rate param(Value between 1 and 1010)", 1);
      }  else if(strcmp(param, "data_rate") == 0) {
        //parse int to get measurement probe rate
        datarate = strtol(value, NULL, 0);
        if((datarate <= 0) || (datarate >= 1010)) 
          perror_and_exit("Invalid data rate param(Value between 1 and 1010)", 1);
      } else if(strcmp(param, "table") == 0) {
	//parse int to get pkt size
        table = strtol(value, NULL, 0);
        if((table < 0) && (table > 2))  
          perror_and_exit("Invalid table number", 1);
      } else if(strcmp(param, "flows") == 0) {
	//parse int to get pkt size
        flows = strtol(value, NULL, 0);
        if(flows <= 0)  
          perror_and_exit("Invalid flow number", 1);
      } else if(strcmp(param, "print") == 0) {
	//parse int to get pkt size
        print = strtol(value, NULL, 0);
      } else if(strcmp(param, "flow_gap") == 0) {
	//parse int to get pkt size
        flow_gap = strtol(value, NULL, 0);
        if(flow_gap < 0)  
          perror_and_exit("Invalid flow_gap number", 1);
      } else 
        fprintf(stderr, "Invalid parameter:%s\n", param);
      param = pos;
    }
  } 

  //calculate sendind interval
  probe_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (proberate * mbits_to_bits);
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
	  (uint32_t)probe_snd_interval, (uint32_t)pkt_size, (uint32_t)proberate);
  data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (datarate * mbits_to_bits);
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
	  (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
  return 0;
}

int 
of_event_flow_removed(struct oflops_context *ctx, const struct ofp_flow_removed * ofph) {  
  struct in_addr in;
  in.s_addr = ofph->match.nw_dst;
  printf("Flow for ip %s removed at %ld.%06ld\n", inet_ntoa(in), 
	 ntohl(ofph->duration_sec), ntohl(ofph->duration_nsec)/1000);
}
