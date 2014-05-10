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

#include "of_parser.h"
#include "log.h"
#include "traffic_generator.h"
#include "utils.h"
#include "context.h"

/**
* \defgroup openflow_reactive
* \ingroup modules
 * Openflow reactive.
 * A module to benchmark how the flow insertion delay scales depending on the number
 * concurent ionserted flow. The measurement includes both the delay to generate the packet_out
 * event and the delay to install the flow
 *
 * Parameters:
*
*   - pkt_size: This parameter can be used to control the length of the
*  packets of the measurement probe. It allows indirectly to adjust the packet
*  throughput of the experiment. The parameter uses bytes as measurement unit.
*   - probe_rate: The rate of the measurement probe, measured in Mbps.
*   - flows: The number of unique flows that the measurement flows will
*  generate.
*   - print:  This parameter enables the measurement module to print
*  extended per flow measurement information. The information is printed in log
*  file.
*
 *
 * Copyright (C) University of Cambridge, 2011
 * \author crotsos
 * \date March, 2011
 *
*/

 /**
* \ingroup openflow_reactive
 * \return name of module
 */
char * name() {
	return "openflow_reactive";
}

/**
 * String for scheduling events
 */
#define BYESTR "bye bye"
#define SND_ACT "send action"
#define SNMPGET "snmp get"
#define SEND_ECHO_REQ "send echo request"

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

/**
 * The file where we write the output of the measurement process.
 */
FILE *measure_output;

uint64_t proberate = 100;

/**
 * calculated sending time interval (measured in usec).
 */
uint64_t probe_snd_interval;

char *network = "192.168.2.0";

//control if a per packet measurement trace is stored
int print = 0;

/**
 * Number of flows to send.
 */
int flows = 100;
char *cli_param;

char local_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};


int *ip_received;
int ip_received_count;

struct timeval *flow_send, *flow_controller,
  *flow_received;

/**
* \ingroup openflow_reactive
 * cleanup flow table and schedule events
 * \param ctx pointer to opaque context
 */
int
start(oflops_context * ctx) {
  struct timeval now;
  void *b;
  char msg[1024];

  //Initialize pap-based  tcp flow reassembler for the communication
  //channel
  msg_init();
  snprintf(msg, 1024,  "Intializing module %s", name());

  get_mac_address(ctx->channels[OFLOPS_DATA1].dev, local_mac);

  //log when I start module
  gettimeofday(&now, NULL);
  oflops_log(now, GENERIC_MSG, msg);
  oflops_log(now,GENERIC_MSG, cli_param);

  //start openflow session with switch
  make_ofp_hello(&b);
  oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  free(b);

  //send a message to clean up flow tables.
  printf("cleaning up flow table...\n");
  make_ofp_flow_del(&b);
  oflops_send_of_mesg(ctx, b);
  free(b);

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

/**
* \ingroup openflow_reactive
  * calculate the insertion statistics
  * \param ctx data context of the module
*/
int destroy(oflops_context *ctx) {
  char msg[1024];
  int i;
  struct timeval now;

  gettimeofday(&now, NULL);

  // for every measurement save the delay in the appropriate entry on the
  // measurement matrix
  for (i = 0; i < flows; i++) {
    //print also packet details on otuput if required
    snprintf(msg, 1024, "%d:%lu.%06lu:%lu.%06lu:%lu.%06lu", i,
	     flow_send[i].tv_sec,  flow_send[i].tv_usec,
	     flow_controller[i].tv_sec, flow_controller[i].tv_usec,
	     flow_received[i].tv_sec, flow_received[i].tv_usec
	     );
    oflops_log(now, GENERIC_MSG, msg);
  }

  return 0;
}

/**
* \ingroup openflow_reactive
* Handle timer event
 * \param ctx pointer to opaque context
 * \param te pointer to timer event
 */
int handle_timer_event(oflops_context * ctx, struct timer_event *te) {
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

/**
* \ingroup openflow_reactive
* Register pcap filter.
 * \param ctx pointer to opaque context
 * \param ofc enumeration of channel that filter is being asked for
 * \param filter filter string for pcap * \param buflen length of buffer
 */
int
get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc,
		char * filter, int buflen) {
  if (ofc == OFLOPS_DATA1)
    return snprintf(filter, buflen, "udp");
  else
    return 0;
}

/**
* \ingroup openflow_reactive
* Handle pcap event.
 * \param ctx pointer to opaque context
 * \param pe pcap event
 * \param ch enumeration of channel that pcap event is triggered
 */
int
handle_pcap_event(oflops_context *ctx, struct pcap_event * pe, enum oflops_channel_name ch) {
  struct pktgen_hdr *pktgen;
  char msg[1024];
  struct flow fl;
  struct timeval now;
  int id;

  if (ch == OFLOPS_DATA1) {
    if(((pktgen = extract_pktgen_pkt(ctx, ch, pe->data, pe->pcaphdr.caplen, &fl)) == NULL)){
      printf("Failed to parse packet\n");
      return 0;
    }

    id = ntohl(fl.nw_dst) - ntohl(inet_addr(network));
    if ((id >= 0) && (id < flows) && (!ip_received[id])) {
      ip_received_count++;
      ip_received[id] = 1;
      memcpy(&flow_received[id], &pe->pcaphdr.ts, sizeof(struct timeval));
      if (ip_received_count >= flows) {
	gettimeofday(&now, NULL);
	add_time(&now, 1, 0);
	oflops_schedule_timer_event(ctx, &now, BYESTR);
	printf("Received all packets to channel 1\n");
	oflops_log(pe->pcaphdr.ts, GENERIC_MSG, "LAST_PKT_RCV");
	oflops_log(pe->pcaphdr.ts, GENERIC_MSG, msg);
      }
    }
  }
  return 0;
}

/**
* \ingroup openflow_reactive
* handle packet_in events
* \param ctx data context of the module
* \param pkt_in openflow packet data
*/
int
of_event_packet_in(oflops_context *ctx, const struct ofp_packet_in * pkt_in) {
  struct flow fl;
  struct pktgen_hdr *pktgen;
  struct timeval now;
  int id;
  void *b;

  switch(pkt_in->reason) {
  case  OFPR_NO_MATCH:
    pktgen = extract_pktgen_pkt(ctx, ntohs(pkt_in->in_port), (void *)pkt_in->data,
				ntohs(pkt_in->total_len), &fl);
    if(pktgen == NULL) { //skip non IP packets
      return 0;
    }

    oflops_gettimeofday(ctx, &now);
    id = ntohl(fl.nw_dst) - ntohl(inet_addr(network));
    if(flow_send[id].tv_sec == 0) {
      flow_send[id].tv_sec =  pktgen->tv_sec;
      flow_send[id].tv_usec =  pktgen->tv_usec;
    }
    if(flow_controller[id].tv_sec == 0)
      memcpy(&flow_controller[id], &now, sizeof(struct timeval));

    fl.in_port = pkt_in->in_port;
    fl.dl_type = htons(fl.dl_type);
    fl.tp_src = htons( fl.tp_src);
    fl.tp_dst = htons(fl.tp_dst);

    make_ofp_flow_add(&b, &fl, OFPP_IN_PORT, 1, 120);

    ((struct ofp_flow_mod *)b)->buffer_id = pkt_in->buffer_id;

    oflops_send_of_mesg(ctx, b);
    free(b);
    //store locally the probe to manipulate it later during the modification phase
    break;
  case OFPR_ACTION:
    printf("OFPR_ACTION: %d bytes\n", ntohs(pkt_in->total_len));
    break;
  default:
    printf("Unknown reason: %d bytes\n", ntohs(pkt_in->total_len));
  }
  return 0;
}


/**
* \ingroup openflow_reactive
* reply appropriately to echo request events
* \param ctx data context of the module
* \param ofph openflow header data
*/
int
of_event_echo_request(oflops_context *ctx, const struct ofp_header * ofph) {
  void *b;

  make_ofp_hello(&b);
  ((struct ofp_header *)b)->type = OFPT_ECHO_REPLY;
  ((struct ofp_header *)b)->xid = ofph->xid;
  oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  free(b);
  return 0;
}

/**
* \ingroup openflow_reactive
* log asynchronous SNMP replies
* \param ctx data context of the module
* \param se SNMP packet data
*/
int
handle_snmp_event(oflops_context * ctx, struct snmp_event * se) {
  netsnmp_variable_list *vars;
  int len = 1024, i;
  char msg[1024], log_buf[1024];
  struct timeval now;

  for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {
    snprint_value(msg, len, vars->name, vars->name_length, vars);

    for (i = 0; i < ctx->cpuOID_count; i++) {
      if((vars->name_length == ctx->cpuOID_len[i]) &&
	 (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
	snprintf(log_buf, len, "cpu:%ld:%d:%s",
		 se->pdu->reqid,
		 (int)vars->name[ vars->name_length - 1], msg);
	oflops_log(now, SNMP_MSG, log_buf);
      }
    }

    for(i=0;i<ctx->n_channels;i++) {
      if((vars->name_length == ctx->channels[i].inOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].inOID,
		 ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
	snprintf(log_buf, len, "port:rx:%ld:%d:%s",
		 se->pdu->reqid,
		 (int)(int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	oflops_log(now, SNMP_MSG, log_buf);
	break;
      }

      if((vars->name_length == ctx->channels[i].outOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].outOID,
		 ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
	snprintf(log_buf, len, "port:tx:%ld:%d:%s",
		 se->pdu->reqid,
		 (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	//	printf("port %d : tx %s pkts\n",  (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	oflops_log(now, SNMP_MSG, log_buf);
	break;
      }
    } //for
  }// if cpu
  return 0;
}

/**
* \ingroup openflow_reactive
* generate a single sequential measurement probe
* \param ctx data context of the module
*/
int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  struct in_addr ip_addr;

  init_traf_gen(ctx);

  //background data
  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min, network);
  ip_addr.s_addr = ntohl(inet_addr(network));
  ip_addr.s_addr += (flows-1);
  ip_addr.s_addr = htonl(ip_addr.s_addr);
  //str_ip = inet_ntoa(ip_addr);
  strcpy(det.dst_ip_max,  inet_ntoa(ip_addr));
  if(ctx->trafficGen == PKTGEN)
    strcpy(det.mac_src,"00:00:00:00:00:00");
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
* \ingroup openflow_reactive
 * Initialization code with parameters
 * \param ctx
 */
int init(oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  struct timeval now;

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
      }  else if(strcmp(param, "flows") == 0) {
	//parse int to get pkt size
        flows = strtol(value, NULL, 0);
        if(flows <= 0)
          perror_and_exit("Invalid flow number", 1);
      } else if(strcmp(param, "print") == 0) {
	//parse int to get pkt size
        print = strtol(value, NULL, 0);
      } else
        fprintf(stderr, "Invalid parameter:%s\n", param);
      param = pos;
    }
  }

  //calculate sendind interval
  probe_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (proberate * mbits_to_bits);
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n",
	  (uint32_t)probe_snd_interval, (uint32_t)pkt_size, (uint32_t)proberate);

  flow_send = xmalloc(flows*sizeof(struct timeval));
  memset(flow_send, '\0', flows*sizeof(struct timeval));
  flow_controller = xmalloc(flows*sizeof(struct timeval));
  memset(flow_controller, '\0', flows*sizeof(struct timeval));
  flow_received = xmalloc(flows*sizeof(struct timeval));
  memset(flow_received, '\0', flows*sizeof(struct timeval));
  ip_received = xmalloc(flows*sizeof(int));
  memset(ip_received, '\0', flows*sizeof(int));

  return 0;
}
