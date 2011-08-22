#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <limits.h>
#include <math.h>
#include <openflow/openflow.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>


#include <test_module.h>

#include "log.h"
#include "msg.h"
#include "traffic_generator.h"

/** String for scheduling events
 */
#define BYESTR "bye bye"
#define SNMPGET "snmp get"
#define SND_PKT "send packet"

/**
 * packet size limits
 */
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

// calculated sending time interval (measured in usec). 
uint64_t probe_snd_interval;


// Number of flows to send.
int flows = 100;
char *cli_param;
char *network = "192.168.3.0";
int pkt_size = 1500;
int finished = 0;
uint32_t pkt_in_count = 0;
int print = 0;

// Some constants to help me with conversions
const uint64_t sec_to_usec = 1000000;
const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

//local mac
char local_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

struct entry {
  struct timeval snd,rcv;
  uint32_t ip, id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
}; 

TAILQ_HEAD(tailhead, entry) head;
int rcv_pkt_count = 0;		    

static char *b = NULL;
int b_len;
struct ofp_packet_out *pkt_out;
struct ether_header *ether;
struct iphdr *ip;
struct udphdr *udp;
struct pktgen_hdr *pktgen;
static int pkt_counter;

int generate_pkt_out(struct oflops_context * ctx, struct timeval *now);

// FIXME: this has an ugly part, where we write directly to the tcp socket. need 
// to remove that in a later release

/**
 * \defgroup openflow_packet_out openflow packe out
 * \ingroup modules
 * A module to benchmark the performance of the packet out functionality of an
 * openflow implementation
 *
 * Parameters:
 *
 *    - pkt_size:  This parameter can be used to control the length of the
 *   packets of the measurement probe. It allows indirectly to adjust the packet
 * throughput of the experiment. (default 1500 bytes)
 *    - probe_snd_interval: This parameter controls the data rate of the
 * measurement probe, in Mbps. (default 10Mbps)
 *    - print: This parameter defines if the measurement module prints
 *   extended per packet measurement information. The information is printed in log
 *   file.
 * 
 * Copyright (C) University of Cambridge, Computer Lab, 2011
 * \author crotsos
 * \date September, 2009
 * 
 */

/**
 * \ingroup openflow_packet_out
 * \return name of module
 */
char * name()
{
  return "Pkt_in_module";
}

/**
 * \ingroup openflow_packet_out
 * Initialization
 * \param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx) {
  struct timeval now;
  gettimeofday(&now, NULL);
  char *data;
  char msg[1024];
  int res;

  //init measurement queue
  TAILQ_INIT(&head); 

  //Initialize pcap-based  tcp flow reassembler for the communication 
  //channel
  msg_init();
  snprintf(msg, 1024,  "Intializing module %s", name());

  //log when I start module
  gettimeofday(&now, NULL);
  oflops_log(now, GENERIC_MSG, msg);
  oflops_log(now, GENERIC_MSG, cli_param);

  get_mac_address(ctx->channels[OFLOPS_DATA1].dev, local_mac);

  //start openflow session with switch
  make_ofp_hello((void *)&data);
  res = oflops_send_of_mesgs(ctx, data, sizeof(struct ofp_hello));
  free(data);  

  //send a message to clean up flow tables. 
  printf("cleaning up flow table...\n");
  res = make_ofp_flow_del((void *)&data);
  res = oflops_send_of_mesg(ctx, (void *)data);  
  free(data);

  //get port and cpu status from switch 
  gettimeofday(&now, NULL);
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx,&now, SNMPGET);

  //Schedule end
  gettimeofday(&now, NULL);
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx,&now, SND_PKT);

  //Schedule end
  gettimeofday(&now, NULL);
  add_time(&now, 20, 0);
  oflops_schedule_timer_event(ctx,&now, BYESTR);

  return 0;
}

/** Handle timer  
 * \ingroup openflow_packet_out
 * \param ctx pointer to opaque context
 * \param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te)
{
  struct timeval now;
  char * str;
  int i, snd, rc;
  fd_set fds;
  struct timeval timeout;
  str = (char *) te->arg;

  if(!strcmp(str,SNMPGET)) {
    for(i=0;i<ctx->cpuOID_count;i++) {
      oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);
    }
    for(i=0;i<ctx->n_channels;i++) {
      oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);
      oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);
    }  
    gettimeofday(&now, NULL);
    add_time(&now, 10, 0);
    oflops_schedule_timer_event(ctx,&now, SNMPGET);
  } else if(!strcmp(str,BYESTR)) {
    oflops_end_test(ctx,1);
  } else if(!strcmp(str,SND_PKT)) {
    oflops_gettimeofday(ctx, &now);
    generate_pkt_out(ctx, &now);
    snd = 0;
    while( snd <  b_len) {
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
      FD_ZERO(&fds);
      FD_SET(ctx->control_fd, &fds);
      while((rc = select(sizeof(fds)*8, NULL, &fds, NULL, &timeout)) <= 0) {
        FD_ZERO(&fds);
        FD_SET(ctx->control_fd, &fds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        if(rc < 0) 
          perror_and_exit("select failed", 1);
      }

      if (FD_ISSET(ctx->control_fd, &fds)) {
        snd += write(ctx->control_fd, b + snd, b_len - snd);
      }
    }
    gettimeofday(&now, NULL);
    add_time(&now, probe_snd_interval/sec_to_usec, probe_snd_interval%sec_to_usec);
    oflops_schedule_timer_event(ctx,&now, SND_PKT);    
  } else
    fprintf(stderr, "Unknown timer event: %s", str);
  return 0;
}

/**
 * \ingroup openflow_packet_out
 */
int 
destroy(oflops_context *ctx) {
  struct entry *np;
  uint32_t mean, median, variance, i;
  float loss;
  char msg[1024];
  double *data;
  struct timeval now;

  gettimeofday(&now, NULL);

  data = xmalloc(rcv_pkt_count*sizeof(double));
  i=0;
  for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
    if(((int)time_diff(&np->snd, &np->rcv) < 0) || 
        ((int)time_diff(&np->snd, &np->rcv) > 10000000)) continue;
    data[i++] = (double)time_diff(&np->snd, &np->rcv);
    if(print) {
      snprintf(msg, 1024, "%lu.%06lu:%lu.%06lu:%d:%d",
          np->snd.tv_sec, np->snd.tv_usec,
          np->rcv.tv_sec, np->rcv.tv_usec,
          time_diff(&np->snd, &np->rcv), 
          np->id); 
      oflops_log(now, OFPT_PACKET_IN_MSG, msg);
    }
    free(np);
  }

  if(i > 0) {
    gsl_sort (data, 1, i);

    //calculating statistical measures
    mean = (uint32_t)gsl_stats_mean(data, 1, i);
    variance = (uint32_t)gsl_stats_variance(data, 1, i);
    median = (uint32_t)gsl_stats_median_from_sorted_data (data, 1, i);
    loss = (float)i/(float)pkt_counter;

    snprintf(msg, 1024, "statistics:%lu:%lu:%lu:%f:%d", (long unsigned)mean, (long unsigned)median, 
        (long unsigned)sqrt(variance), loss, i);
    printf("statistics:%lu:%lu:%lu:%f:%d\n", (long unsigned)mean, (long unsigned)median, 
        (long unsigned)variance, loss, i);
    oflops_log(now, GENERIC_MSG, msg);
  }
  return 0;
}

/**
 * \ingroup openflow_packet_out
 */
int 
handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  netsnmp_variable_list *vars;
  int i;
  char msg[1024], log_buf[1024];
  struct timeval now;

  for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {
    snprint_value(msg, 1024, vars->name, vars->name_length, vars);


    for (i = 0; i < ctx->cpuOID_count; i++) {
      if((vars->name_length == ctx->cpuOID_len[i]) &&
          (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
        snprintf(log_buf, 1024, "cpu:%ld:%ld:%s",
            se->pdu->reqid, 
            vars->name[ vars->name_length - 1],msg);
        oflops_log(now, SNMP_MSG, log_buf);
      }
    } 

    for(i=0;i<ctx->n_channels;i++) {
      if((vars->name_length == ctx->channels[i].inOID_len) &&
          (memcmp(vars->name, ctx->channels[i].inOID,  
                  ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
        snprintf(log_buf, 1024, "port:rx:%ld:%d:%s",  
            se->pdu->reqid, 
            (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
        oflops_log(now, SNMP_MSG, log_buf);
        break;
      }

      if((vars->name_length == ctx->channels[i].outOID_len) &&
          (memcmp(vars->name, ctx->channels[i].outOID,  
                  ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
        snprintf(log_buf, 1024, "port:tx:%ld:%d:%s",  
            se->pdu->reqid, 
            (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
        oflops_log(now, SNMP_MSG, log_buf);
        break;
      }
    } //for
  }
  return 0;
}

/**
 * Initialization code with parameters
 * \ingroup openflow_packet_out
 * \param ctx 
 */
int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  struct timeval now;

  //init counters
  finished = 0;
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
      }  else 
        if(strcmp(param, "probe_snd_interval") == 0) {
          //parse int to get measurement probe rate
          probe_snd_interval = strtol(value, NULL, 0);
          if( probe_snd_interval  < 500) 
            perror_and_exit("Invalid probe rate param(larger than 100 microsec", 1);
        } else 
          if(strcmp(param, "flows") == 0) {
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
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes)\n", 
      (uint32_t)probe_snd_interval, (uint32_t)pkt_size);
  return 0;
}

/**
 * \ingroup openflow_packet_out
 */
int
generate_pkt_out(struct oflops_context * ctx,struct timeval *now) {
  struct ofp_action_output *act_out;
  uint64_t time_count;

  if(b == NULL) {
    b_len = sizeof(struct ofp_packet_out) + sizeof(struct ofp_action_output) + pkt_size;
    b = (char *)xmalloc(b_len*sizeof(char));

    //setting up openflow packet out fields
    pkt_out = (struct ofp_packet_out *)b;
    pkt_out->header.version = OFP_VERSION;
    pkt_out->header.type =  OFPT_PACKET_OUT;
    pkt_out->header.length =  htons(b_len);
    pkt_out->header.xid = 0;

    pkt_out->buffer_id = htonl(-1);
    pkt_out->in_port = htons(OFPP_NONE);
    pkt_out->actions_len = htons(sizeof(struct ofp_action_output));

    //pkt_out->actions = xmalloc(sizeof(struct ofp_action_output));
    act_out = (struct ofp_action_output *) pkt_out->actions;
    act_out->type = htons(OFPAT_OUTPUT);
    act_out->len = htons(8);      
    act_out->port = htons(ctx->channels[OFLOPS_DATA1].of_port);
    act_out->max_len = htons(2000);

    //setting up the ethernet header
    ether = (struct ether_header *)(b + sizeof(struct ofp_packet_out) + 
        sizeof(struct ofp_action_output));
    memcpy(ether->ether_shost, "\x00\x1e\x68\x9a\xc5\x75", ETH_ALEN);
    memcpy(ether->ether_dhost, local_mac, ETH_ALEN);
    ether->ether_type = htons(ETHERTYPE_IP);

    //setting up the ip header
    ip = (struct iphdr *)(b + sizeof(struct ofp_packet_out) + 
        sizeof(struct ofp_action_output) + sizeof(struct ether_header));
    ip->protocol=1;
    ip->ihl=5;
    ip->version=4;
    ip->ttl = 100;
    ip->protocol = IPPROTO_UDP; //udp protocol
    ip->saddr = inet_addr("10.1.1.1"); 
    ip->daddr = inet_addr("192.168.3.0"); //test.nw_dst;
    ip->tot_len = htons(pkt_size - sizeof(struct ether_header));

    //setting up the udp header
    udp = (struct udphdr *)(b + sizeof(struct ofp_packet_out) + 
        sizeof(struct ofp_action_output) + sizeof(struct ether_header) +
        sizeof(struct iphdr));
    udp->source = htons(8080);
    udp->dest = htons(8080);
    udp->len = htons(pkt_size - sizeof(struct ether_header) 
        - sizeof(struct iphdr));

    //setting up pktgen header
    pktgen = (struct pktgen_hdr *)(b + sizeof(struct ofp_packet_out) + 
        sizeof(struct ofp_action_output) + sizeof(struct ether_header) +
        sizeof(struct iphdr) + sizeof(struct udphdr));

    pktgen->magic = htonl(0xbe9be955);
  }
  pktgen->tv_sec = htonl(now->tv_sec);
  pktgen->tv_usec = htonl(now->tv_usec);
  pktgen->seq_num = htonl(++pkt_counter);
  ip->check= htons(0x87c5);

  return 1;
}

/** Register pcap filter.
 * \ingroup openflow_packet_out
 * \param ctx pointer to opaque context
 * \param ofc enumeration of channel that filter is being asked for
 * \param filter filter string for pcap
 * \param buflen length of buffer
 */
int get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen)
{
  if (ofc == OFLOPS_DATA1) {
    return snprintf(filter,buflen,"udp");
  }
  return 0;
}

/** Handle pcap event.
 * \ingroup openflow_packet_out
 * \param ctx pointer to opaque context
 * \param pe pcap event
 * \param ch enumeration of channel that pcap event is triggered
 */
int handle_pcap_event(struct oflops_context *ctx, struct pcap_event *pe,
    oflops_channel_name ch) {
  struct flow fl;
  struct pktgen_hdr *pkt;
  if (ch == OFLOPS_DATA1) {
    pkt = extract_pktgen_pkt(ctx, ch, (unsigned char *)pe->data, 
        pe->pcaphdr.caplen, &fl);

    if( fl.dl_type != 0x0800) {
      printf("Invalid eth type %x\n",fl.dl_type );
      return 0;
    }

    pkt = (struct pktgen_hdr *)(pe->data + sizeof(struct ether_header) +
        sizeof(struct iphdr) + sizeof(struct udphdr));    
    struct entry *n1 = malloc(sizeof(struct entry));
    n1->snd.tv_sec = ntohl(pkt->tv_sec);
    n1->snd.tv_usec = ntohl(pkt->tv_usec);
    memcpy(&n1->rcv, &pe->pcaphdr.ts, sizeof(struct timeval));
    n1->ip = fl.nw_src;
    n1->id =  ntohl(pkt->seq_num);
    rcv_pkt_count++;
    TAILQ_INSERT_TAIL(&head, n1, entries);
  }
  return 0;
}

/**
 * \ingroup openflow_packet_out
 */
int
handle_traffic_generation (oflops_context *ctx) {

  start_traffic_generator(ctx);
  return 1;
}

/**
 * \ingroup openflow_packet_out
 */
int 
of_event_echo_request(struct oflops_context *ctx, const struct ofp_header * ofph) {
  void *buf;
  int res;
  make_ofp_hello(&buf);
  ((struct ofp_header *)buf)->type = OFPT_ECHO_REPLY;
  ((struct ofp_header *)buf)->xid = ofph->xid;
  res = oflops_send_of_mesgs(ctx, buf, sizeof(struct ofp_hello));
  free(b);
  return 0;
}
