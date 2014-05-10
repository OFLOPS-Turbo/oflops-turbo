#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <math.h>
#include <limits.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>
#include <gsl/gsl_sort.h>

#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>

#include "of_parser.h"
#include "log.h"
#include "traffic_generator.h"
#include "utils.h"
#include "oflops.h"

/**
 * \defgroup openflow_echo_delay openflow echo
 * \ingroup modules
 * Measure the delay of the control channel using openflow echo messages.
 *
 * paramaters:
 * - delay: define the inter-request delay in microseconds.
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 *
 */

/**
 * \ingroup openflow_echo_delay
 * @return name of module
 */
char * name() {
  return "openflow_echo_test";
}

/**
 * String for scheduling events
 */
#define BYESTR "bye bye"
#define ECHO_REQUEST "echo request"
#define SNMPGET "snmp get"

/**
 * Some constants to help me with conversions
 */
const uint64_t sec_to_usec = 1000000;
const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

/**
 * calculated sending time interval (measured in usec).
 */
uint64_t delay = 1000000;

int table = 0;
char *network = "192.168.2.0";

//control if a per packet measurement trace is stored
int print = 0;

/**
 * Number of flows to send.
 */
char *cli_param;
int trans_id = 1;
struct entry {
  struct timeval snd,rcv;
  int ch, id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};

// static storage, since we have the tansaction id to define the index
// of the measurement
struct entry echo_data[1000000];
int echo_data_count = 0;

/**
 * empty flow table and schedule events
 * @param ctx pointer to opaque context
 */
int
start(oflops_context * ctx) {
  void *b; //somewhere to store message data
  struct timeval now;
  char msg[1024];

  msg_init();

  //log when I start module
  oflops_gettimeofday(ctx, &now);
  snprintf(msg, 1024,  "Intializing module %s", name());
  oflops_log(now, GENERIC_MSG, msg);
  oflops_log(now,GENERIC_MSG , cli_param);

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
  //send the flow modyfication command in 30 seconds.
  oflops_gettimeofday(ctx, &now);
  printf("test %u.%06u\n", now.tv_sec, now.tv_usec);
  add_time(&now, delay/1000000, delay%1000000);
  printf("after %u.%06u\n", now.tv_sec, now.tv_usec);
  oflops_schedule_timer_event(ctx,&now, ECHO_REQUEST);

  //get port and cpu status from switch
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx,&now, SNMPGET);

  //end process
  add_time(&now, 20, 0);
  oflops_schedule_timer_event(ctx,&now, BYESTR);

  return 0;
}

/**
 * \ingroup openflow_echo_delay
 * calculate statistics for the echo probes.
 * \param ctx data contaxt of the module
 */
int destroy(oflops_context *ctx) {
  int  i;
  char msg[1024];
  struct timeval now;
  double *data;
  uint32_t mean, std, median;
  float lost = 0.0;
  int count = 0;

  //get what time we start printin output
  oflops_gettimeofday(ctx, &now);

  data = xmalloc(echo_data_count * sizeof(double));
  for(i = 1; i <= echo_data_count; i++) {
    snprintf(msg, 1024, "OFP_ECHO:%d:%ld.%06ld:%ld.%06ld:%d", i, echo_data[i].snd.tv_sec, echo_data[i].snd.tv_usec,
        echo_data[i].rcv.tv_sec, echo_data[i].rcv.tv_usec, time_diff(& echo_data[i].snd, &echo_data[i].rcv));
    oflops_log(now, GENERIC_MSG, msg);
    if ((echo_data[i].snd.tv_sec > 0) && (echo_data[i].rcv.tv_sec > 0)) {
      data[count++] = time_diff(& echo_data[i].snd, &echo_data[i].rcv);
    } else {
      lost ++;
    }
  }
  if(count > 0) {
    gsl_sort (data, 1, count);
    mean = (uint32_t)gsl_stats_mean(data, 1, count);
    std = (uint32_t)sqrt(gsl_stats_variance(data, 1, count));
    median = (uint32_t)gsl_stats_median_from_sorted_data (data, 1, count);
    printf("statistics:echo:%u:%u:%u:%d\n", mean, median, std, count);
    snprintf(msg, 1024, "statistics:echo:%u:%u:%u:%d:%f", mean, median, std, count, (lost/(float)echo_data_count));
    oflops_log(now, GENERIC_MSG, msg);
  }
  return 0;
}

/**
 * \ingroup mplayer openflow_echo_delay
 * Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(oflops_context * ctx, struct timer_event *te) {
  char *str = te->arg;
  int i;
  void *b = NULL;
  struct timeval now;

  //terminate process
  if (strcmp(str, BYESTR) == 0) {
    printf("terminating test....\n");
    oflops_end_test(ctx,1);
    return 0;
  } else if (strcmp(str, ECHO_REQUEST) == 0) {
    //log time
    //oflops_gettimeofday(ctx, &echo_data[trans_id].snd);

    //send packet
    make_ofp_hello(&b);
    ((struct ofp_header *)b)->type = OFPT_ECHO_REQUEST;
    ((struct ofp_header *)b)->xid = htonl(trans_id++);
    oflops_send_of_mesg(ctx, b);
    free(b);

    //arrange next echo
    oflops_gettimeofday(ctx, &now);
    add_time(&now, delay/1000000, delay%1000000);
    printf("next event in %u.%06u\n", delay/1000000, delay%1000000);
    oflops_schedule_timer_event(ctx, &now, ECHO_REQUEST);

  } else if(strcmp(str, SNMPGET) == 0) {
    for(i = 0; i < ctx->cpuOID_count; i++) {
      oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);
    }
    for(i=0;i<ctx->n_channels;i++) {
      oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);
      oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);
    }
    oflops_gettimeofday(ctx, &now);
    add_time(&now, 10, 0);
    oflops_schedule_timer_event(ctx,&now, SNMPGET);
  }
  return 0;
}

/**
 * \ingroup openflow_echo_delay
 * handle of error messages
 * \param ctx data context of module
 * \param ofph a pointer to the data of the packet
 */
int
of_event_other(oflops_context *ctx, struct ofp_header *ofph) {
  struct ofp_error_msg *err_p = NULL;
  struct timeval now;
  char msg[1024];
  oflops_gettimeofday(ctx, &now);
  switch(ofph->type) {
    case OFPT_ERROR:
      err_p = (struct ofp_error_msg *)ofph;
      snprintf(msg, 1024, "OFPT_ERROR(type: %d, code: %d)", ntohs(err_p->type), ntohs(err_p->code));
      oflops_log(now, OFPT_ERROR_MSG, msg);
      fprintf(stderr, "%s\n", msg);
      break;
  }
  return 0;
}

/**
 * \ingroup openflow_echo_delay
 * handle echo requests and generates replies
 * \param ctx data context of the module
 * \param ofph  pointer to the data of the of packet
 */
int
of_event_echo_request(oflops_context *ctx, const struct ofp_header * ofph) {
  void *b;

  printf("got an echo request\n");
  make_ofp_hello(&b);
  ((struct ofp_header *)b)->type = OFPT_ECHO_REPLY;
  ((struct ofp_header *)b)->xid = ofph->xid;
  oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  free(b);
  return 0;
}

/**
 * \ingroup openflow_echo_delay
 * handle asynchronous snmp replies and log data
 * \param ctx data context of the module
 * \param se data of the SNMP reply
 */
int
handle_snmp_event(oflops_context * ctx, struct snmp_event * se) {
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
        oflops_log(now, SNMP_MSG, log);
        break;
      }
    } //for
  }// if cpu
  return 0;
}

/**
 * dummy traffic generation implementation
 * \param ctx data context of the module
 */
int
handle_traffic_generation (oflops_context *ctx) {
  init_traf_gen(ctx);
  start_traffic_generator(ctx);
  return 1;
}

/**
 * initialization of the state of the module.
 * \param ctx data context of the module
 * \param config_str a space seprate initialization string
 */
int init(oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  struct timeval now;

  oflops_gettimeofday(ctx, &now);

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
    if(value != NULL) {
      if(strcmp(param, "delay") == 0) {
        //parse int to get measurement probe rate
        delay = strtol(value, NULL, 0);
        if((delay <= 100))
          perror_and_exit("Invalid probe delay param(Value must be larger that 100 msec)", 1);
      } else
        fprintf(stderr, "Invalid parameter:%s\n", param);
      param = pos;
    }
  }
  return 0;
}

/**
 * \ingroup openflow_echo_delay
 * setup a filter on the control channel to capture echo data.
 * \param ctx data context of the module
 * \param ofc the id of the channel
 */
int
get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc,
    char * filter, int buflen) {
  if (ofc == OFLOPS_CONTROL) {
    return snprintf(filter, buflen, "port %d",  ctx->listen_port);
  }
  return 0;
}

/**
 * \ingroup openflow_echo_delay
 * Handle pcap event.
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int
handle_pcap_event(oflops_context *ctx, struct pcap_event * pe, enum oflops_channel_name ch) {
  struct iphdr *ip_p;
  struct tcphdr *tcp_p;
  struct ofp_header *ofph;
  int len = pe->pcaphdr.caplen;

  if (ch == OFLOPS_CONTROL) {
    ip_p = (struct iphdr *) (pe->data + sizeof(struct ether_header));
    len -= sizeof(struct ether_header);
    if (len < 4*ip_p->ihl) {
      printf("ip header\n");
      return 0;
    }

    tcp_p = (struct tcphdr *)(pe->data + sizeof(struct ether_header) + 4*ip_p->ihl);
    len -=  4*ip_p->ihl;

    if (len < 4*tcp_p->doff) {
      printf("tcp header\n");
      return 0;
    }

    //as echo msg are, small  expect that the replies will not be spread in multiple packets
    ofph = (struct ofp_header *)(pe->data + sizeof(struct ether_header) +
        4*ip_p->ihl + 4*tcp_p->doff);
    switch(ofph->type) {
      case OFPT_ECHO_REQUEST:
        if((ntohl(ofph->xid) > 0) && (ntohl(ofph->xid) <= trans_id)) {
          echo_data_count++;
          memcpy( &echo_data[ntohl(ofph->xid)].snd, &pe->pcaphdr.ts, sizeof(struct timeval));
        }
        break;
      case OFPT_ECHO_REPLY:
        if((ntohl(ofph->xid) > 0) && (ntohl(ofph->xid) <= trans_id)) {
          memcpy( &echo_data[ntohl(ofph->xid)].rcv, &pe->pcaphdr.ts, sizeof(struct timeval));
        }
        break;
    }
  }
  return 0;
}
