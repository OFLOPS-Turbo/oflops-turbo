#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <arpa/inet.h>

#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <math.h>
#include <limits.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>

#include "log.h"
#include "traffic_generator.h"
#include "utils.h"
#include "context.h"

/** \defgroup openflow_action_delay flow action module
 * \ingroup modules
 * Packet in module.
 * This module benchmarks the implementation of specific sequence of action
 * in the action section of the flow.
 *
 * Parameters:
 *
 * - pkt_size: This parameter can be used to control the length of
 * packets of the measurement probe, measured in bytes. Thus, together with the
 *   rate parameter, it allows indirectly to adjust the packet throughput of the
 * experiment. (default 1500 bytes)
 * - data_rate: The rate of the measurement probe measured in Mbps.
 * (default 10Mbps)
 * - table: The parameter define whether the inserted flow will be
 * a wildcard(value of 1) or exact match(value of 0).  (default 1)
 * - action:  A comma separate string of entries of the format
 *   action_id/action_value. E.g. a value of `b/1010,0/2` defines that the action
 *   will modify the tcp/udp port of the matching packet to a value of 1010 and the
 * packet will be output on port 2. (default no action)
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 *
 */

/**
 * \ingroup openflow_action_delay
 * @return name of module
 */
char * name() {
  return "openflow_action_measurement";
}

// String for scheduling events
#define BYESTR "bye bye"
#define SND_ACT "send action"
#define SNMPGET "snmp get"

//logging filename
#define LOG_FILE "action_generic.log"

// Some constants to help me with conversions
const uint64_t sec_to_usec = 1000000;
const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;


uint64_t datarate = 100;
uint64_t data_snd_interval;

int table = 0;
char *network = "192.168.3.0";
struct flow *fl_probe;


// packet size limits
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

/**
 * Probe packet size
 */
uint32_t pkt_size = 1500;

/**
 * Buffer to store the content of the action of the flow mod message.
 */
void *command = NULL;
int command_len = 0;

/** The file where we write the output of the measurement process.
 */
FILE *measure_output;

/**
 * calculated sending time interval (measured in usec).
 */

int count[] = {0,0,0}; // counting how many packets where received over a
// specific channel

/**
 * storing the argument list passed to the module
 */
char *cli_param;
char *logfile = LOG_FILE;
int print = 0;

//the local mac address of the probe
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

struct entry {
  struct timeval snd,rcv;
  int ch, id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};

TAILQ_HEAD(tailhead, entry) head;

int is_hex(const char *data, int len);
uint8_t read_hex(const char *data);
int append_action(int action, const char *action_param);
uint32_t extract_pkt_id(const char *b, int len);

/**
 * \ingroup openflow_action_delay
 * Initializate flow table and schedule events
 * \param ctx pointer to opaque context
 */
int
start(struct oflops_context * ctx) {
  struct flow *fl = (struct flow*)xmalloc(sizeof(struct flow));
  fl_probe = (struct flow*)xmalloc(sizeof(struct flow));
  void *b; //somewhere to store message data
  int res, len;
  struct timeval now;  //init measurement queue
  TAILQ_INIT(&head);

  //init logging service
  msg_init();

  //log when I start module
  gettimeofday(&now, NULL);
  oflops_log(now,GENERIC_MSG , "Intializing module openflow_action_measurement");
  oflops_log(now,GENERIC_MSG , cli_param);

  get_mac_address(ctx->channels[OFLOPS_DATA1].dev, data_mac);

  make_ofp_hello(&b);
  res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  free(b);

  //send a message to clean up flow tables.
  printf("cleaning up flow table...\n");
  res = make_ofp_flow_del(&b);
  res = oflops_send_of_mesgs(ctx, b, res);
  free(b);

  /**
   * Send flow records to start routing packets.
   */
  printf("Sending new flow ...\n");
  bzero(fl, sizeof(struct flow));
  if(table == 0)
    fl->mask = 0; //if table is 0 the we generate an exact match */
  else
    fl->mask = OFPFW_IN_PORT | OFPFW_DL_VLAN | OFPFW_DL_VLAN_PCP | OFPFW_TP_DST;
  fl->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
  fl->dl_type = htons(ETHERTYPE_IP);
  memcpy(fl->dl_src, data_mac, ETH_ALEN);
  memcpy(fl->dl_dst, "\x00\x15\x17\x7b\x92\x0a", ETH_ALEN);
  fl->dl_vlan = htons(1);
  fl->nw_proto = IPPROTO_UDP;
  fl->nw_src =  inet_addr("10.1.1.1");
  fl->nw_dst =  inet_addr("10.1.1.2");
  fl->tp_src = htons(8080);
  fl->tp_dst = htons(8080);
  len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA2].of_port, 1, 1200);
  res = oflops_send_of_mesgs(ctx, b, len);
  free(b);
  //store locally the applied rule of the data stream
  memcpy(fl_probe, fl, sizeof(struct flow));

  /**
   * Shceduling events
   */
  //send the flow modyfication command in 30 seconds.
  gettimeofday(&now, NULL);
  add_time(&now, 20, 0);
  oflops_schedule_timer_event(ctx,&now, SND_ACT);

  //get port and cpu status from switch
  gettimeofday(&now, NULL);
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx,&now, SNMPGET);

  //end process
  gettimeofday(&now, NULL);
  add_time(&now, 30, 0);
  oflops_schedule_timer_event(ctx,&now, BYESTR);
  return 0;
}

/**
 * \ingroup openflow_action_delay
 * calculate the stats of the measurement probes.
 * \param ctx data context of the module.
 */
int
destroy(struct oflops_context *ctx) {
  char msg[1024];
  struct timeval now;
  FILE *out = fopen(logfile, "w");
  struct entry *np;
  int  min_id[] = {INT_MAX, INT_MAX, INT_MAX};
  int ix[] = {0,0,0};
  int max_id[] = {INT_MIN, INT_MIN, INT_MIN}, ch;
  uint32_t mean, std, median;
  float loss;
  double **data;

  gettimeofday(&now, NULL);
  printf("destroying code\n");

  //insert delay
  data = xmalloc(3*sizeof(double *));
  for(ch = 0; ch < 3; ch++)
    data[ch] = xmalloc(count[ch]*sizeof(double));

  for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
    ch = np->ch - 1;
    min_id[ch] = (np->id < min_id[ch])?np->id:min_id[ch];
    max_id[ch] = (np->id > max_id[ch])?np->id:max_id[ch];
    data[ch][ix[ch]++] = time_diff(&np->snd, &np->rcv);
    if(print)
      if(fprintf(out, "%lu %lu.%06lu %lu.%06lu %d\n",
            (long unsigned int)np->id,
            (long unsigned int)np->snd.tv_sec,
            (long unsigned int)np->snd.tv_usec,
            (long unsigned int)np->rcv.tv_sec,
            (long unsigned int)np->rcv.tv_usec,  np->ch) < 0)
        perror_and_exit("fprintf fail", 1);
    //release memory
    free(np);
  }

  for(ch = 0; ch < 3; ch++) {
    if(ix[ch] == 0) continue;
    gsl_sort (data[ch], 1, ix[ch]);
    mean = (uint32_t)gsl_stats_mean(data[ch], 1, ix[ch]);
    std = (uint32_t)sqrt(gsl_stats_variance(data[ch], 1, ix[ch]));
    median = (uint32_t)gsl_stats_median_from_sorted_data (data[ch], 1, ix[ch]);
    loss = (float)ix[ch]/(float)(max_id[ch] - min_id[ch]);

    //print summarization data
    snprintf(msg, 1024, "statistics:port:%d:%u:%u:%u:%.4f:%d",
        ctx->channels[ch + 1].of_port, mean, median, std, loss, count[ch]);
    printf("statistics:port:%d:%u:%u:%u:%.4f:%d\n",
        ctx->channels[ch + 1].of_port, mean, median, std, loss, count[ch]);
    oflops_log(now, GENERIC_MSG, msg);
  }

  return 0;
}

/**
 * \ingroup openflow_action_delay
 * Handle timer event
 * - BYESTR: terminate module
 * - SND_ACT: send measured action
 * - SNMPGET: query snmp stats
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te) {
  char *str = te->arg;
  int len, i;
  void *b;
  struct timeval now;
  //terminate process
  if (strcmp(str, BYESTR) == 0) {
    printf("terminating test....\n");
    oflops_end_test(ctx,1);
    return 0;
  } else if (strcmp(str, SND_ACT) == 0) {
    len = make_ofp_flow_modify(&b, fl_probe, command, command_len,
        1, 1200);
    oflops_send_of_mesg(ctx, b);
    free(b);
    printf("sending correct modification to measure delay\n");
  } else if(strcmp(str, SNMPGET) == 0) {
    for(i=0;i<ctx->cpuOID_count;i++) {
      oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);
    }
    for(i=0;i<ctx->n_channels;i++) {
      oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);
      oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);
    }
    gettimeofday(&now, NULL);
    add_time(&now, 5, 0);
    oflops_schedule_timer_event(ctx,&now, SNMPGET);
  }
  return 0;
}

/**
 * \ingroup openflow_action_dela
 * setup a filter on data channels only
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap
 * @param buflen length of buffer
 */
int get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc,
        char * filter, int buflen)
{
    if(ofc == OFLOPS_DATA2) {
        return snprintf(filter, buflen, "udp");
    }
    return 0;
}

/**
 * \ingroup openflow_action_dela
 * Handle pcap event.
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int
handle_pcap_event(struct oflops_context *ctx, struct pcap_event * pe, oflops_channel_name ch) {
  struct pktgen_hdr *pktgen;
  int dir, len;
  struct ofp_header *ofp;
  struct pcap_event *ofp_msg;
  struct flow fl;

/*  if (ch == OFLOPS_CONTROL) {
    dir = append_data_to_flow(pe->data,pe->pcaphdr);
    while(contains_next_msg(dir) > 0) {
      len = get_next_msg(dir, &ofp_msg);
      ofp = (struct ofp_header *)ofp_msg->data;
      switch(ofp->type) {
        case OFPT_FLOW_MOD:
          oflops_log(pe->pcaphdr.ts,OFPT_FLOW_MOD_ADD, "flow modification send");
          break;
      }
    }
  } else  */

  if ((ch == OFLOPS_DATA1) || (ch == OFLOPS_DATA2) || (ch == OFLOPS_DATA3)) {
    // printf("got a packet on port %d\n", ch);
    pktgen = extract_pktgen_pkt(ctx, ch, pe->data, pe->pcaphdr.caplen, &fl);
    if(pktgen == NULL) {
      printf("Failed to parse measurement packet\n");
      return 0;
    }

    struct entry *n1 = malloc(sizeof(struct entry));
    n1->snd.tv_sec = pktgen->tv_sec;
    n1->snd.tv_usec = pktgen->tv_usec;
    memcpy(&n1->rcv, &pe->pcaphdr.ts, sizeof(struct timeval));
    n1->id = pktgen->seq_num;
    n1->ch = ch;
    count[ch - 1]++;
    TAILQ_INSERT_TAIL(&head, n1, entries);
  }
  return 0;
}

/**
 * \ingroup openflow_action_delay
 * reply to echo requests
 * \param ctx data context of the module
 * \param ofph pointer to data of the echo packet
 */
int
of_event_echo_request(struct oflops_context *ctx, const struct ofp_header * ofph) {
  struct ofp_header * ofp_reply = xmalloc(sizeof(struct ofp_header));
  memcpy(ofp_reply, ofph, sizeof(struct ofp_header));
  ofp_reply->type = OFPT_ECHO_REPLY;
  oflops_send_of_mesgs(ctx, (void *)ofp_reply, sizeof(struct ofp_header));
  return 0;
}

/**
 * \ingroup openflow_action_delay
 * handle asynch. snmp replies
 * \param ctx data context of module
 * \param se snmp data
 */
int
handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  netsnmp_variable_list *vars;
  int len = 1024;
  char msg[1024], out_buf[1024];
  struct timeval now;
  int i;
  gettimeofday(&now, NULL);

  for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {
    snprint_value(msg, len, vars->name, vars->name_length, vars);
    for (i = 0; i < ctx->cpuOID_count; i++) {
      if((vars->name_length == ctx->cpuOID_len[i]) &&
          (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
        snprintf(out_buf, len, "cpu:%s", msg);
        oflops_log(now, SNMP_MSG, out_buf);
      }
    }

    for(i=0;i<ctx->n_channels;i++) {
      if((vars->name_length == ctx->channels[i].inOID_len) &&
          (memcmp(vars->name, ctx->channels[i].inOID,
                  ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
        snprintf(out_buf, len, "port %d : rx %s pkts",
            (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
        oflops_log(now, SNMP_MSG, out_buf);
        break;
      }

      if((vars->name_length == ctx->channels[i].outOID_len) &&
          (memcmp(vars->name, ctx->channels[i].outOID,
                  ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
        snprintf(out_buf, len, "port %d : tx %s pkts",
            (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
        oflops_log(now, SNMP_MSG, out_buf);
        break;
      }
    } //for
  }// if cpu
  return 0;
}

/**
 * \ingroup openflow_action_delay
 * Traffic generation methods
 * \param ctx data context of module
 */
int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;

  init_traf_gen(ctx);
  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"10.1.1.2");
  strcpy(det.dst_ip_max,"10.1.1.2");
  if(ctx->trafficGen == PKTGEN)
    strcpy(det.mac_src,"00:00:00:00:00:00");
  else
    snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned char)data_mac[0], (unsigned char)data_mac[1],
        (unsigned char)data_mac[2], (unsigned char)data_mac[3],
        (unsigned char)data_mac[4], (unsigned char)data_mac[5]);
  strcpy(det.mac_dst,"00:15:17:7b:92:0a");
  det.vlan = 1;
  det.vlan_p = 0;
  det.vlan_cfi = 0;
  det.pkt_count = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  det.delay = data_snd_interval*1000;
  strcpy(det.flags, "");
  add_traffic_generator(ctx, OFLOPS_DATA1, &det);

  start_traffic_generator(ctx);
  return 1;
}


/*
 * read the first 2 hex characters and return the byte.
 */
uint8_t
read_hex(const char *data) {
  uint8_t ret = 0;
  int i;

  for(i = 0 ; i < 2 ; i++) {
    ret = ret << 4;
    if((*data >= 'A') && (*data <= 'F')) {
      ret += 10 + (*data - 'A');
    } else if((*data >= 'a') && (*data <= 'f')) {
      ret += 10 + ((*data) - 'a');
    } else if((*data >= '0') && (*data <= '9')) {
      ret += ((*data) - '0');
    }
    data++;
  }
  return ret;
}

/**
 * \ingroup openflow_action_delay
 * Initialization code with parameters
 * @param ctx
 */
int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  int len = strlen(config_str);
  char *value = NULL;
  char *action;
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
      } else if(strcmp(param, "data_rate") == 0) {
        //parse int to get rate of background data
        datarate = strtol(value, NULL, 0);
        if((datarate < 0) || (datarate > 1010))
          perror_and_exit("Invalid data rate param(Values between 1 and 1010)", 1);
      } else if(strcmp(param, "action") == 0) {
        char *p = value;
        while((*p != ' ') && (*p != '\0') && (config_str + len > p)) {
          action = p;
          //find where value ends and set it to null to extract the string.
          p = index(p, ',');
          if(p == NULL) {
            p = config_str + len + 1;
            *p='\0';
          } else {
            *p = '\0';
            p++;
          }

          //set null char to split action param and action value
          param = index(action, '/');
          if(param != NULL) {
            *param = '\0';
            param++;
          }

          //check if action value is correct and append it at the end of the action list
          if(*action >= '0' && *action <= '9') {
            append_action((*action) - '0', param);
          } else if (*action == 'a') {
            append_action(10, param);
          } else {
            printf("invalid action: %1s", action);
            continue;
          }
        }
      } else if(strcmp(param, "table") == 0) {
        //parse int to get pkt size
        table = strtol(value, NULL, 0);
        if((table < 0) && (table > 2))
          perror_and_exit("Invalid table number", 1);
      } else if(strcmp(param, "print") == 0) {
        //parse int to check whether per packet statistics should be stored
        print = strtol(value, NULL, 0);
      } else
        fprintf(stderr, "Invalid parameter:%s\n", param);
      param = pos;
    }
  }

  //calculate sendind interval
  data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (datarate * mbits_to_bits);
  fprintf(stderr, "Sending data interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n",
      (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);

  return 0;
}

/*
 * Help function
 */
/*
 * Given the global variables buffer and buffer_len, append at their end
 * the commands that with type action and action param action_param.
 * @param action the id of the action.
 * @param action_param the parameter of the action
 * @todo code is very dirty. Needs to be refactored.
 */
int
append_action(int action, const char *action_param) {
  struct ofp_action_output *act_out;
  struct ofp_action_vlan_vid *act_vid;
  struct ofp_action_vlan_pcp *act_pcp;
  struct ofp_action_header *act;
  struct ofp_action_dl_addr *act_dl;
  struct ofp_action_nw_addr *act_nw;
  struct ofp_action_nw_tos *act_tos;
  struct ofp_action_tp_port *act_port;
  switch(action) {
    case OFPAT_OUTPUT:
      fprintf(stderr, "output packet to port %s\n", action_param);
      command_len += sizeof(struct ofp_action_output);

      command = realloc(command, command_len);
      act_out = (struct ofp_action_output *)
        (command + (command_len - sizeof(struct ofp_action_output)));
      bzero((void *)act_out,sizeof(struct ofp_action_output));
      act_out->type = htons(action);
      act_out->len = htons(8);
      act_out->max_len = htons(2000);
      act_out->port = htons((uint16_t)strtol(action_param, NULL, 10));
      break;
    case OFPAT_SET_VLAN_VID:
      if( (strtol(action_param, NULL, 10) < 0) || (strtol(action_param, NULL, 10) >= 0xFFF)) {
        printf("invalid vlan id\n");
        return -1;
      }
      fprintf(stderr, "change vlan to %ld\n", strtol(action_param, NULL, 10));
      command_len += sizeof(struct ofp_action_vlan_vid);
      command = realloc(command, command_len);
      act_vid = (struct ofp_action_vlan_vid *)
        (((void *)command) + (command_len-sizeof(struct ofp_action_vlan_vid)));
      bzero((void *)act_vid, sizeof(struct ofp_action_vlan_vid));
      act_vid->type = htons(action);
      act_vid->len = htons(8);
      act_vid->vlan_vid = htons((uint16_t)strtol(action_param, NULL, 10));
      break;
    case OFPAT_SET_VLAN_PCP:
      if( (strtol(action_param, NULL, 16) < 0) || (strtol(action_param, NULL, 16) > 7)) {
        printf("invalid vlan pcp\n");
        return -1;
      }
      printf("change vlan pcp %ld\n", strtol(action_param, NULL, 16));
      command_len += sizeof(struct ofp_action_vlan_pcp);
      command = realloc(command, command_len);
      act_pcp = (struct ofp_action_vlan_pcp *)
        (command + (command_len - sizeof(struct ofp_action_vlan_pcp)));
      bzero((void *)act_pcp, sizeof(struct ofp_action_vlan_pcp));
      act_pcp->type = htons(action);
      act_pcp->len = htons(8);
      act_pcp->vlan_pcp = (uint8_t)strtol(action_param, NULL, 16);
      break;
    case OFPAT_STRIP_VLAN:
      printf("strip vlan header\n");
      command_len += sizeof(struct ofp_action_header);
      command = realloc(command, command_len);
      act = (struct ofp_action_header *)
        (command + (command_len - sizeof(struct ofp_action_header)));
      bzero((void *)act, sizeof(struct ofp_action_header));
      act->type = htons(action);
      act->len = htons(8);
      break;
    case OFPAT_SET_DL_SRC:
    case OFPAT_SET_DL_DST:
      if((strlen(action_param) != 12) || (is_hex(action_param, 12) == 0)) {
        printf("invalid mac address\n");
        return -1;
      }
      printf("Change ethernet address to %s\n", action_param);
      command_len += sizeof(struct ofp_action_dl_addr);
      command = realloc(command, command_len);
      act_dl = (struct ofp_action_dl_addr *)
        (((void *)command) + (command_len - sizeof(struct ofp_action_dl_addr)));
      bzero((void *)act_dl, sizeof(struct ofp_action_header));
      act_dl->type = htons(action);
      act_dl->len = htons(16);
      int i;
      for(i = 0 ; i < 6; i++) {
        act_dl->dl_addr[i] = read_hex(action_param);
        action_param += 2;
      }
      printf("%02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned char)act_dl->dl_addr[0],
          (unsigned char)act_dl->dl_addr[1], (unsigned char)act_dl->dl_addr[2],
          (unsigned char)act_dl->dl_addr[3], (unsigned char)act_dl->dl_addr[4],
          (unsigned char)act_dl->dl_addr[5]);
      break;
    case OFPAT_SET_NW_SRC:
    case OFPAT_SET_NW_DST:
      printf("Change ip address to %llx\n",  strtoll(action_param, NULL, 16));
      if((strlen(action_param) != 8) || (is_hex(action_param, 8) == 0)) {
        printf("invalid ip address\n");
        return -1;
      }
      command_len += sizeof(struct ofp_action_nw_addr);
      command = realloc(command, command_len);
      act_nw = (struct ofp_action_nw_addr *)
        (command + (command_len - sizeof(struct ofp_action_nw_addr)));
      act_nw->type = htons(action);
      act_nw->len = htons(8);
      act_nw->nw_addr = htonl(strtoll(action_param, NULL, 16));
      break;

    case OFPAT_SET_NW_TOS:
      printf("change tos to %lx\n", strtol(action_param, NULL, 16));
      command_len += sizeof(struct ofp_action_nw_tos);
      command = realloc(command, command_len);
      act_tos = (struct ofp_action_nw_tos *)
        (((void *)command) + (command_len - sizeof(struct ofp_action_nw_tos)));
      act_tos->type = htons(action);
      act_tos->len = htons(8);
      act_tos->nw_tos = (uint8_t)strtol(action_param, NULL, 16);
      break;

    case OFPAT_SET_TP_SRC:
    case OFPAT_SET_TP_DST:
      printf("change port to %ld\n", strtol(action_param, NULL, 16));
      command_len += sizeof(struct ofp_action_tp_port);
      command = realloc(command, command_len);
      act_port = (struct ofp_action_tp_port *)
        (((void *)command) + (command_len - sizeof(struct ofp_action_tp_port)));
      act_port->type = htons(action);
      act_port->len = htons(8);
      act_port->tp_port = htons((uint16_t)strtol(action_param, NULL, 16));
      break;
  }
  return 0;
}


/*
 * check if the char array contains hex like characters only.
 */
int
is_hex(const char *data, int len) {
  int i;
  for(i = 0 ; i < len; i++) {
    if(!( ((*data >= 'A') && (*data <= 'F')) ||
          ((*data >= 'a') && (*data <= 'f')) ||
          ((*data >= '0') && (*data <= '9')) ))
      return 0;
    data++;
  }
  return 1;
}


void
print_hex(char *data) {
  int i,j;
  for (i = 1; i <= 5; i++) {
    for(j = 0; j < 8; j++) {
      printf("%02x%02x ", (uint8_t)*(data+(16*i+2*j)), (uint8_t)*(data+(16*i+2*j+1)) );
    }
    printf("\n");
  }
}
