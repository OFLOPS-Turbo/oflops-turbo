#include <sys/queue.h>
#include <math.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>
#include <gsl/gsl_sort.h>

#include <nf_pktgen.h>

#include "of_parser.h"
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

struct entry {
  struct timeval snd,rcv;
  int ch, id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};

/** The rate at which data will be send between the data ports (In Mbits per sec.).
 */
uint64_t duration = 10;

TAILQ_HEAD(tailhead, entry) head;

FILE *measure_output;
double *delay;
uint32_t delay_count;
uint64_t max_pkt_count;

uint32_t
get_snmp_packet_counter(oflops_context *ctx) {
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
    snmp_add_null_var(pdu, ctx->channels[OFLOPS_DATA1].outOID,
		      ctx->channels[OFLOPS_DATA1].outOID_len);
    /*
     * Send the Request out.
     */
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
      for(vars = response->variables; vars; vars = vars->next_variable)  {
	ret = (uint32_t)*(vars->val.integer);
      }
    }
  } while(status != STAT_SUCCESS || response->errstat != SNMP_ERR_NOERROR);

  if (response)
    snmp_free_pdu(response);
  response = NULL;
  snmp_close(ss);

  return ret;
}


int init(oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  //init counters
  sendno = 0;
  TAILQ_INIT(&head);
  finished = 0;
  //open file for storing measurement
  measure_output = fopen("measure.log", "w");

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

  //calculate maximum number of packet I may receive
  printf("%lu %u %lu %lu %lu\n", duration, pkt_size, byte_to_bits, sec_to_usec,
	 mbits_to_bits);
  max_pkt_count = duration*1000000000 /
    ((pkt_size * byte_to_bits * sec_to_usec) / (mbits_to_bits));
  delay = (double *)xmalloc(max_pkt_count * sizeof(double));
    printf("delay_count : %lu\n", max_pkt_count);

  return 0;
}

/** Initialization
 * @param ctx pointer to opaque context
 */
int start(oflops_context * ctx) {
  void *b;
  struct flow *fl = (struct flow*)xmalloc(sizeof(struct flow));
  int res, len;
  msg_init();

  //get the mac address of channel 1
  get_mac_address(ctx->channels[OFLOPS_DATA1].dev, local_mac);
  printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ctx->channels[OFLOPS_DATA1].dev,
	 (unsigned char)local_mac[0], (unsigned char)local_mac[1],
	 (unsigned char)local_mac[2], (unsigned char)local_mac[3],
	 (unsigned char)local_mac[4], (unsigned char)local_mac[5]);


  make_ofp_hello(&b);
  write(ctx->control_fd, b, sizeof(struct ofp_hello));
  free(b);

  // clean up flow table
  printf("cleaning up flow table...\n");
  res = make_ofp_flow_del(&b);
  write(ctx->control_fd, b, res);
  free(b);

  //Send a singe ruke to route the traffic we will generate
  bzero(fl, sizeof(struct flow));
  fl->mask = OFPFW_IN_PORT | OFPFW_TP_DST;
  fl->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
  fl->dl_type = htons(ETHERTYPE_IP);
  memcpy(fl->dl_src, local_mac, ETH_ALEN);
  memcpy(fl->dl_dst, "\x00\x1e\x68\x9a\xc5\x75", ETH_ALEN);
  fl->dl_vlan = 0xffff;
  fl->nw_proto = IPPROTO_UDP;
  fl->nw_src =  inet_addr("10.1.1.1");
  fl->nw_dst =  inet_addr("10.1.1.2");
  fl->tp_src = htons(8080);
  fl->tp_dst = htons(8080);
  len = make_ofp_flow_add(&b, fl, OFPP_IN_PORT, 0, OFP_FLOW_PERMANENT);
  write(ctx->control_fd, b, len);
  free(b);

  free(fl);

  return 0;
}

/** Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap
 * @param buflen length of buffer
 */
int get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc, char * filter, int buflen) {
  //set the system to listwn on port 1
  if(ofc == OFLOPS_DATA1)
    return snprintf(filter,buflen," ");
  else
    return 0;

}

int
handle_pcap_event(oflops_context *ctx, struct pcap_event * pe, enum oflops_channel_name ch) {
  struct pktgen_hdr *pktgen;
  struct timeval snd, rcv;
  struct flow fl;

  if(ch == OFLOPS_DATA1) {
    if(delay_count >= max_pkt_count) {
      printf("received packet is more than %lu\n", max_pkt_count);
      return 0;
    }
    pktgen = extract_pktgen_pkt(ctx, ch, pe->data, pe->pcaphdr.caplen, &fl);
    if(pktgen == NULL) {
      printf("Malformed packet\n");
      return 0;
    }

    snd.tv_sec = pktgen->tv_sec;
    snd.tv_usec = pktgen->tv_usec;
    memcpy(&rcv, &pe->pcaphdr.ts, sizeof(struct timeval));
    delay[delay_count++] = (double)time_diff(&snd, &rcv);
  }
  return 0;
}

int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  char msg[1024];
  //int datarate[]={1, 10, 64, 128, 256, 512, 1000};
  //int datarate_count = 7;
  int datarate[]={128, 256, 512, 1000};
  int datarate_count = 4;

  int i;
  uint64_t data_snd_interval;
  uint32_t mean, std, median;
  float loss;
  struct timeval now;
  uint32_t start_count, end_count;
  struct nf_gen_stats gen_stat;
  struct nf_cap_stats stat;

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


  strcpy(det.mac_dst,"00:1e:68:9a:c5:75");
  det.vlan = 0xffff;
  det.vlan_p = 1;
  det.vlan_cfi = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  strcpy(det.flags, "");

  //calculating interpacket gap
  for (i = 0; i < datarate_count; i++) {
    char filename[100];
    snprintf(filename, 100, "queue-%04d-delay.txt", datarate[i] );
    test_output = fopen(filename, "w");
    if(!test_output)
      perror_and_exit("fopen", 1);

    start_count = get_snmp_packet_counter(ctx);
    //init packet counter
    delay_count = 0;

    //claculate interpacket gap
    data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec*1000) / (datarate[i] * mbits_to_bits);
    det.delay = data_snd_interval;
    //calculate packets send
    if(data_snd_interval)
      det.pkt_count = ((uint64_t)(duration*1000000000) / (data_snd_interval));
    else
      det.pkt_count = (uint64_t)(duration*1000000000);
    //print sending probe details
    fprintf(stderr, "Sending data interval : %u nsec (pkt_size: %u bytes, rate: %u Mbits/sec %lu packets)\n",
	    (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate[i],  det.pkt_count);

    //start packet generator
    add_traffic_generator(ctx, OFLOPS_DATA1, &det);
    start_traffic_generator(ctx);

    sleep(10);

    fclose(test_output);


    end_count = get_snmp_packet_counter(ctx);
    gsl_sort (delay, 1, delay_count);
    mean = (uint32_t)gsl_stats_mean(delay, 1, delay_count);
    std = (uint32_t)sqrt(gsl_stats_variance(delay, 1, delay_count));
    median = (uint32_t)gsl_stats_median_from_sorted_data (delay, 1, delay_count);
    //    loss = (float)delay_count/(float)det.pkt_count;
    loss =  (float)(det.pkt_count - (end_count - start_count))/(float)det.pkt_count;


    printf("delay:%d:%u:%u:%u:%.4f:%d:%u\n",
	   datarate[i], mean, median, std, loss, delay_count, (end_count - start_count));
    snprintf(msg, 1024, "delay:%d:%u:%u:%u:%.4f:%d:%u",
	     datarate[i], mean, median, std, loss, delay_count, (end_count - start_count));
    gettimeofday(&now, NULL);
    oflops_log(now, GENERIC_MSG, msg);
    // TODO: snprintf the name of of_data1 device instead

    if(ctx->trafficGen == NF_PKTGEN) {
      display_xmit_metrics(0, &gen_stat);
	nf_cap_stat(0, &stat);
	snprintf(msg, 1024, "nf:%u:%u:%u", datarate[i], gen_stat.pkt_snd_cnt, stat.pkt_cnt);
      oflops_log(now, GENERIC_MSG, msg);
      printf("%s\n", msg);
    }
  }

  oflops_end_test(ctx,1);
  return 1;
}

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

