#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <math.h>
#include <limits.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>
#include <openflow/openflow.h>

#include <gsl/gsl_statistics.h>
#include <gsl/gsl_sort.h>

#include "of_parser.h"
#include "log.h"
#include "traffic_generator.h"
#include "utils.h"
#include "context.h"

/** \defgroup openflow_mod_flow openflow add flow
 *   \ingroup modules
 * \brief Openflow flow insertion test module.
 *
 * A module to measure the scalabitily and performance of the flow addition
 * mechanism of an openflow implementation.
 *
 * Parameter:
 *
 * - pkt_size: This parameter can be used to control the length of the
 * packets of the measurement probe. It allows indirectly to adjust the packet
 * throughput of the experiment. The parameter uses bytes as measurement unit.
 * The parameter applies for both measurement probes.
 * - probe_rate: The rate of the sequential probe, measured in Mbps.
 * - data_rate: The rate of the constant probe, measured in Mbps.
 * - flows:  The number of unique flows that the module will
 * update/insert.
 * - table:  This parameter controls whether the inserted flow will be
 *  a wildcard(value of 1) or exact match(value of 0). For the wildcard flows, the
 *  module wildcards all of the fields except the destination IP address.
 * - print: This parameter enables the measurement module to print
 *  extended per packet measurement information. The information is printed in a
 *  separate CSV file, named "action\_aggregate.log".
 *
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 *
 */

/**
 * \ingroup openflow_mod_flow
 * get the name of the module
 * \return name of module
 */
char * name() {
    return "openflow_mod_flow";
}

/**
 * event static names
 */
#define BYESTR "bye bye"
#define SND_ACT "send action"
#define SNMPGET "snmp get"

//logging filename
#define LOG_FILE "action_aggregate.log"
char *logfile = LOG_FILE;

/**
 * packet size limits
 */
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

/**
 * Some constants to help me with conversions
 */
const uint64_t sec_to_usec = 1000000;
const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

// packet generation loca variables
uint64_t proberate = 100;
uint64_t datarate = 100;
uint32_t pkt_size = 1500;
uint64_t probe_snd_interval;
uint64_t data_snd_interval;
int table = 0;
char *network = "192.168.2.0";
int flows = 100;
struct flow *fl_probe;

/**
 * A variable to inform when the module is over.
 */
int finished, first_pkt = 0;
//control if a per packet measurement log is created on destroy
int print = 0;
struct timeval flow_mod_timestamp, pkt_timestamp;
int send_flow_mod = 0, stored_flow_mod_time = 0;
int count[] = {0,0,0};

char *cli_param;

char local_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

struct entry {
    struct timeval snd,rcv;
    int ch, id;
    uint32_t dst_ip;
    TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};
TAILQ_HEAD(tailhead, entry) head;


int *ip_received;
int ip_received_count;

/**
 * \ingroup openflow_mod_flow
 * Initialize mac address of the measurement probe, setup connection
 * channel, insert initial flow set and schedule events.
 * @param ctx pointer to opaque context
 */
int
start(oflops_context * ctx) {
    fl_probe = (struct flow*)xmalloc(sizeof(struct flow));
    void *b; //somewhere to store message data
    struct timeval now;
    char msg[1024];
    struct in_addr ip_addr;
    int i, len, inc = 1;

    //init module packet queue
    TAILQ_INIT(&head);

    //Initialize pap-based  tcp flow reassembler for the communication
    //channel
    msg_init();
    bzero(&flow_mod_timestamp, sizeof(struct timeval));
    snprintf(msg, 1024,  "Intializing module %s", name());

    get_mac_address(ctx->channels[OFLOPS_DATA1].dev, local_mac);
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ctx->channels[OFLOPS_DATA2].dev,
            (unsigned char)local_mac[0], (unsigned char)local_mac[1], (unsigned char)local_mac[2],
            (unsigned char)local_mac[3], (unsigned char)local_mac[4], (unsigned char)local_mac[5]);
    get_mac_address(ctx->channels[OFLOPS_DATA2].dev, data_mac);

    //log when I start module
    oflops_gettimeofday(ctx, &now);
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
     * Send flow records to start switching packets.
     */

    printf("XXXXXXXXXXXXX starting table = %dXXXXXXXXXX", table);
    bzero(fl_probe, sizeof(struct flow));
    if(table == 0)
        fl_probe->mask = 0; //if table is 0 the we generate an exact match */
    else
        fl_probe->mask =  OFPFW_DL_DST | OFPFW_DL_SRC | (32 << OFPFW_NW_SRC_SHIFT) |
            (0 << OFPFW_NW_DST_SHIFT) | OFPFW_DL_VLAN | OFPFW_TP_DST | OFPFW_NW_PROTO |
            OFPFW_TP_SRC | OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS;

    oflops_gettimeofday(ctx, &flow_mod_timestamp);
    fl_probe->dl_type = htons(ETHERTYPE_IP);
    memcpy(fl_probe->dl_src, data_mac, 6);
    memcpy(fl_probe->dl_dst, "\x00\x15\x17\x7b\x92\x0a", 6);
    fl_probe->in_port = htons(ctx->channels[OFLOPS_DATA2].of_port);
    fl_probe->dl_vlan = 0;
    fl_probe->nw_src =  inet_addr("10.1.1.1");
    ip_addr.s_addr = inet_addr(network);
    ip_addr.s_addr =  ntohl(ip_addr.s_addr);
    fl_probe->nw_proto = IPPROTO_UDP;
    fl_probe->tp_src = htons(8080);
    fl_probe->tp_dst = htons(8080);

    for(i=0; i< flows; i++) {
        fl_probe->nw_dst =  htonl(ip_addr.s_addr);
        len = make_ofp_flow_modify_output_port(&b, fl_probe,
                ctx->channels[OFLOPS_DATA3].of_port, -1, 1200);
        ((struct ofp_flow_mod *)b)->priority = htons(11);
        ((struct ofp_flow_mod *)b)->flags = 0;
        oflops_send_of_mesgs(ctx, b, len);
        free(b);
        ip_addr.s_addr += inc;
    }
    ip_received = xmalloc(flows*sizeof(int));
    memset(ip_received, 0, flows*sizeof(int));

    /**
     * Shceduling events
     */
    //send the flow modyfication command in 30 seconds.
    oflops_schedule_timer_event(ctx, 40, 0, SND_ACT);

    //get port and cpu status from switch
    oflops_schedule_timer_event(ctx, 1, 0, SNMPGET);

    //end process
    oflops_schedule_timer_event(ctx, 240, 0, BYESTR);

    return 0;
}

/**
 * \ingroup openflow_mod_flow
 * Calculate measurement probe stats and output them.
 * \param ctx module context
 */
int destroy(oflops_context *ctx) {
    FILE *out = NULL;
    struct entry *np;
    int  min_id[] = {INT_MAX, INT_MAX, INT_MAX};
    int ix[] = {0,0,0};

    int max_id[] = {INT_MIN, INT_MIN, INT_MIN}, ch;
    char msg[1024];
    struct timeval now;
    double **data;
    uint32_t mean, std, median;
    float loss;
    struct in_addr in;

    //get what time we start printin output
    oflops_gettimeofday(ctx, &now);

    //open log file if required
    if(print) {
        out = fopen(logfile, "w");
        if(out == NULL)
            perror_and_exit("fopen_logfile", 1);
    }

    //init tmp data storage
    data = xmalloc(3*sizeof(double *));
    for(ch = 0; ch < 3; ch++) {
        data[ch] = xmalloc(count[ch]*sizeof(double));
    }

    // for every measurement save the delay in the appropriate entry on the
    // measurement matrix
    for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
        ch = np->ch - 1;
        min_id[ch] = (np->id < min_id[ch])?np->id:min_id[ch];
        max_id[ch] = (np->id > max_id[ch])?np->id:max_id[ch];
        data[ch][ix[ch]++] = time_diff(&np->snd, &np->rcv);
        //print also packet details on otuput if required
        if(print) {
            in.s_addr = np->dst_ip;
            if(fprintf(out, "%lu %lu.%06lu %lu.%06lu %d %s\n",
                        (long unsigned int)np->id,
                        (long unsigned int)np->snd.tv_sec,
                        (long unsigned int)np->snd.tv_usec,
                        (long unsigned int)np->rcv.tv_sec,
                        (long unsigned int)np->rcv.tv_usec,  np->ch,
                        inet_ntoa(in)) < 0)
                perror_and_exit("fprintf fail", 1);
        }

        free(np);
    }

    for(ch = 0; ch < 3; ch++) {
        if(ix[ch] > 0) {
            gsl_sort (data[ch], 1, ix[ch]);
            mean = (uint32_t)gsl_stats_mean(data[ch], 1, ix[ch]);
            std = (uint32_t)sqrt(gsl_stats_variance(data[ch], 1, ix[ch]));
            median = (uint32_t)gsl_stats_median_from_sorted_data (data[ch], 1, ix[ch]);
            loss = (float)ix[ch]/(float)(max_id[ch] - min_id[ch]);

            snprintf(msg, 1024, "statistics:port:%d:%u:%u:%u:%.4f:%d",
                    ctx->channels[ch + 1].of_port, mean, median, std, loss, count[ch]);
            printf("statistics:port:%d:%u:%u:%u:%.4f:%d\n",
                    ctx->channels[ch + 1].of_port, mean, median, std, loss, count[ch]);
            oflops_log(now, GENERIC_MSG, msg);
        }
    }
    return 0;
}

/**
 * \ingroup openflow_mod_flow
 * Handle timer event.
 * - BYESTR: terminate module execution
 * - SND_ACT: send new flows to switch
 * - SNMPGET: query stats from switch using snmp
 * @param ctx context of module
 * @param te event data
 */
int handle_timer_event(oflops_context * ctx, struct timer_event *te) {
    char *str = te->arg;
    int len, i, inc=1;
    void *b;
    struct in_addr ip_addr;

    //terminate process
    if (strcmp(str, BYESTR) == 0) {
        printf("terminating test....\n");
        oflops_end_test(ctx,1);
        finished = 0;
        return 0;
    } else if (strcmp(str, SND_ACT) == 0) {
        //first create new rules
        send_flow_mod = 1;
        if(table == 0)
            fl_probe->mask = 0; //if table is 0 the we generate an exact match */
        else
            fl_probe->mask =  OFPFW_DL_DST | OFPFW_DL_SRC | (32 << OFPFW_NW_SRC_SHIFT) |
                (0 << OFPFW_NW_DST_SHIFT) | OFPFW_DL_VLAN | OFPFW_TP_DST | OFPFW_NW_PROTO |
                OFPFW_TP_SRC | OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS;

        oflops_gettimeofday(ctx, &flow_mod_timestamp);
        oflops_log(flow_mod_timestamp, GENERIC_MSG, "START_FLOW_MOD");
        memcpy(fl_probe->dl_src, data_mac, 6);
        memcpy(fl_probe->dl_dst, "\x00\x15\x17\x7b\x92\x0a", 6);
        fl_probe->in_port = htons(ctx->channels[OFLOPS_DATA2].of_port);
        ip_addr.s_addr = inet_addr(network);
        ip_addr.s_addr =  ntohl(ip_addr.s_addr);
        for(i=0; i< flows; i++) {
            fl_probe->nw_dst =  htonl(ip_addr.s_addr);
            len = make_ofp_flow_add(&b, fl_probe,
                    ctx->channels[OFLOPS_DATA1].of_port, 1, 1200);
            ((struct ofp_flow_mod *)b)->priority = htons(11);
            ((struct ofp_flow_mod *)b)->flags = 0;
            oflops_send_of_mesgs(ctx, b, len);
            free(b);
            ip_addr.s_addr += inc;
        }

        make_ofp_hello(&b);
        ((struct ofp_header *)b)->type = OFPT_BARRIER_REQUEST;
        oflops_send_of_mesg(ctx, b);
        free(b);
        oflops_gettimeofday(ctx, &flow_mod_timestamp);
        oflops_log(flow_mod_timestamp, GENERIC_MSG, "END_FLOW_MOD");
        stored_flow_mod_time = 1;
        printf("sending flow modifications ....\n");

    } else if(strcmp(str, SNMPGET) == 0) {
        /*for(i = 0; i < ctx->cpuOID_count; i++) {*/
        /*oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);*/
        /*}*/
        /*for(i=0;i<ctx->n_channels;i++) {*/
        /*oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);*/
        /*oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);*/
        /*}*/
        // oflops_gettimeofday(ctx, &now);
        /*gettimeofday(&now, NULL);*/
        /*add_time(&now, 120, 0);*/
        /*oflops_schedule_timer_event(ctx,&now, SNMPGET);*/
    }
    return 0;
}

/**
 * \ingroup openflow_mod_flow
 * Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap * @param buflen length of buffer
 */
int
get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc,
        char * filter, int buflen) {
    if (ofc == OFLOPS_CONTROL) {
        return 0;
        //return snprintf(filter, buflen, "port %d",  ctx->listen_port);
    } else if ((ofc == OFLOPS_DATA1) /* ||(ofc == OFLOPS_DATA2)||(ofc == OFLOPS_DATA3) */) {
        return snprintf(filter, buflen, "udp");
    }
    return 0;
}

/**
 * \ingroup openflow_mod_flow
 * Handle event on data plane
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int
handle_pcap_event(oflops_context *ctx, struct pcap_event * pe, enum oflops_channel_name ch) {
    struct pktgen_hdr *pktgen;
    struct flow fl;
    struct timeval now;
    struct entry *n1;
    char msg[1024];
    struct in_addr in;

    if ((ch == OFLOPS_DATA1) || (ch == OFLOPS_DATA2) || (ch == OFLOPS_DATA3)) {
        if((pktgen = extract_pktgen_pkt(ctx, ch, pe->data, pe->pcaphdr.caplen, &fl)) == NULL) {
            printf("Failed to parse packet\n");
            return 0;
        }

        if ((flow_mod_timestamp.tv_sec > 0) &&  (ch == OFLOPS_DATA1)) {
            int id = ntohl(fl.nw_dst) - ntohl(inet_addr(network));
            if ((id >= 0) && (id < flows) && (!ip_received[id])) {
                ip_received_count++;
                ip_received[id] = 1;
                in.s_addr = fl.nw_dst;
                printf("FLOW_INSERTED:%s\n", inet_ntoa(in));
                snprintf(msg, 1024, "FLOW_INSERTED:%s", inet_ntoa(in));
                oflops_log(pe->pcaphdr.ts, GENERIC_MSG, msg);
                if (ip_received_count >= flows) {
                    printf("Received all packets to channel 2\n");
                    snprintf(msg, 1024, "COMPLETE_INSERT_DELAY:%u", time_diff(&flow_mod_timestamp, &pe->pcaphdr.ts));
                    printf("%s\n", msg);
                    oflops_log(pe->pcaphdr.ts, GENERIC_MSG, msg);
                    oflops_log(pe->pcaphdr.ts, GENERIC_MSG, "LAST_PKT_RCV");
                    oflops_gettimeofday(ctx, &now);
                    add_time(&now, 0, 10);
                    oflops_schedule_timer_event(ctx, 0, 10, SNMPGET);
                    add_time(&now, 10, 0);
                    oflops_schedule_timer_event(ctx, 10, 0, BYESTR);
                }
            }
        }
        if(pktgen->seq_num % 10000 == 0)
            printf("data packet received %d port %d\n", pktgen->seq_num, ch);

        n1 = malloc(sizeof(struct entry));
        n1->snd.tv_sec = pktgen->tv_sec;
        n1->snd.tv_usec = pktgen->tv_usec;
        memcpy(&n1->rcv, &pe->pcaphdr.ts, sizeof(struct timeval));
        n1->id = pktgen->seq_num;
        n1->ch = ch;
        n1->dst_ip = fl.nw_dst;
        count[ch - 1]++;
        TAILQ_INSERT_TAIL(&head, n1, entries);
    }
    return 0;
}

/**
 * \ingroup openflow_mod_flow
 * Record barrier reply message timestamp and openflow message.
 * \param ctx context of the module
 * \param ofph data of the openflow message
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
        case OFPT_BARRIER_REPLY:
            oflops_log(now, GENERIC_MSG, "BARRIRER_REPLY");
            snprintf(msg, 1024, "BARRIER_DELAY:%d", time_diff(&now, &flow_mod_timestamp));
            oflops_log(now, GENERIC_MSG, msg);
            printf("BARRIER_DELAY:%d\n",  time_diff(&now, &flow_mod_timestamp));
            break;
    }
    return 0;
}

/**
 * \ingroup openflow_mod_flow
 * printf packet in events.
 * \param ctx context of the module
 * \param pkt_in data of the pkt_in message
 */
int
of_event_packet_in(oflops_context *ctx, const struct ofp_packet_in * pkt_in) {
    switch(pkt_in->reason) {
        case  OFPR_NO_MATCH:
            /*   printf("OFPR_NO_MATCH: %d bytes\n", ntohs(pkt_in->total_len)); */
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
 * \ingroup openflow_mod_flow
 * reply to openflow requests so that the control channel will not close.
 * \param ctx context data of the module.
 * \param ofph data of the openflow echo request message.
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
 * \ingroup openflow_mod_flow
 * log information from snmp replies
 * \param ctx data of the context of the module
 * \param se the snmp reply of the message
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
                snprintf(log, len, "port:rx:%ld:%d:%d",
                        se->pdu->reqid,
                        (int)(int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], (uint32_t)*(vars->val.integer));
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
 * \ingroup openflow_mod_flow
 * start generation of 2 measrument probe(constant and variable)
 * \param ctx data of the context of the module.
 */
int
handle_traffic_generation (oflops_context *ctx) {
    struct traf_gen_det det;
    struct in_addr ip_addr;

    init_traf_gen(ctx);

    //background data
    strcpy(det.src_ip,"10.1.1.1");
    strcpy(det.dst_ip_min,"192.168.2.0");

    ip_addr.s_addr = ntohl(inet_addr("192.168.2.0"));
    //if(table == 1)
    //  ip_addr.s_addr += ((flows-1) << 8);
    //else
    ip_addr.s_addr += (flows-1);
    ip_addr.s_addr = htonl(ip_addr.s_addr);
    //str_ip = inet_ntoa(ip_addr);
    strcpy(det.dst_ip_max,  inet_ntoa(ip_addr));
    if(ctx->trafficGen == PKTGEN)
        strcpy(det.mac_src,"00:00:00:00:00:00"); //"00:1e:68:9a:c5:74");
    else
        snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)data_mac[0], (unsigned char)data_mac[1],
                (unsigned char)data_mac[2], (unsigned char)data_mac[3],
                (unsigned char)data_mac[4], (unsigned char)data_mac[5]);

    strcpy(det.mac_dst_base, "00:15:17:7b:92:0a");
	det.mac_dst_count = 1;
    det.vlan = 0xffff;
    det.vlan_p = 0;
    det.vlan_cfi = 0;
    det.udp_src_port = 8080;
    det.udp_dst_port = 8080;
    det.pkt_size = pkt_size;
    det.delay = data_snd_interval*1000;
    strcpy(det.flags, "");
    add_traffic_generator(ctx, OFLOPS_DATA2, &det);

    start_traffic_generator(ctx);
    return 1;
}

/**
 * \ingroup openflow_mod_flow
 * Initialization code of the module parameter.
 * \param ctx data of the context of the module.
 * \param config_str the initiliazation string of the module.
 */
int init(oflops_context *ctx, char * config_str) {
    char *pos = NULL;
    char *param = config_str;
    char *value = NULL;
    struct timeval now;

    //init counters
    finished = 0;

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
                if((proberate <= 0) || (proberate >= 10010))
                    perror_and_exit("Invalid probe rate param(Value between 1 and 10010)", 1);
            }  else if(strcmp(param, "data_rate") == 0) {
                //parse int to get measurement probe rate
                datarate = strtol(value, NULL, 0);
                if((datarate <= 0) || (datarate >= 10010))
                    perror_and_exit("Invalid data rate param(Value between 1 and 10010)", 1);
            } else if(strcmp(param, "table") == 0) {
                //parse int to get pkt size
                table = strtol(value, NULL, 0);
                if((table < 0) && (table > 2))
                    perror_and_exit("Invalid table number", 1);

                printf("XXXXXXXXXXXXX reading table = %dXXXXXXXXXX", table);
            } else if(strcmp(param, "flows") == 0) {
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
    data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (datarate * mbits_to_bits);
    fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n",
            (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
    return 0;
}
