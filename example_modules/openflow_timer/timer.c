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
 * \defgroup openflow_timer openflow timer test
 * \ingroup modules
 * A module to benchamrk the accuracy of the timers of the switch
 *
 * Paramters:
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
 * Copyright (C) t-labs, 2010
 * \author crotsos
 * \date June, 2010
 *
 */

/**
 * \ingroup openflow_timer
 * \return name of module
 */
char * name() {
    return "openflow_timer";
}

/**
 * String for scheduling events
 */
#define BYESTR "bye bye"
#define SNMPGET "snmp get"
#define SND_FLOW "send flow"

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
uint64_t datarate = 100;
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
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

int *ip_received;
int ip_received_count;


struct timeval *first, *last;
double *delay;

/**
 * \ingroup openflow_timer
 * Initialization
 * \param ctx pointer to opaque context
 */
int
start(oflops_context * ctx) {
    struct flow *fl = (struct flow*)xmalloc(sizeof(struct flow));
    void *b; //somewhere to store message data
    struct timeval now;
    char msg[1024];

    //Initialize pap-based  tcp flow reassembler for the communication
    //channel
    msg_init();
    snprintf(msg, 1024,  "Intializing module %s", name());

    get_mac_address(ctx->channels[OFLOPS_DATA1].dev, data_mac);
    first = (struct timeval *)xmalloc(flows*sizeof(struct timeval));
    memset(first, '\0', flows*sizeof(struct timeval));
    last = (struct timeval *)xmalloc(flows*sizeof(struct timeval));
    memset(last, '\0', flows*sizeof(struct timeval));
    delay = (double*)xmalloc(flows*sizeof(double));
    memset(last, '\0', flows*sizeof(double));


    //log when I start module
    gettimeofday(&now, NULL);
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
     * Send flow records to start routing packets.
     */
    printf("Sending measurement probe flow...\n");
    bzero(fl, sizeof(struct flow));

    fl->mask = OFPFW_ALL;
    make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA2].of_port, 1, 120);
    ((struct ofp_flow_mod *)b)->priority = htons(0);
    ((struct ofp_flow_mod *)b)->flags = 0;
    oflops_send_of_mesg(ctx, b);
    free(b);

    ip_received = xmalloc(flows*sizeof(int));
    memset(ip_received, 0, flows*sizeof(int));

    /**
     * Shceduling events
     */
    //get port and cpu status from switch
    gettimeofday(&now, NULL);
    add_time(&now, 1, 0);
    oflops_schedule_timer_event(ctx,&now, SND_FLOW);

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
 * \ingroup openflow_timer
 */
int
destroy(oflops_context *ctx) {
    int i;
    char data[1024];
    struct in_addr addr;

    for(i = 0; i< flows; i++) {
        addr.s_addr =  ntohl(htonl(inet_addr(network)) + i);
        if(first[i].tv_sec > 0) {
            snprintf(data, 1024, "flow_timeout:%s:%lu.%06lu:%lu.%06lu:%u:%f", inet_ntoa(addr),
                    first[i].tv_sec, first[i].tv_usec, last[i].tv_sec, last[i].tv_usec,
                    time_diff(&first[i], &last[i]), delay[i]);
            printf("%s\n", data);
            oflops_log(last[i],GENERIC_MSG , data);

        }
    }

    return 0;
}

/**
 * \ingroup openflow_timer
 * Handle timer event
 * \param ctx pointer to opaque context
 * \param te pointer to timer event
 */
int handle_timer_event(oflops_context * ctx, struct timer_event *te) {
    char *str = te->arg;
    int i;
    struct timeval now;
    struct flow *fl = (struct flow*)xmalloc(sizeof(struct flow));
    void *b; //somewhere to store message data
    int len;

    //terminate process
    if (strcmp(str, BYESTR) == 0) {
        printf("terminating test....\n");
        oflops_end_test(ctx,1);
        return 0;
    } else if (strcmp(str, SND_FLOW) == 0) {
        if(table == 0)
            fl->mask = 0; //if table is 0 the we generate an exact match */
        else
            fl->mask =  OFPFW_IN_PORT | OFPFW_DL_DST | OFPFW_DL_SRC |
                (0 << OFPFW_NW_SRC_SHIFT) | (0 << OFPFW_NW_DST_SHIFT) |
                OFPFW_DL_VLAN | OFPFW_TP_DST | OFPFW_NW_PROTO |
                OFPFW_TP_SRC | OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS;

        fl->dl_type = htons(ETHERTYPE_IP);
        fl->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
        memcpy(fl->dl_src, data_mac, 6);
        memcpy(fl->dl_dst, "\x00\x15\x17\x7b\x92\x0a", 6);
        fl->dl_vlan = htons(0xffff);
        fl->nw_proto = IPPROTO_UDP;
        fl->nw_src =  inet_addr("10.1.1.1");
        fl->nw_dst =  inet_addr(network);
        fl->tp_src = htons(8080);
        fl->tp_dst = htons(8080);

        for(i = 0; i < flows; i++) {
            len = make_ofp_flow_add(&b, fl, OFPP_IN_PORT, 1, 10);
            ((struct ofp_flow_mod *)b)->priority = htons(10);
            ((struct ofp_flow_mod *)b)->flags = htons(OFPFF_SEND_FLOW_REM);
            ((struct ofp_flow_mod *)b)->idle_timeout = OFP_FLOW_PERMANENT;
            ((struct ofp_flow_mod *)b)->hard_timeout = htons(10);
            oflops_send_of_mesgs(ctx, b, len);
            free(b);
            fl->nw_dst =  ntohl(htonl(fl->nw_dst) + 1);
        }
    }else if(strcmp(str, SNMPGET) == 0) {
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
 * \ingroup openflow_timer
 * Register pcap filter.
 * \param ctx pointer to opaque context
 * \param ofc enumeration of channel that filter is being asked for
 * \param filter filter string for pcap * \param buflen length of buffer
 */
int
get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc,
        char * filter, int buflen) {
    //if ((ofc == OFLOPS_DATA1) || (ofc == OFLOPS_DATA2) || (ofc == OFLOPS_DATA3)) {
    if(ofc == OFLOPS_DATA1){
        return snprintf(filter, buflen, "udp");
    }
    return 0;
}

/**
 * \ingroup openflow_timer
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
 * \ingroup openflow_timer
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
    ip_addr.s_addr += (flows-1);
    ip_addr.s_addr = htonl(ip_addr.s_addr);
    strcpy(det.dst_ip_max,  inet_ntoa(ip_addr));
    if(ctx->trafficGen == PKTGEN)
        strcpy(det.mac_src,"00:00:00:00:00:00"); //"00:1e:68:9a:c5:74");
    else
        snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)data_mac[0], (unsigned char)data_mac[1],
                (unsigned char)data_mac[2], (unsigned char)data_mac[3],
                (unsigned char)data_mac[4], (unsigned char)data_mac[5]);

    strcpy(det.mac_dst,"00:15:17:7b:92:0a");
    det.vlan = 100;
    det.vlan_p = 0;
    det.vlan_cfi = 0;
    det.udp_src_port = 8080;
    det.udp_dst_port = 8080;
    det.pkt_size = pkt_size;
    det.delay = data_snd_interval*1000;
    strcpy(det.flags, "");
    add_traffic_generator(ctx, OFLOPS_DATA1, &det);

    start_traffic_generator(ctx);
    return 1;
}

int count = 0;
/**
 * \ingroup openflow_timer
 * log flow removal events in order to quantify the accuracy of the counter
 */
int
of_event_flow_removed(oflops_context *ctx, const struct ofp_flow_removed * ofph) {
    struct timeval now;
    struct in_addr addr;

    int id = ntohl(ofph->match.nw_dst) - ntohl(inet_addr(network));
    if((id < 0) || (id >= flows)) {
        addr.s_addr = ofph->match.nw_dst;
        printf("Invalid ip %s\n", inet_ntoa(addr));
        return 0;
    }
    delay[id] = ntohl(ofph->duration_sec)*1000000 +
        (float)ntohl(ofph->duration_nsec)/1000;
    count++;
    if(count>=flows) {
        //end process
        gettimeofday(&now, NULL);
        add_time(&now, 5, 0);
        oflops_schedule_timer_event(ctx,&now, BYESTR);
        return 0;
    }
    return 0;
}

/**
 * \ingroup openflow_timer
 * Handle pcap event.
 * \param ctx pointer to opaque context
 * \param pe pcap event
 * \param ch enumeration of channel that pcap event is triggered
 */
int handle_pcap_event(oflops_context *ctx, struct pcap_event *pe,
        enum oflops_channel_name ch) {
    struct flow fl;
    struct pktgen_hdr *pkt;
    if (ch == OFLOPS_DATA1) {
        pkt = extract_pktgen_pkt(ctx, ch, (unsigned char *)pe->data,
                pe->pcaphdr.caplen, &fl);
        if(pkt == NULL) { //skip non IP packets
            return 0;
        }
        //if(pkt->seq_num%1000 == 0)
        //printf("packet received on port %d\n", pkt->seq_num);
        int id = ntohl(fl.nw_dst) - ntohl(inet_addr(network));
        if(first[id].tv_sec == 0) {
            memcpy(&first[id], &pe->pcaphdr.ts, sizeof(struct timeval));
        }
        memcpy(&last[id], &pe->pcaphdr.ts, sizeof(struct timeval));
    }
    return 0;
}

/**
 * \ingroup openflow_timer
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
 * \ingroup openflow_timer
 * Initialization code with parameters
 * \param ctx
 */
int init(oflops_context *ctx, char * config_str) {
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
    data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (datarate * mbits_to_bits);
    fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n",
            (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
    return 0;
}
