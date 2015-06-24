#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>
#include <math.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>
#include <gsl/gsl_sort.h>

#include "of_parser.h"
#include "log.h"
#include "traffic_generator.h"
#include "utils.h"
#ifndef BUFLEN
#define BUFLEN 4096
#endif

/** String for scheduling events
*/
#define BYESTR "bye bye"
#define GETSTAT "getstat"
#define SNMPGET "snmp get"

/** packet size constants
*/
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

#define TEST_DURATION 60
// don't query for less than a millisecond, as the measurement will not be accurate
#define MIN_QUERY_DELAY 1000

#define SEC_TO_USEC 1000000

#define LOG_FILE "measure.log"

/**
 * \defgroup openflow_aggr_flow_stats openflow aagregate flow stats
 *  \ingroup modules
 *  \brief Openflow aggr stats flow benchmark.
 *
 * A module to measure the scalabitily and performance of the aggr flow stat
 * mechanism of an openflow implementation.
 *
 * Parameter:
 *   - flows: The total number of unique flow that the module will
 * initialize the flow table of the switch. (default 128)
 *   - query: The number of unique flows that the module will query the
 *   switch in each flow request. Because the matching method of the module is based
 * on the netmask field of the matching field. (default 128)
 *   - pkt_size:  This parameter can be used to control the length of the
 *   packets of the measurement probe. It allows indirectly to adjust the packet
 *   throughput of the experiment.
 *   - data_rate: The rate, in Mbps, of the variable probe. (default
 *       10Mbps)
 *   - probe_rate: The rate, in Mbps, of the constant probe. (default 10Mbps)
 *   - query_delay: The delay, in microseconds, between the different
 * stats requests. (default 10000 usec)
 *   - print: A parameter that defines whether the module will output full
 *   per packet details of the measurement probes. If this value is set to 1, then
 *   the module will print on a file called "measure.log" for each capture packet a
 *   comma separated record with the timestamps of the generation and capture times of the
 *   packet, the packet id, the port at which the packet was captured and the flow id
 * of the flow that was used in order to switch the packet. (default 0)
 *   - table: This parameter controls whether the inserted flow will be
 * a wildcard(value of 1) or exact match(value of 0). (default 0)
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 *
 */

/*
 * flow and packet generation details.
 */
int flows = 128;
int flows_exponent, query_exponent;
int query = 64;
int poll_started = 0;
char *network = "192.168.2.0";
const uint64_t sec_to_usec = 1000000; //Some constants to help me with conversions
const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;
uint64_t pkt_size = 1500;
int query_delay = 1000000; //1 sec
uint64_t data_snd_interval;
uint64_t probe_snd_interval;

uint64_t datarate = 100;
uint64_t proberate = 100;

int table = 0;

// experiment internal state
int finished;
int trans_id=0;
int print = 0;
struct timeval stats_start;

char *logfile = LOG_FILE;

// a structure to store measurement probe informations.
struct entry {
    struct timeval snd,rcv;
    uint32_t nw_dst;
    int ch, id;
    TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};
TAILQ_HEAD(tailhead, entry) head;

// a structure to store information regarding statistics
struct stats_entry {
    struct timeval snd, rcv;
    int id;
} stats_counter[(TEST_DURATION * SEC_TO_USEC)/MIN_QUERY_DELAY];
int stats_count = 0;

// control whether detailed packet information is printed
int count[] = {0,0,0}; // counting how many packets where received over a
// specific channel
//the local mac address of the probe
char probe_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

/**
 * @ingroup openflow_aggr_flow_stats
 * get the module name.
 * @return name of module
 */
char * name()
{
    return "openflow_aggr_flow_stats";
}

/**
 * \ingroup openflow_aggr_flow_stats
 * Initialization code of the module parameter.
 * \param ctx data of the context of the module.
 * \param config_str the initiliazation string of the module.
 */
int init(oflops_context *ctx, char * config_str) {
    char *pos = NULL;
    char *param = config_str;
    char *value = NULL;
    double exponent;

    //init measurement queue
    TAILQ_INIT(&head);

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
            if(strcmp(param, "flows") == 0) {
                flows = atoi(value);
                if(flows <= 0)
                    perror_and_exit("Invalid flow number",1);
            } else if(strcmp(param, "query") == 0) {
                query = atoi(value);
                if(query <= 0)
                    perror_and_exit("Invalid flow number",1);

                exponent = log2(query);
                if(exponent - floor(exponent) != 0) {
                    printf("query=%d, exponent=%f, floor exponent:%f\n", query, exponent, floor(exponent));
                    query = (int)pow(2, ceil(exponent));
                    printf("query size must be a power of 2. converting to %d\n", query);
                }

            } else if(strcmp(param, "network") == 0) {
                network = (char *)xmalloc(strlen(value) + 1);
                strcpy(network, value);
            } else if(strcmp(param, "pkt_size") == 0) {
                //parse int to get pkt size
                pkt_size = strtol(value, NULL, 0);
                if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))  {
                    perror_and_exit("Invalid packet size value", 1);
                }
            } else if(strcmp(param, "data_rate") == 0) {
                //parse int to get pkt size
                datarate = strtol(value, NULL, 0);
                if((datarate <= 0) || (datarate > 1010))  {
                    perror_and_exit("Invalid data rate param(Values between 1 and 1010)", 1);
                }
            } else if(strcmp(param, "probe_rate") == 0) {
                //parse int to get pkt size
                proberate = strtol(value, NULL, 0);
                if((proberate <= 0) || (proberate >= 1010)) {
                    perror_and_exit("Invalid probe rate param(Value between 1 and 1010)", 1);
                }
            } else if(strcmp(param, "query_delay") == 0) {
                query_delay = strtol(value, NULL, 0);
                if(query_delay <= MIN_QUERY_DELAY) {
                    perror_and_exit("Invalid probe rate param(Value between 1 and 1010)", 1);
                }
                printf("query delay %d\n", query_delay);
                //should packet timestamp be printed
            } else if(strcmp(param, "table") == 0) {
                //parse int to get pkt size
                table = strtol(value, NULL, 0);
            }else if(strcmp(param, "print") == 0) {
                //parse int to get pkt size
                print = strtol(value, NULL, 0);
            } else {
                fprintf(stderr, "Invalid parameter:%s\n", param);
            }
            param = pos;
        }
    }

    //calculating interpacket gap
    data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (datarate * mbits_to_bits);
    fprintf(stderr, "Sending data interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n",
            (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
    probe_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (proberate * mbits_to_bits);
    fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n",
            (uint32_t)probe_snd_interval, (uint32_t)pkt_size, (uint32_t)proberate);

    return 0;
}

/**
 * \ingroup openflow_aggr_flow_stats
 * Calculate and log the probe and stats mechanism performance statistics.
 * \param ctx the data of the context of the module.
 */
int destroy(oflops_context *ctx) {
    char msg[1024];
    struct timeval now;
    FILE *out = fopen(logfile, "w");
    struct entry *np;
    uint32_t mean, median, std;
    int min_id[] = {INT_MAX, INT_MAX, INT_MAX};
    int max_id[] = {INT_MIN, INT_MIN, INT_MIN};
    int ix[] = {0, 0, 0};
    int ch, i;
    float loss;
    double **data;
    struct in_addr in;

    gettimeofday(&now, NULL);
    fprintf(stderr, "This is the destroy code of the module\n");

    printf("%d %d %d\n", count[0], count[1], count[2]);

    data = (double **)malloc(3*sizeof(double*));
    for(ch = 0; ch < 3; ch++)
        if(count[ch])
            data[ch] = (double *)malloc(count[ch] * sizeof(double));
        else
            data[ch] = NULL;

    for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
        if((np->ch > OFLOPS_DATA3) || ((np->ch < OFLOPS_DATA1))){
            printf("Invalid channel %d. skipping packet\n", np->ch);
            continue;
        }
        ch = np->ch - 1;
        if(print) {
            in.s_addr = np->nw_dst;
            if(fprintf(out, "%lu %lu.%06lu %lu.%06lu %d %s\n",
                        (long unsigned int)np->id,
                        (long unsigned int)np->snd.tv_sec,
                        (long unsigned int)np->snd.tv_usec,
                        (long unsigned int)np->rcv.tv_sec,
                        (long unsigned int)np->rcv.tv_usec,
                        np->ch, inet_ntoa(in)) < 0)
                perror_and_exit("fprintf fail", 1);
        }
        if( time_cmp(&np->snd, &np->rcv)> 0) {
            ix[ch]++;
            min_id[ch] = (np->id < min_id[ch])?np->id:min_id[ch];
            max_id[ch] = (np->id > max_id[ch])?np->id:max_id[ch];
            data[ch][ix[ch]] = (double) time_diff(&np->snd, &np->rcv);
        }
        free(np);
    }

    for(ch = 0; ch < 3; ch++) {
        if(ix[ch] == 0) continue;
        gsl_sort (data[ch], 1, ix[ch]);
        mean = (uint32_t)gsl_stats_mean(data[ch], 1, ix[ch]);
        std = (uint32_t)sqrt(gsl_stats_variance(data[ch], 1, ix[ch]));
        median = (uint32_t)gsl_stats_median_from_sorted_data (data[ch], 1, ix[ch]);
        loss = (float)ix[ch]/(float)(max_id[ch] - min_id[ch]);
        snprintf(msg, 1024, "statistics:port:%d:%u:%u:%u:%.4f:%d",
                ch, mean, median, std, loss, ix[ch]);
        printf("%s\n", msg);
        oflops_log(now, GENERIC_MSG, msg);

    }

    ix[0] = 0;
    min_id[0] =  INT_MAX;
    max_id[0] =  INT_MIN;
    free(data[0]);
    data[0] = (double *)malloc(sizeof(double)*(stats_count));

    for (i = 0; i < trans_id; i++) {

        if(((stats_counter[i].rcv.tv_sec == 0) &&
                    (stats_counter[i].rcv.tv_usec == 0)) ||
                (ix[0] >=  stats_count)) continue;

        data[0][ix[0] - 1]  = (double) time_diff(&stats_counter[i].snd, &stats_counter[i].rcv);
        ix[0]++;
        snprintf(msg, 1024, "stats:%u:%u.%06u:%u.%06u:%u",i,
                (uint32_t)stats_counter[i].snd.tv_sec,
                (uint32_t)stats_counter[i].snd.tv_usec,
                (uint32_t)stats_counter[i].rcv.tv_sec,
                (uint32_t)stats_counter[i].rcv.tv_usec,
                (uint32_t)time_diff(&stats_counter[i].snd,
                    &stats_counter[i].rcv));
        printf("%s\n", msg);
        oflops_log(now, GENERIC_MSG, msg);
    }

    ix[0]--; //we have added 1 on the last round which we have to remove
    if(ix[0] > 0) {
        gsl_sort (data[0], 1, ix[0]);
        mean = (uint32_t)gsl_stats_mean(data[0], 1, ix[0]);
        std = (uint32_t)sqrt(gsl_stats_variance(data[0], 1, ix[0]));
        median = (uint32_t)gsl_stats_median_from_sorted_data (data[0], 1, ix[0]);
        loss = (float)ix[0]/(float)(max_id[0] - min_id[0]);
        snprintf(msg, 1024, "statistics:stats:%u:%u:%u:%.4f:%d",
                mean, median, std, loss, ix[0]);
        printf("%s\n", msg);
        oflops_log(now, GENERIC_MSG, msg);
    } else {
        oflops_log(now, GENERIC_MSG, "stats_stats:fail");
    }
    return 0;
}

/**
 * \ingroup openflow_aggr_flow_stats
 * Init module data, insert required flows and schedule basic module events.
 * \param ctx pointer to opaque context
 */
int start(oflops_context * ctx)
{
    int res = -1, i, len = 0;
    struct timeval now;
    struct in_addr ip_addr;
    struct flow *fl = (struct flow*)xmalloc(sizeof(struct flow));

    // a genric structure with which
    // we can create and send messages.
    void *b;

    msg_init();

    //make filedescriptor blocking
    int saved_flags = fcntl(ctx->control_fd, F_GETFL);
    fcntl(ctx->control_fd, F_SETFL, saved_flags & ~O_NONBLOCK);

    get_mac_address(ctx->channels[OFLOPS_DATA1].dev, data_mac);
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ctx->channels[OFLOPS_DATA1].dev,
            (unsigned char)data_mac[0], (unsigned char)data_mac[1],
            (unsigned char)data_mac[2], (unsigned char)data_mac[3],
            (unsigned char)data_mac[4], (unsigned char)data_mac[5]);

    get_mac_address(ctx->channels[OFLOPS_DATA2].dev, probe_mac);
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ctx->channels[OFLOPS_DATA2].dev,
            (unsigned char)probe_mac[0], (unsigned char)probe_mac[1],
            (unsigned char)probe_mac[2], (unsigned char)probe_mac[3],
            (unsigned char)probe_mac[4], (unsigned char)probe_mac[5]);

    gettimeofday(&now, NULL);
    oflops_log(now,GENERIC_MSG , "Intializing module openflow_flow_dump_test");

    make_ofp_hello(&b);
    res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
    free(b);

    sleep(1);

    // send a features request, to stave off timeout (ignore response)
    printf("cleaning up flow table...\n");
    res = make_ofp_flow_del(&b);
    res = oflops_send_of_mesgs(ctx, b, res);
    free(b);

    //Send a singe rule to route the traffic we will generate
    bzero(fl, sizeof(struct flow));
    if (table)
        fl->mask =  OFPFW_IN_PORT | OFPFW_DL_DST | OFPFW_DL_SRC |
            (0 << OFPFW_NW_SRC_SHIFT) | (0 << OFPFW_NW_DST_SHIFT) |
            OFPFW_DL_VLAN | OFPFW_TP_DST | OFPFW_NW_PROTO |
            OFPFW_TP_SRC | OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS;
    else
        fl->mask = 0;
    fl->in_port = htons(ctx->channels[OFLOPS_DATA2].of_port);
    fl->dl_type = htons(ETHERTYPE_IP);
    memcpy(fl->dl_src, probe_mac, ETH_ALEN);
    memcpy(fl->dl_dst, "\x00\x15\x17\x7b\x92\x0a", ETH_ALEN);
    fl->dl_vlan = 0xffff;
    fl->nw_proto = IPPROTO_UDP;
    fl->nw_src =  inet_addr("10.1.1.1");
    fl->nw_dst =  inet_addr("10.1.1.2");
    fl->tp_src = htons(8080);
    fl->tp_dst = htons(8080);
    len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA3].of_port, 1, 1200);
    res = oflops_send_of_mesgs(ctx, b, len);
    free(b);

    printf("Sending new flow rules...\n");
    ip_addr.s_addr = inet_addr(network);
    ip_addr.s_addr =  ntohl(ip_addr.s_addr);
    fl->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
    fl->dl_vlan = 0xffff;
    memcpy(fl->dl_src, data_mac, ETH_ALEN);
    memcpy(fl->dl_dst, "\x00\x1e\x68\x9a\xc5\x75", ETH_ALEN);
    fl->mask = 0;
    for(i=0; i< flows; i++) {
        ip_addr.s_addr += 1;
        fl->nw_dst =  htonl(ip_addr.s_addr);

        len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA2].of_port, 1, 1200);
        res = oflops_send_of_mesg(ctx, b);
        free(b);
    }

    //Schedule end
    oflops_schedule_timer_event(ctx, TEST_DURATION, 0, BYESTR);

    //the event to request the flow statistics.
    oflops_schedule_timer_event(ctx, 1, 0, GETSTAT);

    //get port and cpu status from switch
    oflops_schedule_timer_event(ctx, 1, 0, SNMPGET);

    flows_exponent = (int)floor(log2(flows));
    query_exponent = (int)log2(query);

    return 0;
}

/**
 * \ingroup openflow_aggr_flow_stats
 * Handle module timer event:
 *
 * - GETSTAT: send aggr flow stats request
 * - BYESTR: terminate module
 * - SNMPGET: snmp request
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(oflops_context * ctx, struct timer_event *te)
{
    int i;
    void *b = NULL;
    char *str = te->arg;
    uint32_t flow_netmask;
    //send flow statistics request.
    if(strcmp(str, GETSTAT) == 0) {

        if(trans_id == 0) {
            printf("flow stats request send with xid %d\n", trans_id);
            memcpy(&stats_start, &te->sched_time, sizeof(struct timeval));
            poll_started = 1;
        }

        oflops_gettimeofday(ctx, &stats_counter[trans_id].snd);
        bzero(&stats_counter[trans_id].rcv, sizeof(struct timeval));

        make_ofp_aggr_flow_stats(&b, trans_id++);
        struct ofp_aggregate_stats_request *reqp = (struct ofp_aggregate_stats_request *)
            (b + sizeof(struct ofp_stats_request));

        reqp->match.wildcards = htonl(OFPFW_IN_PORT | OFPFW_DL_VLAN |  OFPFW_DL_SRC |
                OFPFW_DL_DST |  OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_TP_SRC |
                OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS | OFPFW_TP_DST |
                (32 << OFPFW_NW_SRC_SHIFT) | ((query_exponent) << OFPFW_NW_DST_SHIFT));

        //calculate netowrk mask for the query
        flow_netmask = (ntohl(inet_addr(network)) & ((0xFFFFFFFF)<<flows_exponent));
        if(query_exponent < flows_exponent)
            flow_netmask += (stats_count%(0x1 <<(flows_exponent-query_exponent))
                    << query_exponent);

        reqp->match.nw_dst = htonl(flow_netmask);

        oflops_send_of_mesg(ctx, b);
        free(b);

        //schedule next query
        oflops_schedule_timer_event(ctx, query_delay/SEC_TO_USEC, 
				query_delay%SEC_TO_USEC, GETSTAT);
        //terminate programm execution
    } else if (strcmp(str, BYESTR) == 0) {
        printf("terminating test....\n");
        oflops_end_test(ctx,1);
    } else if(strcmp(str, SNMPGET) == 0) {
        for(i=0;i<ctx->cpuOID_count;i++) {
            oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);
        }
        for(i=0;i<ctx->n_channels;i++) {
            oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);
            oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);
        }
        oflops_schedule_timer_event(ctx, 10, 0, SNMPGET);
    }
    return 0;
}

/**
 * \ingroup openflow_aggr_flow_stats
 * a method to log apropriate snmp replies
 * \param ctx data context of the module
 * \param se the data of the snmmp reply
 */
int
handle_snmp_event(oflops_context * ctx, struct snmp_event * se) {
    netsnmp_variable_list *vars;
    int i, len = 1024;
    char msg[1024], log[1024];
    struct timeval now;

    for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {
        snprint_value(msg, len, vars->name, vars->name_length, vars);

        for (i = 0; i < ctx->cpuOID_count; i++) {
            if((vars->name_length == ctx->cpuOID_len[i]) &&
                    (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
                snprintf(log, len, "cpu : %s %%", msg);
                oflops_log(now, SNMP_MSG, log);
            }
        }

        for(i=0;i<ctx->n_channels;i++) {
            if((vars->name_length == ctx->channels[i].inOID_len) &&
                    (memcmp(vars->name, ctx->channels[i].inOID,
                            ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
                snprintf(log, len, "port %d : rx %s pkts",
                        (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1],
                        msg);
                oflops_log(now, SNMP_MSG, log);
                break;
            }

            if((vars->name_length == ctx->channels[i].outOID_len) &&
                    (memcmp(vars->name, ctx->channels[i].outOID,
                            ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
                snprintf(log, len, "port %d : tx %s pkts",
                        (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
                oflops_log(now, SNMP_MSG, log);
                break;
            }
        } //for
    }// if cpu
    return 0;
}

/**
 * \ingroup openflow_aggr_flow_stats
 * Register pcap filter for channel 2 and 3
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap
 * @param buflen length of buffer
 */
int get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc, char * filter, int buflen)
{
    if(ofc == OFLOPS_CONTROL) {
        return 0;
        return snprintf(filter,buflen,"port %d", ctx->listen_port);
    } else if ( (ofc == OFLOPS_DATA3) || (ofc == OFLOPS_DATA2)) {
        return snprintf(filter,buflen,"udp");
        return 0;
    }
    return 0;
}

/**
 * \ingroup openflow_aggr_flow_stats
 * Handle pcap event on data channel.
 * @param ctx data of the context of the program
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int handle_pcap_event(oflops_context *ctx, struct pcap_event *pe,
        enum oflops_channel_name ch) {
    struct flow fl;
    struct pktgen_hdr *pktgen;

    if ( (ch == OFLOPS_DATA3) || (ch == OFLOPS_DATA2)){
        if(!poll_started) return 0;
        pktgen = extract_pktgen_pkt(ctx, ch, (unsigned char *)pe->data, pe->pcaphdr.caplen, &fl);
        if(pktgen == NULL) //skip non IP packets
            return 0;

        struct entry *n1 = malloc(sizeof(struct entry));
        n1->snd.tv_sec = pktgen->tv_sec;
        n1->snd.tv_usec = pktgen->tv_usec;
        memcpy(&n1->rcv, &pe->pcaphdr.ts, sizeof(struct timeval));
        n1->id = htonl(pktgen->seq_num);
        n1->ch = ch;
        count[ch - 1]++;
        n1->nw_dst = fl.nw_dst;
        TAILQ_INSERT_TAIL(&head, n1, entries);
    }
    return 0;
}

/**
 * \ingroup openflow_aggr_flow_stats
 * setup two measurement probes (random and constant)
 * \param data of the context of the module
 */
int
handle_traffic_generation (oflops_context *ctx) {
    struct traf_gen_det det;
    char *str_ip;
    struct in_addr ip;
    init_traf_gen(ctx);

    //background data
    strcpy(det.src_ip,"10.1.1.1");
    strcpy(det.dst_ip_min,"192.168.2.1");

    ip.s_addr = ntohl(inet_addr("192.168.2.1"));
    ip.s_addr += (flows - 1);
    ip.s_addr = htonl(ip.s_addr);
    str_ip = inet_ntoa(ip);
    strcpy(det.dst_ip_max, str_ip);
    if(ctx->trafficGen == PKTGEN)
        strcpy(det.mac_src,"00:00:00:00:00:00");
    else
        snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)data_mac[0], (unsigned char)data_mac[1],
                (unsigned char)data_mac[2], (unsigned char)data_mac[3],
                (unsigned char)data_mac[4], (unsigned char)data_mac[5]);
    strcpy(det.mac_dst_base, "00:1e:68:9a:c5:75");
	det.mac_dst_count = 1;
    det.vlan = 0xffff;
    det.vlan_p = 1;
    det.vlan_cfi = 0;
    det.udp_src_port = 8080;
    det.udp_dst_port = 8080;
    det.pkt_size = pkt_size;
    det.delay = data_snd_interval*1000;
    strcpy(det.flags, "IPDST_RND");
    add_traffic_generator(ctx, OFLOPS_DATA1, &det);

    //measurement probe
    strcpy(det.dst_ip_min,"10.1.1.2");
    strcpy(det.dst_ip_max,"10.1.1.2");
    if(ctx->trafficGen == PKTGEN)
        strcpy(det.mac_src,"00:00:00:00:00:00");
    else
        snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)probe_mac[0], (unsigned char)probe_mac[1],
                (unsigned char)probe_mac[2], (unsigned char)probe_mac[3],
                (unsigned char)probe_mac[4], (unsigned char)probe_mac[5]);
    strcpy(det.mac_dst_base, "00:15:17:7b:92:0a");
	det.mac_dst_count = 1;
    det.vlan = 0xffff;
    det.delay = probe_snd_interval*1000;
    strcpy(det.flags, "");
    add_traffic_generator(ctx, OFLOPS_DATA2, &det);
    start_traffic_generator(ctx);
    return 1;
}

/**
 * \ingroup openflow_aggr_flow_stats
 *  A method that log aggr flow stats replies and error messages.
 * \param ctx data of the context of the moudle
 * \param ofph openflow packet data pointer
 */
int
of_event_other(oflops_context *ctx, const struct ofp_header * ofph) {
    struct timeval now;
    char msg[100];
    struct ofp_error_msg *err_p;

    if(ofph->type == OFPT_STATS_REPLY) {
        struct ofp_stats_reply *ofpr = (struct ofp_stats_reply *)ofph;
        if(ntohs(ofpr->type) == OFPST_AGGREGATE) {
            sprintf(msg, "%d", ntohl(ofph->xid));
            gettimeofday(&now, NULL);
            oflops_log(now, OFPT_STATS_REPLY_FLOW, msg);
            if((ntohs(ofpr->flags) & OFPSF_REPLY_MORE) == 0) {
                oflops_gettimeofday(ctx, &stats_counter[ntohl(ofph->xid)].rcv);
                stats_count++;
            }
        }
    } else if (ofph->type == OFPT_ERROR) {
        err_p = (struct ofp_error_msg *)ofph;
        sprintf(msg, "OFPT_ERROR(type: %d, code: %d)", ntohs(err_p->type), ntohs(err_p->code));
        fprintf(stderr, "%s\n", msg);
        perror_and_exit(msg, 1);
    }
    return 0;
}
