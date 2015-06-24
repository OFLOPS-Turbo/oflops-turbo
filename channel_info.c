#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <nf_pktgen.h>

#include "channel_info.h"
#include "utils.h"
#include "msgbuf.h"
#include "oflops_pcap.h"

int channel_info_init(struct channel_info * channel, const char * dev)
{
    struct ifreq ifr;
    int dumb;
    char *tmp;
    bzero(channel, sizeof(channel_info));

    if((tmp = index(dev, ':')) != NULL) {
        *tmp = '\0';
        tmp++;
        channel->of_port = atoi(tmp);
    } else {
        channel->of_port = -1;
    }

    channel->inOID_len = MAX_OID_LEN;
    channel->outOID_len = MAX_OID_LEN;
    channel->dev = strdup(dev);
    channel->pcap_fd = -1;
    channel->raw_sock = -1;
    channel->sock = -1;
    channel->dump = NULL;
    channel->cap_type = PCAP;
    /* Not sure why I need a socket to do this */
    dumb = socket(AF_INET, SOCK_STREAM, 0);
    /*retrieve ethernet interface index*/
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if(ioctl(dumb, SIOCGIFINDEX, &ifr) == -1)
        perror_and_exit("SIOCGIFINDEX", 1);

    channel->ifindex = ifr.ifr_ifindex;
    channel->packet_len = 0;
    channel->outgoing = msgbuf_new(4096);   // will get resized
    channel->det = NULL;
    close(dumb);
    return 0;
}

char *
ip2str(char *ret, uint32_t ip) {
	sprintf(ret, "%d.%d.%d.%d", 
			(ip & 0xFF000000) > 24, (ip & 0xFF0000) > 16,
			(ip & 0xFF00) > 8, (ip & 0xFF));
	return ret;
}

void 
cap_filter_to_pcap(cap_filter f, char *buf, int len) {
	int c = 0;
	char ret[20];
	if(f.proto) 
		c += snprintf(buf + c, len, "proto %d ", f.proto);
	if (f.src) 
		c += snprintf(buf + c, len, "src host %s ", ip2str(ret, f.src));
	if (f.src_mask) 
		c += snprintf(buf + c, len, "src net %s ", ip2str(ret, f.src_mask));	
	if (f.dst) 
		c += snprintf(buf + c, len, "dst host %s ", ip2str(ret, f.dst));
	if (f.dst_mask) 
		c += snprintf(buf + c, len, "dst net %s ", ip2str(ret, f.dst_mask));
	if(f.port) 
		c += snprintf(buf + c, len, "port %d ", f.port);
}

/****************************************************
 * query module if they want pcap and set it up for them if yes
 * also create a raw_socket bound to each device if we have the
 * device set
 */
void 
setup_channel(oflops_context *ctx, test_module *mod, enum oflops_channel_name ch)
{
    char buf[BUFLEN];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
	cap_filter *f;
	int count = 0, ix;
    bpf_u_int32 mask = 0, net = 0;
    channel_info *ch_info = &ctx->channels[ch];
	static int filter_count = 0;

    if(ch_info->dev == NULL) { // no device specified
        ch_info->dev = pcap_lookupdev(errbuf);
        fprintf(stderr, "%s channel %i not configured; guessing device: ",
                ((ch == OFLOPS_CONTROL) ? "Control" : "Data"), ch);

        if(ch_info->dev)
            fprintf(stderr, "%s", ch_info->dev);
        else {
            fprintf(stderr, " pcap_lookup() failed: %s ; exiting....\n", errbuf);
            exit(1);
        }
    }

    // setup pcap filter, if wanted
    if( (count = mod->get_pcap_filter(ctx, ch, &f)) <= 0) {
        fprintf(stderr, "Test %s:  No pcap filter for channel %d on %s\n",
                mod->name(), ch, ch_info->dev);
        ch_info->pcap_handle = NULL;
        return;
    }

    assert(ch_info->dev);       // need to have someting here

	cap_filter_to_pcap(f[0], buf, BUFLEN);
    fprintf(stderr, "Test %s:  Starting pcap filter \"%s\" on dev %s for channel %d\n",
            mod->name(), buf, ch_info->dev, ch);
    errbuf[0] = 0;

    // for the case of the control channel we always use the pcap capturing library.
    if((ch == OFLOPS_CONTROL) || (ch_info->cap_type == PCAP)) {
        //for the data channel use capture len param to define the cpatured packet length
        if(ch != OFLOPS_CONTROL) {
            ch_info->pcap_handle = pcap_open_live(ch_info->dev, ctx->snaplen, 1,  0, errbuf);
        } else {
            ch_info->pcap_handle = pcap_open_live(ch_info->dev, 65000, 1, 0, errbuf);

            //based on the control channel capture param, open a pcap dump file named by default controller.pcap
            if(ctx->dump_controller) {
                ch_info->dump = pcap_dump_open(ch_info->pcap_handle, "controller.pcap");

                if(ch_info->dump == NULL) {
                    perror_and_exit(pcap_geterr(ch_info->pcap_handle), 1);
                }
            } else {
                ch_info->dump = NULL;
            }
        }

        if(!ch_info->pcap_handle) {
            fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
            exit(1);
        }

        if(strlen(errbuf) > 0)
            fprintf(stderr, "Non-fatal pcap warning: %s\n", errbuf);

        if((pcap_lookupnet(ch_info->dev, &net, &mask, errbuf) == -1) &&
                (ch == OFLOPS_CONTROL)) {   // only control has an IP
            fprintf(stderr, "WARN: pcap_lookupnet: %s; ", errbuf);
            fprintf(stderr, "filter rules might fail\n");
        }

        //setup pcap filter
        bzero(&filter, sizeof(filter));

        if(pcap_compile(ch_info->pcap_handle, &filter, buf, 1, net)) {
            fprintf(stderr, "pcap_compile: %s\n", errbuf);
            exit(1);
        }

        if(strlen(errbuf) > 0)
            fprintf(stderr, "Non-fatal pcap_setfilter: %s\n", errbuf);

        if(pcap_setfilter(ch_info->pcap_handle, &filter) == -1) {
            fprintf(stderr, "pcap_setfilter: %s\n", errbuf);
            exit(1);
        }

        //extract a file descriptor for the pcap handler and make it non blocking
        //so that we can `select` it later
        if(pcap_setnonblock(ch_info->pcap_handle, 1, errbuf))
            fprintf(stderr, "setup_channel: pcap_setnonblock(): %s\n", errbuf);

        ch_info->pcap_fd = pcap_get_selectable_fd(ch_info->pcap_handle);
        //else open the nf packet gen capturer
    } else  if(ch_info->cap_type == NF2) {
        ch_info->nf_cap = nf_cap_enable(ch_info->dev, ctx->snaplen);
        ch_info->pcap_fd = nf_cap_fileno(ch_info->nf_cap);

		for (ix = 0; ix < count; ix++) {
			cap_filter_to_pcap(f[ix], buf, BUFLEN);
			printf("Enabling rule \"%s\"\n", buf);
			nf_cap_add_rule(filter_count++, f[ix].proto, f[ix].src, f[ix].dst, 
					f[ix].port, f[ix].proto_mask, f[ix].src_mask, f[ix].dst_mask, 
					f[ix].port_mask);
		}

//        printf("nf2 capture on %s (sock:%d)\n", ch_info->dev , ch_info->pcap_fd);
    } else {
        perror_and_exit("Invalid capture type", 1);
    }
}

/**
 * custom objoid parsing method, because the default library implementation segfaulted
 * \param in_oid a string representation of the oid
 * \param out_oid an oid pointer to save the oid obect
 * \param oid_len a pointer reference to return the length of the oid object
 */
void my_read_objid(char *in_oid, oid *out_oid, size_t *out_oid_len)
{
    int oid_len = *out_oid_len, p = 0, tmp = 0, len = strlen(in_oid);
    *(out_oid_len) = 0;

    while(1) {
        tmp = p;

        while((in_oid[tmp] != '.') &&
                (in_oid[tmp] != '\0')) {
            tmp++;
        }

        in_oid[tmp] = '\0';
        tmp++;
        out_oid[*(out_oid_len)] = (oid)strtol(in_oid + p, NULL, 10);

        if(oid_len == *out_oid_len) return;

        *(out_oid_len) += 1;
        p = tmp;

        if(p >= len)
            break;
    }
}

/****************************************************
 * query module if they want pcap and set it up for them if yes
 * also create a raw_socket bound to each device if we have the
 * device set
 */
void setup_channel_snmp(oflops_context *ctx, enum oflops_channel_name ch,
                        char *in_oid, char *out_oid)
{
    if(in_oid == NULL)
        ctx->channels[ch].inOID_len = 0;
    else {
        ctx->channels[ch].inOID_len = MAX_OID_LEN;
        my_read_objid(in_oid, ctx->channels[ch].inOID, &ctx->channels[ch].inOID_len);
        //comment this one because the snmp implementation was giving segaults
        /* if(read_objid(in_oid, ctx->channels[ch].inOID, &ctx->channels[ch].inOID_len) == 0) { */
        /*   printf("inOID: %s(%d)\n", in_oid,  ctx->channels[OFLOPS_CONTROL].inOID_len); */
        /*   snmp_perror("ack"); */
        /*   perror_and_exit("read_objid failed", 1);   */
        /* } */
    }

    if(out_oid == NULL)
        ctx->channels[ch].outOID_len = 0;
    else {
        ctx->channels[ch].outOID_len = MAX_OID_LEN;
        my_read_objid(out_oid, ctx->channels[ch].outOID, &ctx->channels[ch].outOID_len);
        //comment this one because the snmp implementation was giving segaults
        /* if(read_objid(out_oid, ctx->channels[ch].outOID, &ctx->channels[ch].outOID_len) == 0) */
        /*   perror_and_exit("read_objid failed", 1);     */
    }
}
