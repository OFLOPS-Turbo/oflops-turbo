#include <string.h>

#include "module_default.h"
#include "pcap_track.h"

// Set of default operations for modules; just NOOPs except for OFLOPS_CONTROL which we keep timestamps for

int default_module_init(oflops_context *ctx, char * init)
{
    return 0;
}


int default_module_destroy(oflops_context *ctx)
{
    return 0;
}

int default_module_get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc, cap_filter **filter)
{
    if(ofc == OFLOPS_CONTROL)       // only pcap dump the control channel

        /*********************
         * Stolen from man pcap(3):
         *      To print all IPv4 HTTP packets to and from port
         *      80, i.e. print only packets that contain data,
         *      not,  for  example,  SYN  and  FIN packets and ACK-only packets.
         **/
//		bzero(filter, sizeof(cap_filter));
		return 0;
//        return snprintf(filter,buflen,"tcp port %d"  		// port openflow
//                " and (((ip[2:2] - ((ip[0]&0xf)<<2)) - "// ip.tot_len - ip header len *4
//                " ((tcp[12]&0xf0)>>2)) != 0)", 		// - tcp header len *4
//                ctx->listen_port);
    else
        return 0;
}


int default_module_start(oflops_context * ctx) {
    return 0;
}


int default_module_handle_pcap_event(oflops_context *ctx, struct pcap_event * pe, enum oflops_channel_name ch)
{
    return 0;
    if( ch != OFLOPS_CONTROL)
        return 0;
    if(!ctx->channels[OFLOPS_CONTROL].timestamps)
        ctx->channels[OFLOPS_CONTROL].timestamps = ptrack_new();
    // add this packet to the list of timestamps
    return ptrack_add_of_entry(ctx->channels[OFLOPS_CONTROL].timestamps, pe->data, pe->pcaphdr.caplen, pe->pcaphdr);
}



int default_module_of_event_packet_in(oflops_context *ctx, const struct ofp_packet_in * pktin)
{
    return 0;
}



int default_module_of_event_flow_removed(oflops_context *ctx, const struct ofp_flow_removed * ofph)
{
    return 0;
}

int default_module_of_event_echo_request(oflops_context *ctx, const struct ofp_header * ofph)
{
    struct ofp_header resp;
    memcpy(&resp,ofph,sizeof(resp));
    resp.type = OFPT_ECHO_REPLY;
    oflops_send_of_mesg(ctx, &resp);
    return 0;
}


int default_module_of_event_port_status(oflops_context * ctx, const struct ofp_port_status * ofph)
{
    return 0;
}
int default_module_of_event_other(oflops_context * ctx, const struct ofp_header * ofph)
{
    return 0;
}
int default_module_handle_timer_event(oflops_context * ctx, struct timer_event * te)
{
    return 0;
}
int default_module_handle_snmp_event(oflops_context * ctx, struct snmp_event * se)
{
    return 0;
}
int default_module_handle_traffic_generation(oflops_context * ctx)
{
    return 0;
}
