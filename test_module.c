#include <assert.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#ifndef TEST_MODULE_H
#define TEST_MODULE_H

#include <openflow/openflow.h>
#include "oflops_snmp.h"
#include "oflops_pcap.h"
#include "timer_event.h"

#include "msgbuf.h"
#include "channel_info.h"

/**  New test_module should implement these call backs.
 * Unimplemeted callbacks fall back to a default behavior.
 */

typedef struct test_module
{
    /** Return the name of the module
     *
     * DEFAULT: NONE! must be defined
     *
     * @return str returned is static; don't free()
     */
    const char * (*name)(void);

    /** \brief Initialize module with the config string
     *
     * DEFAULT: NONE! must be defined
     *
     * @param ctx opaque context
     * @param config_str string of parameters to pass to module
     * @return 0 if success, -1 if fatal error
     */
    int (*init)(oflops_context *ctx, char * config_str);


    /** \brief Code to be run after the completion of the
     *   execution of a module
     *
     * DEFAULT: NONE! must be defined
     *
     * @param ctx opaque context
     * @return 0 if success, -1 if fatal error
     */
    int (*destroy)(oflops_context *ctx);

    /** \brief Ask module what pcap_filter it wants for this channel
     *
     * DEFAULT: return zero --> don't send pcap events on this channel
     *
     * @param ofc      The oflops channel (data or control) to filter on filter
     * @param filter   A tcpdump-style pcap filter string, suitable for pcap_set_filter()
     *          This string is already allocated.
     * @param buflen   The max length of the filter string
     * @return The length of the filter string: zero implies "do not listen on this channel"
     */
    int (*get_pcap_filter)(oflops_context *ctx, enum oflops_channel_name ofc, char * filter, int buflen);

    /** \brief Tell the module it's time to start its test
     * 	pass raw sockets for send and recv channels
     * 	if the module wants direct access to them
     *
     * DEFAULT: NOOP
     *
     * @param ctx opaque context
     *
     * @return 0 if success or -1 on error
     */
    int (*start)(oflops_context * ctx);

    /** \brief Tell the test module that pcap found a packet on
     * 	a certain channel
     *
     * DEFAULT: ignore pcap events on this channel
     *
     * 	if this module does not want pcap events, return NULL
     * 	for get_pcap_filter()
     *
     * @param ctx   opaque context
     * @param pe    structure holding packet and pcap timestamp
     * @param ch    which channel this packet arrived on
     * @return 0    if success or -1 on error
     */
    int (*handle_pcap_event)(oflops_context *ctx, struct pcap_event * pe, enum oflops_channel_name ch);

    /** \brief Tell the test module that an openflow mesg came
     * 	over the control channel
     *
     * DEFAULT: ignore this type of openflow message
     *
     * @param ctx   opaque context
     * @param ofph  a pointer to an openflow message; do not free()
     * @return 0 if success or -1 on error
     */
    int (*of_event_packet_in)(oflops_context *ctx, const struct ofp_packet_in * ofph);
    int (*of_event_flow_removed)(oflops_context *ctx, const struct ofp_flow_removed * ofph);

    // FIXME: KK says this should be vector of all openflow messages
    int (*of_event_echo_request)(oflops_context *ctx, const struct ofp_header * ofph);
    int (*of_event_port_status)(oflops_context *ctx, const struct ofp_port_status * ofph);
    int (*of_event_other)(oflops_context *ctx, const struct ofp_header * ofph);

    /** \brief Tell the test module that a timer went off
     *
     * DEFAULT: ignore timer events
     *
     * @param ctx   opaque context
     * @param te    a structure holding relevant timer info
     * @return      0 if success or -1 on error
     */
    int (*handle_timer_event)(oflops_context * ctx, struct timer_event * te);
    void * symbol_handle;

    /** \brief Tell the test module that a SNMP reply is received.
     *
     * DEFAULT: Ignore SNMP replies
     *
     * @param ctx opqaue context
     * @param se struct to handle SNMP reply
     * @return 0 if success and -1 if error
     */
    int (*handle_snmp_event)(oflops_context * ctx, struct snmp_event * se);

    /** \brief run the packet generator module
     *
     * DEFAULT: No packet generation
     *
     * @param ctx opqaue context
     * @return 0 if success and -1 if error
     */
    int (*handle_traffic_generation)(oflops_context * ctx);

} test_module;

// List of interfaces exposed from oflops to test_modules

/** Send a buffer of openflow messages from the module to the switch along the control channel
 * @param ctx	opaque pointer
 * @param buf	pointer to an openflow header message (already in network byte order)
 * @param buflen    length of the buffer
 */
size_t oflops_send_of_mesgs(oflops_context *ctx, char * buf, size_t buflen);

/** Send an openflow message from the module to the switch along the control channel
 * @param ctx	opaque pointer
 * @param hdr	pointer to an openflow header message (already in network byte order)
 */
int oflops_send_of_mesg(oflops_context *ctx, struct ofp_header * hdr);

/** Send an raw message to the switch out a specified channel
 * @param ctx	opaque pointer
 * @param ch  	Oflops channel to send the message out
 * @param msg	pointer to mesg including link layer headers
 * @param len	length of msg
 * @return number of bytes written; -1 if error (same as write(2))
 */
int oflops_send_raw_mesg(oflops_context *ctx, enum oflops_channel_name ch, void * msg, int len);

/** Get a file descriptor for the specified channel
 * returns an fd of a UDP socket bound to the device bound to the specified channel
 * @param ctx	opaque pointer
 * @param ch  	Oflops channel
 * @return	file descriptor
 */
int oflops_get_channel_fd(oflops_context *ctx, enum oflops_channel_name ch);

/** Get a file descriptor for the specified channel
 * returns an fd of a *raw* socket bound to the device bound to the specified channel
 * @param ctx	opaque pointer
 * @param ch  	Oflops channel
 * @return	file descriptor
 */
int oflops_get_channel_raw_fd(oflops_context *ctx, enum oflops_channel_name ch);

/** Schedule a time event; arg is passed back to the test_module when the event occurs
 * @param ctx	opaque pointer
 * @param tv	a pointer to the absolute time the event should happen
 * @param arg	a parameter to pass to the event
 * @return a unique ID for the event (if test wants to cancel it) or -1 on error
 */
int oflops_schedule_timer_event(oflops_context *ctx, struct timeval *tv, void * arg);
// FIXME: expose cancel timmer

/** Lookup the timestamp for this chunk of data
 * If the specified channel was setup to be tracked via ptrack (pcap_track.h), then
 * it should be possible to map this blob of data to the libpcap timestamp when it came in
 * ptrack_add_* can be used to track openflow messages, tcp messages, etc.
 * @param ctx	opaque pointer
 * @param data 	the data to lookup
 * @param len	length of the data
 * @param hdr	pointer to a pcap header; this will be filled in if the data is matched
 * @return 	zero if not found (*hdr unchanged); >zero implies *hdr is valid and actual
 * number indicates how far oflops had to search
 */
int oflops_get_timestamp(oflops_context * ctx, void * data, int len, struct pcap_pkthdr * hdr,
        enum oflops_channel_name ofc);

/** Send SNMP get with oid
 * @param ctx opaque pointer
 * @param query oid to request
 * @param len length of oid
 * @return 0 if success and 1 if session fails
 */
int oflops_snmp_get(oflops_context * ctx, oid query[], size_t len);

/** Tell the harness this test is over
 * @param ctx	i		opaque pointer
 * @param should_continue	flag for if this test had a fatal error and the oflops suite should stop processing other tests
 * @return zero (always for now)
 */
int oflops_end_test(oflops_context *ctx, int should_continue);

#endif
#include "test_module.h"
#include "utils.h"

/*****************************************************************************
 * hook for the test module to send an openflow mesg across the control channel
 *     to the switch
 *     FIXME: assert()'s that the message doesn't block -- if this is a problem
 *     we need to implement some buffering and mod the select() call to open for
 *     writing
 **/
int oflops_send_of_mesg(oflops_context *ctx, struct ofp_header * ofph)
{
    int len = ntohs(ofph->length);
    msgbuf_push(ctx->control_outgoing, (void *) ofph, len);
    return len;
}

/*****************************************************************************
 * hook for the test module to send an openflow mesgs across the control channel
 *     to the switch
 *     FIXME: assert()'s that the message doesn't block -- if this is a problem
 *     we need to implement some buffering and mod the select() call to open for
 *     writing
 **/
size_t oflops_send_of_mesgs(oflops_context *ctx, char * buf, size_t buflen)
{
       msgbuf_push(ctx->control_outgoing, buf, buflen);
    return buflen;
}

/***********************************************************************
 * hook for the test module to signal that the test is done
 **/

int oflops_end_test(oflops_context *ctx,int should_continue)
{
    ctx->should_end = 1;
    // ctx->should_continue = should_continue;
    ev_break(ctx->io_loop, EVBREAK_ALL);
    ev_break(ctx->timer_loop, EVBREAK_ALL);
    ev_break(ctx->data_loop, EVBREAK_ALL);
    return 0;
}

/**********************************************************************
 * hook for the test module to get access to a raw file descriptor bound
 * 	to the data channel's device
 **/

int oflops_get_channel_raw_fd(oflops_context * ctx, enum oflops_channel_name ch)
{
    struct ifreq ifr;
    struct sockaddr_ll saddrll;
    struct channel_info * ch_info;
    if(ch >= ctx->n_channels)
        return -1;	// no such channel
    ch_info = &ctx->channels[ch];
    if(ch_info->raw_sock != -1)	// already allocated?
        return ch_info->raw_sock;
    // else, setup raw socket
    ch_info->raw_sock = socket(AF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
    if( ch_info->raw_sock == -1)
        perror_and_exit("raw socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL))",1);
    // bind to a specific port
    strncpy(ifr.ifr_name,ch_info->dev,IFNAMSIZ);
    if( ioctl( ch_info->raw_sock, SIOCGIFINDEX, &ifr)  == -1 )
        perror_and_exit("ioctl()",1);
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = AF_PACKET;
    saddrll.sll_protocol = ETH_P_ALL;
    saddrll.sll_ifindex = ifr.ifr_ifindex;
    if ( bind(ch_info->raw_sock, (struct sockaddr *) &saddrll, sizeof(struct sockaddr_ll)) == -1 )
        perror_and_exit("bind()",1);
    return ch_info->raw_sock;
}

/**********************************************************************
 * hook for the test module to get access to a udp file descriptor bound
 * 	to the data channel's device
 **/
int oflops_get_channel_fd(oflops_context * ctx, enum oflops_channel_name ch)
{
    struct ifreq ifr;
    struct channel_info * ch_info;
    if(ch >= ctx->n_channels)
        return -1;	// no such channel
    ch_info = &ctx->channels[ch];
    if(ch_info->sock != -1)	// already allocated?
        return ch_info->sock;
    // else, setup raw socket
    ch_info->sock = socket(AF_INET,SOCK_DGRAM,0);	// UDP socket
    if( ch_info->sock == -1)
        perror_and_exit("udp socket(AF_INET,SOCK_DGRAM,0)",1);
    // bind to a specific port
    strncpy(ifr.ifr_name,ch_info->dev,IFNAMSIZ);
    if( ioctl( ch_info->sock, SIOCGIFINDEX, &ifr)  == -1 )
        perror_and_exit("ioctl() bind to dev",1);
    return ch_info->sock;
}

/***************************************************************************
 * hook for the test module to schedule an timer_event to be called back into the module
 **/

int oflops_schedule_timer_event(oflops_context *ctx, struct timeval *tv, void * arg)
{
    return wc_event_ev_add(ctx, NULL, arg, *tv);
}

/********************************************************************************
 * hook for the test module to send a raw message out a certain data channel
 * 	here, "raw" means with ethernet header
 **/

int oflops_send_raw_mesg(oflops_context *ctx, enum oflops_channel_name ch, void * msg, int len)
{
    struct sockaddr_ll socket_address;
    int ret;
    oflops_get_channel_raw_fd(ctx,ch);  // ensure that a raw sock is allocated

    ctx->channels[ch].packet_len = len;

    bzero(&socket_address,sizeof(socket_address));
    socket_address.sll_family   = PF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    /*index of the network device
     *          * see full code later how to retrieve it*/
    socket_address.sll_ifindex  = ctx->channels[ch].ifindex;
    /********************* do we need any of this? */
    socket_address.sll_hatype   = ARPHRD_ETHER; //don't need?
    socket_address.sll_halen    = ETH_ALEN;
    socket_address.sll_pkttype  = PACKET_OTHERHOST;
    //*/

    /*queue the packet*/

    // FIXME: not dure if this correnct, as I am not sending anymore data
    // to the data channels from user space
    ret = write( ctx->channels[ch].raw_sock, msg, len);
    //msgbuf_push(ctx->channels[ch].outgoing, msg, len);
    //send_result = sendto(sock, msg, len, 0,  ***** old code
    //		     (struct sockaddr*)&socket_address, sizeof(socket_address));
    //	sendto(ctx->channels[ch].raw_sock, msg, len, 0,
    //(struct sockaddr*)&socket_address, sizeof(socket_address));
    if ( ret < 0 && errno != ENOBUFS ) {
        fprintf(stderr, "sending of data failed\n");
    }

    return len;;
}

int oflops_snmp_get(oflops_context * ctx, oid query[], size_t len)
{
    struct snmp_channel* ch = ctx->snmp_channel_info;
    struct snmp_session* sess;

    //Open session for async request
    if(!(sess = snmp_open(&(ch->session))))
    {
        snmp_perror("snmp_open");
        return 1;
    }

    //Build and send packet
    if (ch->req != NULL)
        snmp_free_pdu(ch->req);
    ch->req = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(ch->req, query, len);
    if (!snmp_send(sess, ch->req))
        snmp_perror("snmp_send");

    return 0;
}

