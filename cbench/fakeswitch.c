#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openflow/openflow.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <net/ethernet.h>

#include <netinet/in.h>

#include "cbench.h"
#include "fakeswitch.h"

static int debug_msg(struct fakeswitch * fs, char * msg, ...);
static int make_features_reply(int switch_id, int xid, char * buf, int buflen);
static int make_vendor_reply(int xid, char * buf, int buflen);
static int make_packet_in(int switch_id, int buffer_id, char * buf, int buflen, int mac_address);
static void fakeswitch_handle_write(struct fakeswitch *fs);

static inline uint64_t htonll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

static inline uint64_t ntohll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) ntohl(n) << 32) | ntohl(n >> 32);
}

void fakeswitch_init(struct fakeswitch *fs, int sock, int bufsize, int debug, int delay, enum test_mode mode, int total_mac_addresses)
{
    static int ID =1 ;
    char buf[BUFLEN];
    struct ofp_header ofph;
    fs->sock = sock;
    fs->debug = debug;
    fs->id = ID++;
    fs->inbuf = msgbuf_new(bufsize);
    fs->outbuf = msgbuf_new(bufsize);
    fs->probe_state = 0;
    fs->mode = mode;
    fs->probe_size = make_packet_in(fs->id, 0, buf, BUFLEN, fs->current_mac_address++);
    fs->count = 0;
    fs->ready_to_send = 0;
    fs->delay = delay;
    fs->total_mac_addresses = total_mac_addresses;
    fs->current_mac_address = 0;

    ofph.version = OFP_VERSION;
    ofph.type = OFPT_HELLO;
    ofph.length = htons(sizeof(ofph));
    ofph.xid   = htonl(1);

    // Send HELLO
    msgbuf_push(fs->outbuf,(char * ) &ofph, sizeof(ofph));
    debug_msg(fs, " sent hello");
}

/***********************************************************************/

void fakeswitch_set_pollfd(struct fakeswitch *fs, struct pollfd *pfd)
{
    pfd->events = POLLIN|POLLOUT;
    /* if(msgbuf_count_buffered(fs->outbuf) > 0)
        pfd->events |= POLLOUT; */
    pfd->fd = fs->sock;
}

/***********************************************************************/

int fakeswitch_get_count(struct fakeswitch *fs)
{
    int ret = fs->count;
    int err;
    fs->count = 0;
    fs->probe_state = 0;        // reset packet state
    // keep reading until there is nothing to clear out the queue
    while( (err = msgbuf_read(fs->inbuf,fs->sock)) > 0);
    // now flush the queue; we ignore these responses b/c we're out
    // of the timing portion of the test
    msgbuf_clear(fs->inbuf);
    msgbuf_clear(fs->outbuf);
    return ret;
}

/***********************************************************************/
static int              make_features_reply(int id, int xid, char * buf, int buflen)
{
    struct ofp_switch_features * features;
    const char fake[] =     // stolen from wireshark
    {
        0x97,0x06,0x00,0xe0,0x04,0x01,0x00,0x00,0x00,0x00,0x76,0xa9,
        0xd4,0x0d,0x25,0x48,0x00,0x00,0x01,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x1f,
        0x00,0x00,0x03,0xff,0x00,0x00,0x1a,0xc1,0x51,0xff,0xef,0x8a,0x76,0x65,0x74,0x68,
        0x31,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x01,0xce,0x2f,0xa2,0x87,0xf6,0x70,0x76,0x65,0x74,0x68,
        0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x02,0xca,0x8a,0x1e,0xf3,0x77,0xef,0x76,0x65,0x74,0x68,
        0x35,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x03,0xfa,0xbc,0x77,0x8d,0x7e,0x0b,0x76,0x65,0x74,0x68,
        0x37,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };

    assert(buflen> sizeof(fake));
    memcpy(buf, fake, sizeof(fake));
    features = (struct ofp_switch_features *) buf;
    features->header.version = OFP_VERSION;
    features->header.xid = xid;
    features->datapath_id = htonll(id);
    return sizeof(fake);
}
/***********************************************************************/
static int make_vendor_reply(int xid, char * buf, int buflen)
{
    struct ofp_error_msg * e;
    assert(buflen> sizeof(struct ofp_error_msg));
    e = (struct ofp_error_msg *) buf;
    e->header.type = OFPT_ERROR;
    e->header.version = OFP_VERSION;
    e->header.length = htons(sizeof(struct ofp_error_msg));
    e->header.xid = xid;
    e->type = htons(OFPET_BAD_REQUEST);
    e->code = htons(OFPBRC_BAD_VENDOR);
    return sizeof(struct ofp_error_msg);
}
/***********************************************************************/
static int make_packet_in(int switch_id, int buffer_id, char * buf, int buflen, int mac_address)
{
    struct ofp_packet_in * pi;
    struct ether_header * eth;
    const char fake[] = {
                0x97,0x0a,0x00,0x52,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
                0x01,0x00,0x40,0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00,
                0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x02,0x08,0x00,0x45,
                0x00,0x00,0x32,0x00,0x00,0x00,0x00,0x40,0xff,0xf7,0x2c,
                0xc0,0xa8,0x00,0x28,0xc0,0xa8,0x01,0x28,0x7a,0x18,0x58,
                0x6b,0x11,0x08,0x97,0xf5,0x19,0xe2,0x65,0x7e,0x07,0xcc,
                0x31,0xc3,0x11,0xc7,0xc4,0x0c,0x8b,0x95,0x51,0x51,0x33,
                0x54,0x51,0xd5,0x00,0x36};
    assert(buflen> sizeof(fake));
    memcpy(buf, fake, sizeof(fake));
    pi = (struct ofp_packet_in *) buf;
    pi->header.version = OFP_VERSION;
    pi->buffer_id = htonl(buffer_id);
    eth = (struct ether_header * ) pi->data;
    // copy into src mac addr; only 4 bytes, but should suffice to not confuse
    // the controller; don't overwrite first byte
    memcpy(&eth->ether_shost[1], &mac_address, sizeof(mac_address));
    // mark this as coming from us, mostly for debug
    eth->ether_dhost[5] = switch_id;
    eth->ether_shost[5] = switch_id;
    return sizeof(fake);
}
/***********************************************************************/
void fakeswitch_handle_read(struct fakeswitch *fs)
{
    int count;
    struct ofp_header * ofph;
    struct ofp_header echo;
    char buf[BUFLEN];
    count = msgbuf_read(fs->inbuf, fs->sock);   // read any queued data
    if (count <= 0)
    {
        fprintf(stderr, "controller msgbuf_read() = %d:  ", count);
        if(count < 0)
            perror("msgbuf_read");
        else
            fprintf(stderr, " closed connection ");
        fprintf(stderr, "... exiting\n");
        exit(1);
    }
    while((count= msgbuf_count_buffered(fs->inbuf)) >= sizeof(struct ofp_header ))
    {
        ofph = msgbuf_peek(fs->inbuf);
        if(count < ntohs(ofph->length))
            return;     // msg not all there yet
        msgbuf_pull(fs->inbuf, NULL, ntohs(ofph->length));
        switch(ofph->type)
        {
            struct ofp_flow_mod * fm;
            struct ofp_packet_out *po;
            case OFPT_PACKET_OUT:
                po = (struct ofp_packet_out *) ofph;
                // assume this is in response to what we sent
                fs->count++;        // got response to what we went
                fs->probe_state--;
                break;
            case OFPT_FLOW_MOD:
                fm = (struct ofp_flow_mod *) ofph;
                if(fm->command== htons(OFPFC_ADD) )
                {
                    fs->count++;        // got response to what we went
                    fs->probe_state--;
                }
                break;
            case OFPT_FEATURES_REQUEST:
                // pull msgs out of buffer
                debug_msg(fs, "got feature_req");
                // Send features reply
                count = make_features_reply(fs->id, ofph->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                debug_msg(fs, "sent feature_rsp");
                if( fs->delay == 0)
                    fs->ready_to_send = 1;
                else 
                {
                    fs->ready_to_send = 2;
                    gettimeofday(&fs->delay_start, NULL);
                    fs->delay_start.tv_sec += fs->delay / 1000;
                    fs->delay_start.tv_usec += (fs->delay % 1000 ) * 1000;
                    debug_msg(fs, " delaying test start %d ms", fs->delay);
                }
                break;
            case OFPT_SET_CONFIG:
                // pull msgs out of buffer
                debug_msg(fs, "got config");
                break;
            case OFPT_VENDOR:
                // pull msgs out of buffer
                debug_msg(fs, "got vendor");
                count = make_vendor_reply(ofph->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                debug_msg(fs, "sent vendor");
                // apply nox hack; nox ignores packet_in until this msg is sent
                fs->probe_state=0;
                break;
            case OFPT_HELLO:
                debug_msg(fs, "got hello");
                // we already sent our own HELLO; don't respond
                break;
            case OFPT_ECHO_REQUEST:
                debug_msg(fs, "got echo, sent echo_resp");
                echo.version= OFP_VERSION;
                echo.length = htons(sizeof(echo));
                echo.type   = OFPT_ECHO_REPLY;
                echo.xid = ofph->xid;
                msgbuf_push(fs->outbuf,(char *) &echo, sizeof(echo));
                break;
            case OFPT_STATS_REQUEST:
                debug_msg(fs, "Silently ignoring stats_request msg\n");
                break;
            default: 
    //            if(fs->debug)
                    fprintf(stderr, "Ignoring OpenFlow message type %d\n", ofph->type);
        };
        if(fs->probe_state < 0)
        {
                debug_msg(fs, "WARN: Got more responses than probes!!: : %d",
                            fs->probe_state);
                fs->probe_state =0;
        }
    }
}
/***********************************************************************/
static void fakeswitch_handle_write(struct fakeswitch *fs)
{
    static int BUFFER_ID=256;
    char buf[BUFLEN];
    int count ;
    int send_count = 0 ;
    int throughput_buffer = 65536;
    int i;
    if( fs->ready_to_send == 1) 
    {
        if ((fs->mode == MODE_LATENCY)  && ( fs->probe_state == 0 ))      
            send_count = 1;                 // just send one packet
        else if ((fs->mode == MODE_THROUGHPUT) && 
                (msgbuf_count_buffered(fs->outbuf) < throughput_buffer))  // keep buffer full
            send_count = (throughput_buffer - msgbuf_count_buffered(fs->outbuf)) / fs->probe_size;
        for (i = 0; i < send_count; i++)
        {
            // queue up packet
            if(BUFFER_ID < 256)     // prevent wrapping
                BUFFER_ID = 256;
            fs->probe_state++;
            // TODO come back and remove this copy
            count = make_packet_in(fs->id, 0, buf, BUFLEN, fs->current_mac_address);
            fs->current_mac_address = ++fs->current_mac_address % fs->total_mac_addresses;
            msgbuf_push(fs->outbuf, buf, count);
        }
    } else if( fs->ready_to_send == 2) 
    {
        struct timeval now;
        gettimeofday(&now, NULL);
        if (timercmp(&now, &fs->delay_start, > ))
        {
            fs->ready_to_send = 1;
            debug_msg(fs, " delay is over: sending probes now");
        }
    }
    // send any data if it's queued
    if( msgbuf_count_buffered(fs->outbuf) > 0)
        msgbuf_write(fs->outbuf, fs->sock, 0);
}
/***********************************************************************/
void fakeswitch_handle_io(struct fakeswitch *fs, const struct pollfd *pfd)
{
    if(pfd->revents & POLLIN)
        fakeswitch_handle_read(fs);
    if(pfd->revents & POLLOUT)
        fakeswitch_handle_write(fs);
}
/************************************************************************/
static int debug_msg(struct fakeswitch * fs, char * msg, ...)
{
    va_list aq;
    if(fs->debug == 0 )
        return 0;
    fprintf(stderr,"\n-------Switch %d: ", fs->id);
    va_start(aq,msg);
    vfprintf(stderr,msg,aq);
    if(msg[strlen(msg)-1] != '\n')
        fprintf(stderr, "\n");
    // fflush(stderr);     // should be redundant, but often isn't :-(
    return 1;
}
