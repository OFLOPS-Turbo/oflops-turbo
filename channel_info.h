#ifndef CHANNEL_INFO_H
#define CHANNEL_INFO_H

struct channel_info;
#include <pcap.h>

#include "context.h"
#include "test_module.h"
#include "pcap_track.h"
#include "msgbuf.h"
#include "nf_pktgen.h"

/**
 * \brief State for a specific control or data channel.
 */

typedef struct channel_info {
    char * dev;                     /**< The name of the local interface of a channel */
    pcap_t * pcap_handle;           /**< A pcap object to capture traffic. Initialized only a module defines appropriately a non length zero field */
    int pcap_fd;                    /**< A non blocking file descriptor from the pcap library. It allows to select over multiple channels */
    int raw_sock;                   /**< A raw socket that allows an application inject crafted packets */
    int sock;                       /**< A descriptor for the TCP socket of the control channel. */
    int ifindex;                    /**< The index of the interface of the channel. */
    int of_port;                    /**< The port number on which the channel is attached on the switch */
    int packet_len;                 /**< length of packet for equally chunked data transfer (0: don't chunk) */
    struct ptrack_list * timestamps;
    struct msgbuf * outgoing;
    struct traf_gen_det *det;       /**< a description of the artificial traffic generated on the channel (valid only for data channels). */
    struct pcap_dump_t *dump;       /**< the structure that store the stores the state of the file, on which we dump pcap data(used only by the control channel) */
    oid inOID[MAX_OID_LEN];         /**< SNMP oid of the output counter of the port on which the channel is attached on the switch */
    size_t inOID_len;               /**< length of the output OID structure */
    oid outOID[MAX_OID_LEN];        /**< SNMP oid of the output counter of the port on which the channel is attached on the switch */
    size_t outOID_len;
    int cap_type;
    struct nf_cap_t *nf_cap;

} channel_info;

int channel_info_init(struct channel_info * channel, char * dev);
void setup_channel(struct oflops_context *ctx, 
        struct test_module *mod, enum oflops_channel_name ch);

#endif
