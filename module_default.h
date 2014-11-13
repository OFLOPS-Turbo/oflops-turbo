#ifndef MODULE_DEFAULT_H
#define MODULE_DEFAULT_H

#include <openflow/openflow.h>

#include "context.h"
#include "oflops_snmp.h"
#include "channel_info.h"

/** @defgroup modules
 *
 * Modules for different oflops runs.
 */

// Set of default operations for modules

/**
 * Default code to execute for the init phase of the module.
 * \param ctx module context.
 * \param param a string with the configurtion params
 */
int default_module_init(oflops_context *ctx, char *param);

/**
 * A default function to be called when a a module is destroyed.
 * \param ctx module context.
 */
int default_module_destroy(oflops_context *ctx);

/**
 * a method to be called when a pcap filter is request for a speciic module.
 * \param ct module context.
 * \param ofc channel type
 * \param filter a string to store the filter.
 * \param buflien maximum sze of the string buffer.
 */
int default_module_get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc,
    cap_filter **filter);

/**
* A method exectued when a module start running (pre-test flow step, etc.).
* \param ctx the context of the module
*/
int default_module_start(oflops_context * ctx);

/**
* A default method to be called when a pcap packet is pushed to the module.
* \param pe a struct to stoe pcap data.
* \param ch the id of the channel from which we received the packet.
*/
int default_module_handle_pcap_event(oflops_context *ctx, struct pcap_event * pe, enum oflops_channel_name ch);

/**
*  Adefault method to be callen when a packet in event cocurs.
* \param ctx muodule context
*\param  pktin a method to sterw tre :w

*/
int default_module_of_event_packet_in(oflops_context *ctx, const struct ofp_packet_in * pktin);

int default_module_of_event_flow_removed(oflops_context *ctx, const struct ofp_flow_removed * ofph);

int default_module_of_event_echo_request(oflops_context *ctx, const struct ofp_header * ofph);
int default_module_of_event_port_status(oflops_context *ctx, const struct ofp_port_status * ofph);
int default_module_of_event_other(oflops_context *ctx, const struct ofp_header * ofph);
int default_module_handle_timer_event(oflops_context * ctx, struct timer_event * te);
int default_module_handle_snmp_event(oflops_context * ctx, struct snmp_event * se);
int default_module_handle_traffic_generation(oflops_context * ctx);

#endif
