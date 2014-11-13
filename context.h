#ifndef CONTEXT_H
#define CONTEXT_H

#include <pcap.h>
#include <ev.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "wc_event.h"

enum oflops_channel_name {
    OFLOPS_CONTROL = 0,		// openflow control channel, e.g., eth0/a  OFLOPS_DATA1,		// sending channel, e.g., eth1
    OFLOPS_DATA1, 		// recving channel, e.g., eth2
    OFLOPS_DATA2, 		// recving channel, e.g., eth2
    OFLOPS_DATA3, 		// recving channel, e.g., eth2
    OFLOPS_DATA4, 		// recving channel, e.g., eth2
    OFLOPS_DATA5, 		// recving channel, e.g., eth2
    OFLOPS_DATA6, 		// recving channel, e.g., eth2
    OFLOPS_DATA7, 		// recving channel, e.g., eth2
    OFLOPS_DATA8, 		// recving channel, e.g., eth2
};

/**
  * \brief possible values of the packet generating mechanism
  */
enum trafficGenValues {
  USER_SPACE=1,
  PKTGEN,
  NF_PKTGEN,
};

/**
  * \brief possible mechanism to capture data
  */
enum trafficCapValues {
  PCAP=1,
  NF2,
};

/**
 * a struct to store all the required configuration parameters for a module run.
 */
typedef struct {
  int n_tests;                            /**< number of tests */
  int max_tests;	                        /**< maximum size of the tests array */
  struct test_module ** tests;            /**< module struct storage */
  struct test_module * curr_test;         /**< the test that we are currently handling */
  char * controller_port;                 /**< which is the interface related t ocontrol */
  int listen_fd;                          /**< file descriptor of the socket of the control channel */
  uint16_t listen_port;                   /**< the port on which the controller will be listening */

  int snaplen;                            /**< maximum capture size of packet */

  int control_fd;                         /**<  */
  ev_io *io_read_ch, *io_write_ch;							  /**< libev io event for the control_fd */
  ev_async *async_ch;					  /**< libev async event to enable read on control_fd */
  ev_async *io_break_async;					  /**< libev async event to enable read on control_fd */
  struct msgbuf * control_outgoing;       /**< (Deprecated) a linked list to store temporarily injected packets */
  int n_channels;                         /**< the number of channel currently used in the current context */
  int max_channels;                       /**< maximum number of channel supported by the channel array */
  struct channel_info * channels;	        /**< an array to store pointer to all channel_info object
                                            of the control and channel objects */

  /** SNMP channel configuration
   */
  struct snmp_channel* snmp_channel_info; /**< An array of snmp channel configurations */
  int should_end;                         /**< */
  int dump_controller;                    /**< a pcap dump object, to dump pcap packets from the control channel */

  char *log;                              /**< a pointer to the logging module */

  int trafficGen;                         /**< the type of the packet capturing method */

  oid **cpuOID;                           /**< an array of cpu oid object */
  size_t *cpuOID_len;                     /**< an array of the length of the cpu oid */
  int cpuOID_count;                       /**< total number of cpu oid in the cpu_oid array */

  struct ev_loop *io_loop;
  struct ev_loop *timer_loop;
  struct ev_loop *data_loop;

} oflops_context;

typedef struct timer_event
{
    int timer_id;               /**< the id of the  */
    void * arg;
    struct timeval sched_time;
} timer_event;


oflops_context *oflops_default_context(void);
int reset_context(oflops_context *);

/** Setup SNMP session.
 * @param ctx context (includes reference to SNMP session/setup)
 */
void setup_snmp_channel(oflops_context* ctx);

/** Teardown SNMP session.
 * @param ctx context (includes reference to SNMP session/setup)
 */
void teardown_snmp_channel(oflops_context* ctx);

void *event_loop(oflops_context *ctx);
int wc_event_ev_add(oflops_context *, void (*)(void *), void *, struct timeval, uint32_t, uint32_t);

#endif
