#include <string.h>
#include <dlfcn.h>
#include <pcap.h>
#include <ev.h>

#include <openflow/openflow.h>

#include "context.h"
#include "timer_event.h"
#include "utils.h"
#include "log.h"
#include "test_module.h"


/**
 * an oflops context generation and initialization method
 * \return a pointer to the new oflops context details
 */
oflops_context * oflops_default_context(void) {

  //initialize oflops nf packet generator (enable packet padding)
  nf_init(1, 0, 0);

  oflops_context * ctx = malloc_and_check(sizeof(oflops_context));
  bzero(ctx, sizeof(*ctx));
  ctx->max_tests = 10 ;
  ctx->tests = malloc_and_check(ctx->max_tests * sizeof(test_module *));

  ctx->listen_port = OFP_TCP_PORT;	// listen on default port

  ctx->listen_fd   = -1;
  ctx->snaplen = 112;

  ctx->n_channels=1;
  ctx->max_channels=10;
  ctx->channels = malloc_and_check(sizeof(struct channel_info)* ctx->max_channels);

  ctx->control_outgoing = msgbuf_new(4096);       // dynamically sized

  ctx->snmp_channel_info = malloc_and_check(sizeof(struct snmp_channel));
  ctx->snmp_channel_info->hostname = NULL;
  ctx->snmp_channel_info->community_string = NULL;
  ctx->channels[OFLOPS_CONTROL].raw_sock = -1;

  // initalize other channels later
  ctx->log = malloc(sizeof(DEFAULT_LOG_FILE));
  strcpy(ctx->log, DEFAULT_LOG_FILE);

  ctx->trafficGen = PKTGEN;

  ctx->dump_controller = 0;
  ctx->cpuOID_count = 0;

  ctx->io_loop = ev_loop_new(EVFLAG_AUTO);
  ctx->timer_loop = ev_loop_new(EVFLAG_AUTO);
  ctx->data_loop = ev_loop_new(EVFLAG_AUTO);
  printf("io_loop=%p, timer_loop=%p\n", ctx->io_loop, ctx->timer_loop);

  return ctx;
}

/**
  * a method to reinit an oflops context structure.
  * to be run me between tests.
  * \param ctx a pointer to the context object
  */
int reset_context(oflops_context * ctx) {
  // close the open lirary object
  if(ctx->curr_test)
    dlclose(ctx->curr_test->symbol_handle);
  return 0;
}
