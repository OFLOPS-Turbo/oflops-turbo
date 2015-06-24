#include "config.h"
#include <assert.h>
#include <dlfcn.h>
#include <pcap.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <poll.h>

#include <nf_pktgen.h>

#include "module_run.h"
#include "module_default.h"
#include "test_module.h"
#include "utils.h"
#include "msgbuf.h"
#include "traffic_generator.h"

static void test_module_loop(oflops_context *ctx, test_module *mod);
static void process_pcap_event(struct ev_loop *loop, struct ev_io *w, int revents);
static void process_control_event_read(struct ev_loop *loop, struct ev_io *w, int revents);
static void process_control_event_write(struct ev_loop *loop, struct ev_io *w, int revents);


/******************************************************
 * setup the test
 *
 */
int setup_test_module(oflops_context *ctx, int ix_mod)
{
  struct test_module *mod = ctx->tests[ix_mod];
  int i;
  //Setup
  setup_snmp_channel(ctx);

  //clean up the rules in the capture subsystem
  nf_cap_clear_rules();

  //configure the system
  for(i=0;i<ctx->n_channels;i++)
    setup_channel( ctx, mod, i);

  mod->start(ctx);
  return 1;
}


/******************************************************
 * call the main loop
 *
 */
void *run_test_module(oflops_context *ctx, int ix_mod)
{

  struct test_module *mod = ctx->tests[ix_mod];

  // moved the initialization code in the setup function  as this should
  // happen before thmodule start method
  /* int i; */
  /* //Setup */
  /* setup_snmp_channel(ctx); */
  /* for(i=0;i<ctx->n_channels;i++) */
  /* 	setup_channel( ctx, mod, i); */

  //Run
  test_module_loop(ctx,mod);
  mod->destroy(ctx);

  //Teardown
  teardown_snmp_channel(ctx);

  if((ctx->channels[OFLOPS_CONTROL].dump != NULL) && (ctx->dump_controller))
    pcap_dump_close(ctx->channels[OFLOPS_CONTROL].dump);

  return NULL;
}
/******************************************************
 * running traffic generation
 *
 */
void *run_traffic_generation(oflops_context *ctx, int ix_mod)
{
  struct test_module *mod = ctx->tests[ix_mod];
  //Run
  mod->handle_traffic_generation(ctx);
  return NULL;
}

struct cap_event_data {
    oflops_context *ctx;
    enum oflops_channel_name ch;
};

static void
async_ctrl_read (EV_P_ ev_async *w, int revents)
{
	oflops_context *ctx = (oflops_context *) w->data;
	// just used for the side effects
	ev_io_start(ctx->io_loop, ctx->io_write_ch);
}

static void
end_io_loop (EV_P_ ev_async *w, int revents) {
	oflops_context *ctx = (oflops_context *) w->data;
	ev_break(ctx->io_loop, EVBREAK_ALL);
}


/********************************************************
 * main loop()
 * 	1) setup poll
 * 	2) call poll with a min timeout of the next event
 * 	3) dispatch events as appropriate
 */
static void test_module_loop(oflops_context *ctx, test_module *mod)
{
//    for(ch=0; ch< ctx->n_channels; ch++) {
//        if(( ctx->channels[ch].pcap_handle) || (ctx->channels[ch].nf_cap))  {
//            io_ch = (ev_io*)xmalloc(sizeof(ev_io));
//            ev_io_init(io_ch, process_pcap_event, ctx->channels[ch].pcap_fd, EV_READ);
//            ev_io_start(ctx->io_loop, io_ch);
//            cap = (struct cap_event_data*)xmalloc(sizeof(struct cap_event_data));
//            cap->ctx = ctx;
//            cap->ch = ch;
//            io_ch->data = (void *)cap;
//        }
//    }

    ctx->io_read_ch = (ev_io*)xmalloc(sizeof(ev_io));
    ev_io_init(ctx->io_read_ch, process_control_event_read, ctx->control_fd, EV_READ);
//    ev_set_priority(ctx->io_read_ch, 1);
    ev_io_start(ctx->io_loop, ctx->io_read_ch);
    ctx->io_read_ch->data = (void*)ctx;

    ctx->io_write_ch = (ev_io*)xmalloc(sizeof(ev_io));
    ev_io_init(ctx->io_write_ch, process_control_event_write, ctx->control_fd, EV_WRITE);
 //   ev_set_priority(ctx->io_write_ch, 1);
    ev_io_start(ctx->io_loop, ctx->io_write_ch);
    ctx->io_write_ch->data = (void*)ctx;

    ctx->async_ch = (ev_async*)xmalloc(sizeof(ev_async));
    ev_async_init(ctx->async_ch, async_ctrl_read);
    ev_async_start(ctx->io_loop, ctx->async_ch);
    ctx->async_ch->data = (void*)ctx;

    ctx->io_break_async = (ev_async*)xmalloc(sizeof(ev_async));
    ev_async_init(ctx->io_break_async,  end_io_loop);
    ev_async_start(ctx->io_loop, ctx->io_break_async);
    ctx->io_break_async->data = (void*)ctx;

    ev_run(ctx->io_loop, 0);
}



static void process_control_event_write(struct ev_loop *loop, struct ev_io *w, int revents)
{
    oflops_context *ctx = (oflops_context *)w->data;
    test_module * mod = ctx->curr_test;
    char * neobuf;
    static char * buf;
    static int buflen   = -1;
    static int bufstart =  0;       // begin of unprocessed data
    static int bufend   =  0;       // end of unprocessed data
    unsigned int msglen;
    struct ofp_header * ofph;
    int count, len;
    struct timeval now;

    if ( buflen == - 1 )
    {
        buflen = BUFLEN;
        buf = malloc_and_check(BUFLEN);
    }
    if(bufend >= buflen )   // if we've filled up our buffer, resize it
    {
        buflen *=2 ;
        buf = realloc_and_check(buf, buflen);
    }

    if(revents | EV_WRITE)
    {
        if((len = msgbuf_write(ctx->control_outgoing,ctx->control_fd, 0)) < 0)
            perror_and_exit("control write()",1);
        if (len > 0) {
            /*struct timeval now;*/
            char msg[1024];
            oflops_gettimeofday(ctx, &now);
            sprintf(msg, "SND_DATA:%d", len);
            oflops_log(now, GENERIC_MSG, msg);
        } else 
			ev_io_stop(ctx->io_loop, ctx->io_write_ch);
    }
}

/***********************************************************************************************
 * static void process_control_event(oflops_context *ctx, test_module * mod, struct pollfd *fd);
 * 	if POLLIN is set, read an openflow message from the control channel
 * 	FIXME: handle a control channel reset here
 */
static void process_control_event_read(struct ev_loop *loop, struct ev_io *w, int revents)
{
    oflops_context *ctx = (oflops_context *)w->data;
    test_module * mod = ctx->curr_test;
    char * neobuf;
    static char * buf;
    static int buflen   = -1;
    static int bufstart =  0;       // begin of unprocessed data
    static int bufend   =  0;       // end of unprocessed data
    unsigned int msglen;
    struct ofp_header * ofph;
    int count, len;
    struct timeval now;

    if ( buflen == - 1 )
    {
        buflen = BUFLEN;
        buf = malloc_and_check(BUFLEN);
    }
    if(bufend >= buflen )   // if we've filled up our buffer, resize it
    {
        buflen *=2 ;
        buf = realloc_and_check(buf, buflen);
    }

    if(revents | EV_READ) {
        count = read(ctx->control_fd, &buf[bufend], buflen - bufend);
        if(count < 0)
        {
            perror("process_control_event:read() ::");
            return ;
        }
        if(count == 0)
        {
            fprintf(stderr, "Switch Control Connection reset! wtf!?!...exiting\n");
            exit(0);
        }
        bufend += count;            // extend buf by amount read
        count = bufend - bufstart;  // re-purpose count
    

		while(count > 0 )
		{
			if(count <  sizeof(ofph))   // if we didn't get full openflow header
				return;                 // come back later

			ofph = (struct ofp_header * ) &buf[bufstart];
			msglen = ntohs(ofph->length);
			if( ( msglen > count) ||    // if we don't yet have the whole msg
					(buflen < (msglen + bufstart)))  // or our buffer is full
				return;     // get the rest on the next pass

			neobuf = malloc_and_check(msglen);
			memcpy(neobuf, ofph, msglen);

			switch(ofph->type)
			{
				case OFPT_PACKET_IN:
					mod->of_event_packet_in(ctx, (struct ofp_packet_in *)neobuf);
					break;
				case OFPT_FLOW_EXPIRED:
					mod->of_event_flow_removed(ctx, (struct ofp_flow_removed *)neobuf);
					break;
				case OFPT_PORT_STATUS:
					mod->of_event_port_status(ctx, (struct ofp_port_status *)neobuf);
					break;
				case OFPT_ECHO_REQUEST:
					mod->of_event_echo_request(ctx, (struct ofp_header *)neobuf);
					break;
				default:
					if(ofph->type > OFPT_BARRIER_REPLY)   // FIXME: update for new openflow versions
					{
						fprintf(stderr, "%s:%d :: Data buffer probably trashed : unknown openflow type %d\n",
								__FILE__, __LINE__, ofph->type);
						abort();
					}
					mod->of_event_other(ctx, (struct ofp_header * ) neobuf);
					break;
			};
			free(neobuf);
			bufstart += msglen;
			count = bufend - bufstart;  // repurpose count
		}
	}       // end while()

    if ( bufstart >= bufend)        // if no outstanding bytes
        bufstart = bufend = 0;      // reset our buffer
}


/**********************************************************************************************
 * static void process_pcap_event(oflops_context *ctx, test_module * mod, struct pollfd *fd, enum oflops_channel_name ch);
 * 	front end to oflops_pcap_handler
 * 		make sure all of the memory is kosher before and after
 * 		pcap's callback thing has always annoyed me
 */
static void process_pcap_event(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct cap_event_data *cap = (struct cap_event_data *)w->data;
    oflops_context *ctx = cap->ctx;
    enum oflops_channel_name ch = cap->ch;
    test_module * mod =ctx->curr_test;

    struct pcap_event_wrapper wrap;
    int count;
    const uint8_t *data;
    static pcap_event pe;
//	static struct pcap_pkthdr h;

    // read the next packet from the appropriate pcap socket
    if(revents | EV_READ) {
        if (ctx->channels[ch].cap_type == PCAP) {
            assert(ctx->channels[ch].pcap_handle);
            count = pcap_dispatch(ctx->channels[ch].pcap_handle, 1, oflops_pcap_handler, (u_char *) & wrap);

            //dump packet if required
            if((ch == OFLOPS_CONTROL) && (ctx->channels[ch].pcap_handle)
                && (ctx->dump_controller))
                pcap_dump((u_char *)ctx->channels[ch].dump, &wrap.pe->pcaphdr, wrap.pe->data);


            if (count == 0)
                return;
            if (count < 0) {
                fprintf(stderr,"process_pcap_event:pcap_dispatch returned %d :: %s \n", count,
                pcap_geterr(ctx->channels[ch].pcap_handle));
                return;
            }
            // dispatch it to the test module
            mod->handle_pcap_event(ctx, wrap.pe, ch);
            // clean up our mess
            pcap_event_free(wrap.pe);
        } else  if(ctx->channels[ch].cap_type == NF2) {
            pe.data = (unsigned char *)nf_cap_next(ctx->channels[ch].nf_cap, &pe.pcaphdr);
            if(data != NULL) 
                mod->handle_pcap_event(ctx, &pe, ch);
        }
    }
    return;
}
/*************************************************************************
 * int load_test_module(oflops_context *ctx,
 * 			char * mod_filename, char * initstr);
 * 	open this module and strip symbols out of it
 * 	and call init() on it
 */
int load_test_module(oflops_context *ctx, char * mod_filename, char * initstr)
{
  void * handle;
  test_module * mod;
  mod = malloc_and_check(sizeof(*mod));
  bzero(mod,sizeof(*mod));

  // open module for dyn symbols
  handle = dlopen(mod_filename,RTLD_NOW);
  if(handle == NULL)
    {
      fprintf(stderr,"Error reading symbols from %s : %s\n",
	      mod_filename, dlerror());
      return 1;
    }
  mod->name = dlsym(handle,"name");
  mod->start = dlsym(handle,"start");
  if(!mod->name)
    fprintf( stderr, "Module %s does not contain a name() function\n", mod_filename);
  if(!mod->start)
    fprintf( stderr, "Module %s does not contain a start() function\n", mod_filename);
  if(!mod->name || !mod->start)
    {
      free(mod);
      dlclose(handle);
      return 1;	// fail for now
    }

#define symbol_fetch(X)				\
  mod->X = dlsym(handle, #X);			\
  if(!mod->X)					\
    mod->X = default_module_##X
  symbol_fetch(init);
  symbol_fetch(destroy);
  symbol_fetch(get_pcap_filter);
  symbol_fetch(handle_pcap_event);
  symbol_fetch(of_event_packet_in);
  symbol_fetch(of_event_flow_removed);
  symbol_fetch(of_event_echo_request);
  symbol_fetch(of_event_port_status);
  symbol_fetch(of_event_other);
  symbol_fetch(handle_timer_event);
  symbol_fetch(handle_snmp_event);
  symbol_fetch(handle_traffic_generation);
#undef symbol_fetch
  if(ctx->n_tests >= ctx->max_tests)
    {
      ctx->max_tests *=2;
      ctx->tests = realloc_and_check(ctx->tests, ctx->max_tests * sizeof(struct test_modules *));
    }
  ctx->tests[ctx->n_tests++] = mod;
  mod->symbol_handle=handle;

  if(mod->init)
    mod->init(ctx, initstr);
  return 0;
}
