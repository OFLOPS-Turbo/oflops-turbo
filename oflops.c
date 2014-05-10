
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#ifndef __USE_GNU
#define __USE_GNU
#endif /* __USE_GNU */
#include <pthread.h>
#include <pcap.h>

#include <nf_pktgen.h>

#include "oflops.h"
#include "module_run.h"
#include "usage.h"
#include "control.h"
#include "log.h"
#include "signal.h"
#include "traffic_generator.h"

#include "wc_event.h"

void *run_module(void *param)
{
  struct run_module_param* tmp = (struct run_module_param *)param;
  printf("module ctx=%p\n", tmp->ctx);
  return (void *)run_test_module(tmp->ctx, tmp->ix_mod);
}

void *start_traffic_thread(void *param)
{
  struct run_module_param* tmp = (struct run_module_param *)param;
  printf("traffic ctx=%p\n", tmp->ctx);
  return (void *)run_traffic_generation(tmp->ctx, tmp->ix_mod);
}

struct cap_event_data {
    oflops_context *ctx;
    enum oflops_channel_name ch;
};

static void my_process_pcap_event(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct cap_event_data *cap = (struct cap_event_data *)w->data;
    oflops_context *ctx = cap->ctx;
    enum oflops_channel_name ch = cap->ch;
    test_module * mod =ctx->curr_test;

    struct pcap_event_wrapper wrap;
    int count;
    const uint8_t *data;
    static pcap_event *pe = NULL;

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
                fprintf(stderr,"my_process_pcap_event:pcap_dispatch returned %d :: %s \n", count,
                pcap_geterr(ctx->channels[ch].pcap_handle));
                return;
            }
            // dispatch it to the test module
            mod->handle_pcap_event(ctx, wrap.pe, ch);
            // clean up our mess
            pcap_event_free(wrap.pe);
        } else  if(ctx->channels[ch].cap_type == NF2) {
            if(pe == NULL) {
                pe = malloc_and_check(sizeof(pcap_event));
                //This is a hack
                pe->data = malloc_and_check(2000);
            }
            data = nf_cap_next(ctx->channels[ch].nf_cap, &pe->pcaphdr);

            if(data != NULL) {
                memcpy(pe->data, data, pe->pcaphdr.caplen);
                mod->handle_pcap_event(ctx,pe, ch);
            } else {
                fprintf(stderr, "errorous packet received\n");
                return;
            }
            //free(pe->data);
            //free(pe);
        }
    }
    return;
}




void *start_capture_thread(void *param) {
//    int i;
    int ch;
//    struct pcap_event_wrapper wrap;
//    int count;
//    const uint8_t *data;
//    static pcap_event *pe = NULL;
    struct run_module_param* tmp = (struct run_module_param *)param;
    ev_io *io_ch;
    struct cap_event_data *cap;

    printf("capture ctx=%p\n", tmp->ctx);
    for(ch=0; ch< tmp->ctx->n_channels; ch++) {
        if(( tmp->ctx->channels[ch].pcap_handle) || (tmp->ctx->channels[ch].nf_cap))  {
            io_ch = (ev_io*)xmalloc(sizeof(ev_io));
            ev_io_init(io_ch, my_process_pcap_event, tmp->ctx->channels[ch].pcap_fd, EV_READ);
            ev_io_start(tmp->ctx->data_loop, io_ch);
            cap = (struct cap_event_data*)xmalloc(sizeof(struct cap_event_data));
            cap->ctx = tmp->ctx;
            cap->ch = ch;
            io_ch->data = (void *)cap;
            ev_run(tmp->ctx->data_loop, 0);
        }
    }


//    while (!tmp->ctx->should_end) {
//        for (i=0;i < tmp->ctx->n_channels;i++) {
//            if (tmp->ctx->channels[i].nf_cap) {
//                pe = malloc_and_check(sizeof(pcap_event));
//                pe->data = nf_cap_next(tmp->ctx->channels[i].nf_cap, &pe->pcaphdr);
//                if(pe->data != NULL) {
//                    tmp->ctx->curr_test->handle_pcap_event(tmp->ctx, pe, i);
//                }
//                free(pe);
//            }
//
//        }
//    }
    return NULL;
}


void *run_event_loop(void *param)
{
    struct run_module_param* state = (struct run_module_param *)param;
    printf("event loop\n");
    printf("event ctx=%p\n", state->ctx);
    return event_loop(state->ctx);
}

int main(int argc, char * argv[])
{
  int i, j;
  struct pcap_stat ps;
  pthread_t thread, event_thread, traffic_gen, traffic_cap;
  struct run_module_param *param =  malloc_and_check(sizeof(struct run_module_param));
  char msg[1024];
  struct timeval now;
  struct nf_cap_stats stat;
  struct nf_gen_stats gen_stat;

  // create the default context
  oflops_context * ctx = oflops_default_context();
  param->ctx = ctx;
  parse_args(ctx, argc, argv);

  if(ctx->n_tests == 0 )
    usage("Need to specify at least one module to run\n",NULL);

  oflops_log_init(ctx->log);
  setup_control_channel(ctx);

  fprintf(stderr, "Running %d Test%s\n", ctx->n_tests, ctx->n_tests>1?"s":"");

  for(i=0;i<ctx->n_tests;i++) {
    // init contaxt and setup module
    fprintf(stderr, "-----------------------------------------------\n");
    fprintf(stderr, "------------ TEST %s ----------\n", (*(ctx->tests[i]->name))());
    fprintf(stderr, "-----------------------------------------------\n");
    // reset_context(ctx);
    ctx->curr_test = ctx->tests[i];
    param->ix_mod = i;
    setup_test_module(ctx,i);

    //start all the required threads of the program

    // the data receiving thread
    pthread_create(&thread, NULL, run_module, (void *)param);
    // the data generating thread
    pthread_create(&traffic_gen, NULL, start_traffic_thread, (void *)param);
    // the traffic capture thread
    pthread_create(&traffic_cap, NULL, start_capture_thread, (void *)param);
    // the timer thread.
    pthread_create(&event_thread, NULL, run_event_loop, (void *)param);
    pthread_join(thread, NULL);
    pthread_join(event_thread, NULL);


    // for the case of pktgen traffic generation the thread remain unresponsive to other
    // termination method, and for that reason we use explicit signal termination.
    if(ctx->trafficGen == PKTGEN)
      pthread_cancel(traffic_gen);
    else
      pthread_join(traffic_gen, NULL);

    //reading details for the data generation and capture process and output them to the log file.
    gettimeofday(&now, NULL);
    for(j = 0 ; j < ctx->n_channels;j++) {
      if((ctx->channels[j].cap_type == PCAP) &&
          (ctx->channels[j].pcap_handle != NULL)) {
        pcap_stats(ctx->channels[j].pcap_handle, &ps);
        snprintf(msg, 1024, "%s:%u:%u",ctx->channels[j].dev, ps.ps_recv, ps.ps_drop);
        oflops_log(now, PCAP_MSG, msg);
        printf("%s\n", msg);

        // FIXME: this requires a parsing code to extract only required information and not the whole string.
        char *ret = report_traffic_generator(ctx);
        if(ret) {
          oflops_log(now, PKTGEN_MSG, report_traffic_generator(ctx));
          printf("%s\n", ret);
        }

      } else if((ctx->channels[j].cap_type == NF2) &&
          (ctx->channels[j].nf_cap != NULL)) {
        nf_cap_stat(j-1, &stat);
        snprintf(msg, 1024, "%s:rcv:%u:%u",ctx->channels[j].dev,  stat.pkt_cnt,
            (stat.pkt_cnt - stat.capture_packet_cnt));
        oflops_log(now, PCAP_MSG, msg);
        printf("%s\n", msg);
        display_xmit_metrics(j-1, &gen_stat);
        snprintf(msg, 1024, "%s:snd:%u",ctx->channels[j].dev,gen_stat.pkt_snd_cnt);
        oflops_log(now, PCAP_MSG, msg);
        printf("%s\n",msg);
      }
    }
  }

  oflops_log_close();

  fprintf(stderr, "-----------------------------------------------\n");
  fprintf(stderr, "---------------    Finished   -----------------\n");
  fprintf(stderr, "-----------------------------------------------\n");
  return 0;
}
