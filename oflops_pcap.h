#ifndef OFLOPS_PCAP_H
#define OFLOPS_PCAP_H

#include <pcap.h>

struct pcap_event;

#include "test_module.h"

typedef struct pcap_event {
  struct pcap_pkthdr pcaphdr;
  // NOTE: full packet capture NOT guaranteed; need to check pcaphdr to see
  // 	how much was captured
  unsigned char * data;
} pcap_event;

// Silly hack to get around how pcap_dispatch() works
// 	must be a nicer way, but... <shrug>
struct pcap_event_wrapper
{
  pcap_event *pe;
};

/**
 * release an allocated pcap_event struct
 * \param pe a pointer to the memory location of the object
 */
void pcap_event_free(pcap_event * pe);

/**
 * a function to push a newly cpatured packet to the appropriate method
 * \param pcap_event_wrapper_arg an event wrapper struct to copy data into.
 * \param h the header of the pcap packet 
 * \param bytes the payload of the packet 
 */
void oflops_pcap_handler(u_char * pcap_event_wrapper_arg, const struct pcap_pkthdr *h, const u_char *bytes);
#endif
