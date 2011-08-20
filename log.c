#include "log.h"

const char *msg_type[] = {
  "OFPT_FLOW_MOD_ADD",
  "OFPT_STATS_REQUEST_FLOW",
  "OFPT_STATS_REPLY_FLOW",
  "OFPT_STATS_REQUEST_FLOW",
  "OFPT_STATS_REPLY_PORT",
  "OFPT_HELLO",
  "OFPT_ECHO_REPLY",
  "OFPT_ECHO_REQUEST",
  "OFPT_ERROR",
  "GENERIC_MSG",
  "SNMP_MSG",
  "PCAP_MSG",
  "OFPT_PACKET_IN_MSG",
  "PKTGEN_MSG"
};

FILE* logger;

/**
 * Initializes the logging system of oflops.
 * \param filename The file where the logging messages are stored. 
 */
void
oflops_log_init(const char *filename) {

  //openning the logging file
  logger = fopen(filename, "w");
  if(logger == NULL) {
    perror_and_exit("failed to open log file", 1);
  }
}

/**
 * log message on the logging file 
 * \param ts a timestamp of the logging event
 * \param type the type of the logging event
 * \param details the string to be appented on the logging file 
 */
void 
oflops_log(struct timeval ts, int type, char *details) {
  if (!logger)
    return;

  //print the log message
  fprintf(logger, "%lu.%06lu:%s:%s\n",(long unsigned int)ts.tv_sec,
      (long unsigned int)ts.tv_usec, msg_type[type], details);

  //force system to print the line on the file
  fflush(logger);
}


/**
 * Close the logging system of oflops.
 */
void
oflops_log_close() {
  if(logger)
    fclose(logger);
}
